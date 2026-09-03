/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDNS answers every A query with one fixed address, over plain UDP and —
// behind a self-signed certificate that carries 127.0.0.1 in its SAN, the way
// the real resolvers carry their addresses — over DNS-over-TLS. It counts what
// it served on each so a test can tell which rung of the ladder answered.
type fakeDNS struct {
	udp     net.PacketConn
	tcp     net.Listener
	roots   *x509.CertPool
	answer  [4]byte
	udpHits atomic.Int32
	dotHits atomic.Int32
}

func newFakeDNS(t *testing.T, answer [4]byte) *fakeDNS {
	t.Helper()
	f := &fakeDNS{answer: answer}

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	f.udp = udp
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			f.udpHits.Add(1)
			_, _ = udp.WriteTo(dnsAnswer(buf[:n], answer), from)
		}
	}()

	cert, roots := selfSignedForLoopback(t)
	f.roots = roots
	tcp, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	f.tcp = tcp
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					f.dotHits.Add(1)
					resp := dnsAnswer(q, answer)
					binary.BigEndian.PutUint16(l[:], uint16(len(resp)))
					if _, err := c.Write(append(l[:], resp...)); err != nil {
						return
					}
				}
			}()
		}
	}()

	t.Cleanup(func() {
		_ = udp.Close()
		_ = tcp.Close()
	})
	return f
}

func (f *fakeDNS) udpServer() string { return f.udp.LocalAddr().String() }

func (f *fakeDNS) dotPort() string {
	return strconv.Itoa(f.tcp.Addr().(*net.TCPAddr).Port)
}

// selfSignedForLoopback is a CA-less certificate for 127.0.0.1 and the pool
// that trusts exactly it.
func selfSignedForLoopback(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake resolver"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// dnsAnswer builds the response to query: the question echoed back and, for an
// A question, one record pointing at ip. Any other type gets an empty NOERROR
// answer, which is what Go's resolver expects for a name with no AAAA. The
// query's own additional section (Go appends an EDNS0 OPT record) is dropped
// rather than echoed, so the counts in the header stay honest.
func dnsAnswer(query []byte, ip [4]byte) []byte {
	if len(query) < 12 {
		return nil
	}
	q := 12
	for q < len(query) && query[q] != 0 {
		q += 1 + int(query[q])
	}
	q += 1 + 4 // the root label, then QTYPE and QCLASS
	if q > len(query) {
		return nil
	}
	isA := binary.BigEndian.Uint16(query[q-4:q-2]) == 1

	resp := make([]byte, 0, q+16)
	resp = append(resp, query[:2]...) // ID
	resp = append(resp, 0x81, 0x80)   // QR, RD, RA
	resp = append(resp, 0, 1)         // QDCOUNT
	if isA {
		resp = append(resp, 0, 1) // ANCOUNT
	} else {
		resp = append(resp, 0, 0)
	}
	resp = append(resp, 0, 0, 0, 0) // NSCOUNT, ARCOUNT
	resp = append(resp, query[12:q]...)
	if isA {
		resp = append(resp, 0xC0, 0x0C) // NAME: pointer to the question
		resp = append(resp, 0, 1, 0, 1) // TYPE A, CLASS IN
		resp = append(resp, 0, 0, 0, 60)
		resp = append(resp, 0, 4)
		resp = append(resp, ip[:]...)
	}
	return resp
}

func useDoTPort(t *testing.T, port string) {
	t.Helper()
	prev := tetherDoTPort
	tetherDoTPort = port
	t.Cleanup(func() { tetherDoTPort = prev })
}

func lookupOne(t *testing.T, r *net.Resolver, host string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		t.Fatalf("LookupHost(%s): %v", host, err)
	}
	if len(addrs) != 1 {
		t.Fatalf("LookupHost(%s) = %v, want one address", host, addrs)
	}
	return addrs[0]
}

// lookupA asks for the A record only. LookupHost sends A and AAAA in parallel,
// two Dials at once, which is fine for the ladder but makes attempt counts a
// coin toss; a test that counts uses this.
func lookupA(t *testing.T, r *net.Resolver, host string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.LookupNetIP(ctx, "ip4", host); err != nil {
		t.Fatalf("LookupNetIP(%s): %v", host, err)
	}
}

// A resolver that speaks DNS-over-TLS is asked over it, and plain UDP is never
// touched: the answer cannot be rewritten on the way.
func TestDirectResolverPrefersDNSOverTLS(t *testing.T) {
	f := newFakeDNS(t, [4]byte{5, 255, 255, 70})
	useDoTPort(t, f.dotPort())

	r := newDirectResolver([]string{f.udpServer()}, nil, f.roots)
	if got := lookupOne(t, r, "yandex.ru"); got != "5.255.255.70" {
		t.Fatalf("answer = %s", got)
	}
	if f.dotHits.Load() == 0 {
		t.Fatal("the query did not go over TLS")
	}
	if f.udpHits.Load() != 0 {
		t.Fatalf("%d queries went out as plain UDP with TLS available", f.udpHits.Load())
	}
}

// A certificate that does not cover the resolver's address is a resolver that
// cannot be trusted over TLS — and also what a captive portal impersonating it
// would present. The lookup still succeeds, over plain UDP, exactly as before
// this rung existed.
func TestDirectResolverFallsBackToUDPOnAnUntrustedCertificate(t *testing.T) {
	f := newFakeDNS(t, [4]byte{5, 255, 255, 70})
	useDoTPort(t, f.dotPort())

	// An empty pool trusts nobody; the handshake fails on verification.
	r := newDirectResolver([]string{f.udpServer()}, nil, x509.NewCertPool())
	if got := lookupOne(t, r, "yandex.ru"); got != "5.255.255.70" {
		t.Fatalf("answer = %s", got)
	}
	if f.dotHits.Load() != 0 {
		t.Fatal("a query was served over a TLS session that should not have verified")
	}
	if f.udpHits.Load() == 0 {
		t.Fatal("the lookup did not fall back to plain UDP")
	}
}

// Port 853 that answers with nothing must cost one stall, not one per lookup:
// after the first failure the resolver stays on plain UDP for dotRetryAfter,
// and tries TLS again once the window has passed.
func TestDirectResolverRemembersThatDNSOverTLSFailed(t *testing.T) {
	f := newFakeDNS(t, [4]byte{5, 255, 255, 70})

	// A TCP listener that accepts and hangs up: the TLS handshake fails at once.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer dead.Close()
	var attempts atomic.Int32
	go func() {
		for {
			c, err := dead.Accept()
			if err != nil {
				return
			}
			attempts.Add(1)
			_ = c.Close()
		}
	}()
	useDoTPort(t, strconv.Itoa(dead.Addr().(*net.TCPAddr).Port))

	clock := time.Now()
	d := &dnsDialer{
		servers:  []string{f.udpServer()},
		tlsFirst: true,
		tlsRoots: f.roots,
		now:      func() time.Time { return clock },
	}
	r := d.resolver()

	lookupA(t, r, "a.yandex.ru")
	lookupA(t, r, "b.yandex.ru")
	if got := attempts.Load(); got != 1 {
		t.Fatalf("TLS was attempted %d times across two lookups, want exactly one before the window", got)
	}
	if f.udpHits.Load() == 0 {
		t.Fatal("the lookups did not fall back to plain UDP")
	}

	clock = clock.Add(dotRetryAfter + time.Second)
	lookupA(t, r, "c.yandex.ru")
	if got := attempts.Load(); got != 2 {
		t.Fatalf("TLS was attempted %d times after the window passed, want a second try", got)
	}
}

// The tunnel resolver stays plain: its servers are the tunnel's own, reached
// inside it, and a TLS handshake through the relay would only add latency.
func TestTunnelResolverDoesNotTryTLS(t *testing.T) {
	f := newFakeDNS(t, [4]byte{10, 0, 0, 5})
	useDoTPort(t, f.dotPort())

	r := newTunnelResolver([]string{f.udpServer()})
	if got := lookupOne(t, r, "example.com"); got != "10.0.0.5" {
		t.Fatalf("answer = %s", got)
	}
	if f.dotHits.Load() != 0 {
		t.Fatal("the tunnel resolver went over TLS")
	}
}
