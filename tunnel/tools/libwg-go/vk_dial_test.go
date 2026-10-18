/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
	"github.com/kiper292/tls-client/profiles"
)

// dnsAnswerWithCNAME builds a response to an A query for name: a CNAME first, the way
// internal.api.vk.ru answers, then the A records.
func dnsAnswerWithCNAME(name string, addrs ...[4]byte) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(addrs)+1))

	q, _ := buildDNSQuery(name)
	msg = append(msg, q[12:]...)

	rr := func(rtype uint16, rdata []byte) {
		msg = append(msg, 0xC0, 0x0C) // pointer to the question name
		var fixed [10]byte
		binary.BigEndian.PutUint16(fixed[0:2], rtype)
		binary.BigEndian.PutUint16(fixed[2:4], 1)
		binary.BigEndian.PutUint32(fixed[4:8], 60)
		binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rdata)))
		msg = append(msg, fixed[:]...)
		msg = append(msg, rdata...)
	}
	rr(5, []byte{3, 'a', 'p', 'i', 0xC0, 0x0C})
	for _, a := range addrs {
		rr(1, a[:])
	}
	return msg
}

// The whole point of the change: the second and later A records used to be
// thrown away at the parser.
func TestParseDNSResponseReturnsEveryARecord(t *testing.T) {
	resp := dnsAnswerWithCNAME("api.vk.ru",
		[4]byte{87, 240, 129, 140}, [4]byte{87, 240, 137, 206}, [4]byte{93, 186, 225, 205})

	got, err := parseDNSResponse(resp, "api.vk.ru")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := []string{"87.240.129.140", "87.240.137.206", "93.186.225.205"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// fakeDialer answers per address: a connection, an error, or silence until the
// dial is cancelled — what a blackholed SYN looks like from here.
type fakeDialer struct {
	mu      sync.Mutex
	dialled []string
	refuse  map[string]error
	silent  map[string]bool
	delay   map[string]time.Duration
	// ignoreCancel makes an address finish its connect even after the dial was
	// cancelled, the way a SYN-ACK already on the wire does.
	ignoreCancel map[string]bool
	conns        map[string]*recordingConn
}

type recordingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *recordingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (d *fakeDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	ip, _, _ := net.SplitHostPort(addr)
	d.mu.Lock()
	d.dialled = append(d.dialled, ip)
	d.mu.Unlock()

	if err := d.refuse[ip]; err != nil {
		return nil, err
	}
	if d.silent[ip] {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if wait := d.delay[ip]; wait > 0 {
		if d.ignoreCancel[ip] {
			time.Sleep(wait)
		} else {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	local, remote := net.Pipe()
	go func() { // the far end: says one word when spoken to
		buf := make([]byte, 1)
		if _, err := remote.Read(buf); err == nil {
			remote.Write([]byte{1})
		}
		remote.Close()
	}()
	conn := &recordingConn{Conn: local}
	d.mu.Lock()
	if d.conns == nil {
		d.conns = map[string]*recordingConn{}
	}
	d.conns[ip] = conn
	d.mu.Unlock()
	return conn, nil
}

func (d *fakeDialer) dialledAddrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialled...)
}

func cacheWith(host string, ips ...string) *DnsCache {
	return &DnsCache{
		ips:      map[string][]string{host: ips},
		inflight: make(map[string]*dnsLookup),
	}
}

func (c *DnsCache) snapshot(host string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.ips[host]...)
}

// The healthy case must cost what it always did: one connect to one address.
func TestDialLeavesAnAnsweringAddressAlone(t *testing.T) {
	d := &fakeDialer{}
	conn, ip, setAside, err := dialFirstReachable(context.Background(), "tcp", "443",
		[]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, d.dial)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if ip != "10.0.0.1" || len(setAside) != 0 {
		t.Fatalf("won on %s, set aside %v; want 10.0.0.1 and nothing", ip, setAside)
	}
	if got := d.dialledAddrs(); len(got) != 1 {
		t.Fatalf("an answering first address was raced: dialled %v", got)
	}
}

// A blackholed address gives no error to react to. The next one must join after
// the head start — not before it, and not after the 20s the dial used to spend.
func TestDialRacesPastASilentAddress(t *testing.T) {
	d := &fakeDialer{silent: map[string]bool{"10.0.0.1": true}}

	start := time.Now()
	conn, ip, setAside, err := dialFirstReachable(context.Background(), "tcp", "443",
		[]string{"10.0.0.1", "10.0.0.2"}, d.dial)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if ip != "10.0.0.2" {
		t.Fatalf("won on %s, want the address that answers", ip)
	}
	if !reflect.DeepEqual(setAside, []string{"10.0.0.1"}) {
		t.Fatalf("set aside %v, want the address that was outrun", setAside)
	}
	if elapsed+time.Millisecond < vkDialHeadStart {
		t.Fatalf("second address joined after %v, before the %v head start", elapsed, vkDialHeadStart)
	}
	if elapsed > 2*vkDialHeadStart {
		t.Fatalf("the silent address held the dial for %v", elapsed)
	}
}

// An address that refuses has answered; the head start is for silence only.
func TestDialBringsTheNextAddressForwardOnRefusal(t *testing.T) {
	d := &fakeDialer{refuse: map[string]error{
		"10.0.0.1": errors.New("connection refused"),
		"10.0.0.2": errors.New("network is unreachable"),
	}}

	start := time.Now()
	conn, ip, setAside, err := dialFirstReachable(context.Background(), "tcp", "443",
		[]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, d.dial)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if ip != "10.0.0.3" {
		t.Fatalf("won on %s, want the third address", ip)
	}
	if !reflect.DeepEqual(setAside, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("set aside %v, want both refusals", setAside)
	}
	if elapsed >= vkDialHeadStart {
		t.Fatalf("two instant refusals took %v — the next address waited out the head start", elapsed)
	}
}

func TestDialReportsTotalFailure(t *testing.T) {
	refused := errors.New("connection refused")
	d := &fakeDialer{refuse: map[string]error{"10.0.0.1": refused, "10.0.0.2": refused}}

	_, _, setAside, err := dialFirstReachable(context.Background(), "tcp", "443",
		[]string{"10.0.0.1", "10.0.0.2"}, d.dial)
	if !errors.Is(err, refused) {
		t.Fatalf("got %v, want the cause", err)
	}
	if len(setAside) != 2 {
		t.Fatalf("set aside %v, want both", setAside)
	}
}

// A connect that completes after the race is decided must not leak: nobody is
// left to use it, so it is closed.
func TestDialClosesAConnectionThatLostTheRace(t *testing.T) {
	late := vkDialHeadStart + 150*time.Millisecond
	d := &fakeDialer{
		// The first address wins just after the second has started; the second
		// completes its connect regardless, a little later.
		delay:        map[string]time.Duration{"10.0.0.1": vkDialHeadStart + 50*time.Millisecond, "10.0.0.2": 150 * time.Millisecond},
		ignoreCancel: map[string]bool{"10.0.0.2": true},
	}

	conn, ip, setAside, err := dialFirstReachable(context.Background(), "tcp", "443",
		[]string{"10.0.0.1", "10.0.0.2"}, d.dial)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	if ip != "10.0.0.1" {
		t.Fatalf("won on %s, want the first address", ip)
	}
	// The second address started after the winner: it has had less time, not
	// lost a head start, so it keeps its place.
	if len(setAside) != 0 {
		t.Fatalf("set aside %v, want nothing", setAside)
	}

	deadline := time.Now().Add(late + time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		loser := d.conns["10.0.0.2"]
		d.mu.Unlock()
		if loser != nil && loser.closed.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the connection that lost the race was never closed")
}

// Our own cancellation says nothing about the addresses: none is set aside, and
// the cached answer stays.
func TestCancelledDialBlamesNoAddress(t *testing.T) {
	d := &fakeDialer{silent: map[string]bool{"10.0.0.1": true, "10.0.0.2": true}}
	cache := cacheWith("api.vk.ru", "10.0.0.1", "10.0.0.2")

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	if _, err := dialVKHost(ctx, cache, "tcp", "api.vk.ru:443", d.dial); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want the cancellation", err)
	}
	if got := cache.snapshot("api.vk.ru"); !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("a cancelled dial reordered the cache: %v", got)
	}
}

// What the session looked like behind an L3 whitelist: the address that opens
// the answer never answers. The first dial pays one head start for it; the
// second must not pay again.
func TestVKDialSetsASilentAddressAsideForTheNextDial(t *testing.T) {
	d := &fakeDialer{silent: map[string]bool{"87.240.129.140": true}}
	cache := cacheWith("api.vk.ru", "87.240.129.140", "87.240.137.206", "93.186.225.205")

	conn, err := dialVKHost(context.Background(), cache, "tcp", "api.vk.ru:443", d.dial)
	if err != nil {
		t.Fatalf("first dial failed: %v", err)
	}
	conn.Write([]byte{0})
	conn.Read(make([]byte, 1))
	conn.Close()

	want := []string{"87.240.137.206", "93.186.225.205", "87.240.129.140"}
	if got := cache.snapshot("api.vk.ru"); !reflect.DeepEqual(got, want) {
		t.Fatalf("cache order %v, want %v", got, want)
	}

	start := time.Now()
	conn, err = dialVKHost(context.Background(), cache, "tcp", "api.vk.ru:443", d.dial)
	if err != nil {
		t.Fatalf("second dial failed: %v", err)
	}
	conn.Write([]byte{0})
	conn.Read(make([]byte, 1))
	conn.Close()
	if elapsed := time.Since(start); elapsed >= vkDialHeadStart {
		t.Fatalf("the second dial took %v — it opened with the silent address again", elapsed)
	}
	if got := cache.snapshot("api.vk.ru"); !reflect.DeepEqual(got, want) {
		t.Fatalf("a connection that answered was reordered: %v", got)
	}
}

// Behind an L7 filter the connect succeeds and the ClientHello is cut: the
// address "wins" every race and never carries a byte. Closing such a connection
// is what moves it out of the way.
func TestVKDialSetsAsideAnAddressThatConnectsAndNeverAnswers(t *testing.T) {
	d := &fakeDialer{}
	cache := cacheWith("api.vk.ru", "10.0.0.1", "10.0.0.2")

	conn, err := dialVKHost(context.Background(), cache, "tcp", "api.vk.ru:443", d.dial)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	conn.Close() // the request timed out with nothing read
	conn.Close() // and a second Close must not count twice

	if got := cache.snapshot("api.vk.ru"); !reflect.DeepEqual(got, []string{"10.0.0.2", "10.0.0.1"}) {
		t.Fatalf("cache order %v, want the mute address last", got)
	}
}

// Every address failing means the answer is no use as it stands: the next dial
// has to ask DNS again rather than walk the same list.
func TestVKDialForgetsAnAnswerNoneOfWhichConnects(t *testing.T) {
	refused := errors.New("connection refused")
	d := &fakeDialer{refuse: map[string]error{"10.0.0.1": refused, "10.0.0.2": refused}}
	cache := cacheWith("api.vk.ru", "10.0.0.1", "10.0.0.2")

	if _, err := dialVKHost(context.Background(), cache, "tcp", "api.vk.ru:443", d.dial); err == nil {
		t.Fatal("expected an error")
	}
	if got := cache.snapshot("api.vk.ru"); len(got) != 0 {
		t.Fatalf("a wholly failed answer stayed cached: %v", got)
	}
}

// Resolve is what the TURN side uses; it follows the same order.
func TestResolveReturnsThePreferredAddress(t *testing.T) {
	cache := cacheWith("relay.example", "10.0.0.1", "10.0.0.2")
	cache.SetAside("relay.example", "10.0.0.1")
	cache.SetAside("relay.example", "10.9.9.9") // not in the answer: ignored

	ip, err := cache.Resolve(context.Background(), "relay.example")
	if err != nil || ip != "10.0.0.2" {
		t.Fatalf("got %q, %v; want 10.0.0.2", ip, err)
	}
	if got := cache.snapshot("relay.example"); len(got) != 2 {
		t.Fatalf("an unknown address was added: %v", got)
	}
}

func shrinkHandshakeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := vkHandshakeTimeout
	vkHandshakeTimeout = d
	t.Cleanup(func() { vkHandshakeTimeout = prev })
}

// Audit 2026-10-16: tls-client dials its HTTP/2 pool under
// context.Background(), and a ClientHello answered by nothing — an L7 filter
// that lets the SYN through — held the handshake, and every request waiting on
// it, forever. The guard's deadline ends it.
func TestAHandshakeAnsweredByNothingIsBounded(t *testing.T) {
	shrinkHandshakeTimeout(t, 200*time.Millisecond)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	held := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			held <- c // taken, and never a word back
		}
	}()
	defer func() {
		select {
		case c := <-held:
			c.Close()
		default:
		}
	}()

	conn, err := getCustomDialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		done <- tls.Client(conn, &tls.Config{ServerName: "api.vk.ru"}).HandshakeContext(context.Background())
	}()
	select {
	case err := <-done:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("the handshake ended with %v, want the guard's timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a handshake answered by nothing is still waiting")
	}
}

// Once the handshake is over the deadline is gone: a pooled connection may sit
// idle for longer than any handshake takes, and then carry a request — over
// TLS 1.3, where the client's Finished lifts it, and over TLS 1.2, where its
// first request does.
func TestTheHandshakeGuardIsLiftedOnceTheHandshakeIsOver(t *testing.T) {
	shrinkHandshakeTimeout(t, 200*time.Millisecond)
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, "ok")
			}))
			srv.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			srv.StartTLS()
			defer srv.Close()

			conn, err := getCustomDialContext(context.Background(), "tcp", srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			defer tc.Close()
			if err := tc.HandshakeContext(context.Background()); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			time.Sleep(400 * time.Millisecond) // twice the guard's deadline, idle
			if _, err := fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: vk\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatalf("a request after the handshake: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
			if err != nil {
				t.Fatalf("its answer: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
		})
	}
}

// stallAfterFirstFlight is a TCP relay to upstream that passes the client's
// ClientHello and the server's answer to it, and from the client's next byte
// on lets nothing more come back: the server's side of the handshake stops
// mid-way, after the client has heard it once.
func stallAfterFirstFlight(t *testing.T, upstream string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", upstream)
			if err != nil {
				client.Close()
				return
			}
			t.Cleanup(func() { client.Close(); server.Close() })
			var stalled atomic.Bool
			go func() { // client → server
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(client, hdr); err != nil {
					return
				}
				hello := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
				if _, err := io.ReadFull(client, hello); err != nil {
					return
				}
				server.Write(append(hdr, hello...))
				buf := make([]byte, 4096)
				for {
					n, err := client.Read(buf)
					if n > 0 {
						stalled.Store(true) // before the server can answer it
						server.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
			go func() { // server → client
				buf := make([]byte, 16384)
				for {
					n, err := server.Read(buf)
					if n > 0 && !stalled.Load() {
						client.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// stalledHandshake runs a TLS handshake through the guard and a relay that
// stalls it after the server's first flight, and wants the guard's timeout.
func stalledHandshake(t *testing.T, server *tls.Config) {
	t.Helper()
	shrinkHandshakeTimeout(t, 300*time.Millisecond)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = server
	srv.StartTLS()
	defer srv.Close()

	conn, err := getCustomDialContext(context.Background(), "tcp", stallAfterFirstFlight(t, srv.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		done <- tls.Client(conn, &tls.Config{InsecureSkipVerify: true}).HandshakeContext(context.Background())
	}()
	select {
	case err := <-done:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("the handshake ended with %v, want the guard's timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a handshake stalled after the server's first flight is still waiting")
	}
}

// Codex review: a server that wants another key share answers the ClientHello
// with a HelloRetryRequest, and the client's ChangeCipherSpec and second
// ClientHello went out as "a write after the peer had spoken" — the guard was
// lifted with the handshake barely begun, and a server silent from there held
// it forever. The go client offers X25519 and X25519MLKEM768 shares; a P-256
// server asks again.
func TestAHandshakeStalledAfterAHelloRetryIsBounded(t *testing.T) {
	stalledHandshake(t, &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.CurveP256}})
}

// The same in TLS 1.2: the client's second flight comes before the server's
// Finished, which a stalled server never sends.
func TestATLS12HandshakeStalledBeforeTheServersFinishedIsBounded(t *testing.T) {
	stalledHandshake(t, &tls.Config{MaxVersion: tls.VersionTLS12})
}

// The audit's reproduction end to end, through tls-client itself: the HTTP/2
// connection is gone, the pool's redial lands on a socket that takes the
// ClientHello and never answers, and the request waiting on it — its own
// context long expired — was released only by closing that socket by hand.
// Guarded, the redial fails on its deadline and lets the request go.
func TestAStalledHTTP2RedialReleasesItsRequest(t *testing.T) {
	shrinkHandshakeTimeout(t, 300*time.Millisecond)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	var held []net.Conn
	var heldMu sync.Mutex
	hello := make(chan byte, 1) // the first byte the silent server is sent
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			heldMu.Lock()
			held = append(held, c)
			heldMu.Unlock()
			go func() {
				b := make([]byte, 1)
				if _, err := io.ReadFull(c, b); err == nil {
					select {
					case hello <- b[0]:
					default:
					}
				}
			}()
		}
	}()
	defer func() {
		heldMu.Lock()
		for _, c := range held {
			c.Close()
		}
		heldMu.Unlock()
	}()

	var dials atomic.Int32
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(1),
		tlsclient.WithClientProfile(profiles.Chrome_131),
		tlsclient.WithInsecureSkipVerify(),
		tlsclient.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			to := silent.Addr().String()
			if dials.Add(1) == 1 {
				to = srv.Listener.Addr().String()
			}
			conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, to)
			if err != nil {
				return nil, err
			}
			return guardHandshake(conn, vkHandshakeTimeout), nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()

	req, _ := fhttp.NewRequest("GET", srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("first request went over %s, want HTTP/2 for the pool's redial", resp.Proto)
	}
	client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ = fhttp.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	done := make(chan error, 1)
	started := time.Now() // before the request: a late stamp would make the guard look early
	go func() {
		r, err := client.Do(req)
		if r != nil {
			r.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the request over a silent redial succeeded")
		}
		if el := time.Since(started); el < vkHandshakeTimeout-50*time.Millisecond {
			t.Fatalf("released after %v with %v — before the guard's %v: not the guard", el, err, vkHandshakeTimeout)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the request is still held by a redial whose handshake nothing answers")
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials, want the first and the pool's redial", n)
	}
	select {
	case b := <-hello:
		if b != 22 {
			t.Fatalf("the redial sent %#x first, want a TLS handshake record", b)
		}
	case <-time.After(time.Second):
		t.Fatal("the redial never sent the silent server its ClientHello")
	}
}

// endsHandshake reads one write of a TLS client: only an application_data
// record ends the guard — or a write that is no TLS at all.
func TestEndsHandshakeReadsTheRecords(t *testing.T) {
	rec := func(typ byte, body int) []byte {
		b := []byte{typ, 3, 3, byte(body >> 8), byte(body)}
		return append(b, make([]byte, body)...)
	}
	join := func(rs ...[]byte) []byte {
		var out []byte
		for _, r := range rs {
			out = append(out, r...)
		}
		return out
	}
	cases := []struct {
		name string
		p    []byte
		want bool
	}{
		{"ClientHello", rec(22, 512), false},
		{"HelloRetryRequest's ChangeCipherSpec", rec(20, 1), false},
		{"TLS 1.2 second flight", join(rec(22, 70), rec(20, 1), rec(22, 40)), false},
		{"TLS 1.3 last flight", join(rec(20, 1), rec(23, 53)), true},
		{"a request", rec(23, 300), true},
		{"no TLS at all", []byte("GET / HTTP/1.1\r\n\r\n"), true},
		{"a header cut short", []byte{22, 3, 3}, false},
		{"a record cut short", rec(22, 512)[:100], false},
		{"nothing", nil, false},
	}
	for _, tc := range cases {
		if got := endsHandshake(tc.p); got != tc.want {
			t.Errorf("%s: endsHandshake = %v, want %v", tc.name, got, tc.want)
		}
	}
}
