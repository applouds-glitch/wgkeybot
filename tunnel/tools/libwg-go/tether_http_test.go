/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingDial is a fake upstream: it records what the proxy asked for and
// hands back one end of an in-memory pipe the test drives by hand.
type recordingDial struct {
	mu    sync.Mutex
	calls []string
	conns chan net.Conn
}

func newRecordingDial() *recordingDial {
	return &recordingDial{conns: make(chan net.Conn, 4)}
}

func (d *recordingDial) fn(_ context.Context, host string, port int) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, net.JoinHostPort(host, strconv.Itoa(port)))
	d.mu.Unlock()
	client, server := net.Pipe()
	d.conns <- server
	return client, nil
}

func (d *recordingDial) lastCall(t *testing.T) string {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.calls) == 0 {
		t.Fatal("proxy never dialled upstream")
	}
	return d.calls[len(d.calls)-1]
}

func (d *recordingDial) upstream(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-d.conns:
		t.Cleanup(func() { _ = c.Close() })
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("upstream connection never arrived")
		return nil
	}
}

// CONNECT is what every browser and OS proxy setting uses for HTTPS; the tunnel
// it opens must be byte-transparent in both directions.
func TestTetherHTTPConnectTunnelsBothWays(t *testing.T) {
	dial := newRecordingDial()
	p := newTestTetherProxy(t, dial.fn)

	c := dialProxy(t, p)
	if _, err := c.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	up := dial.upstream(t)
	if got := dial.lastCall(t); got != "example.com:443" {
		t.Fatalf("dialled %q, want example.com:443", got)
	}

	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status line %q does not report success", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, 4)
	_ = up.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := up.Read(buf); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("upstream got %q, want ping", buf)
	}

	if _, err := up.Write([]byte("pong")); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.Read(buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("client got %q, want pong", buf)
	}
}

// Plain HTTP through a proxy arrives in absolute-URI form; upstream must see a
// normal origin-form request instead.
func TestTetherHTTPAbsoluteURIIsRewritten(t *testing.T) {
	dial := newRecordingDial()
	p := newTestTetherProxy(t, dial.fn)

	c := dialProxy(t, p)
	if _, err := c.Write([]byte("GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}

	up := dial.upstream(t)
	if got := dial.lastCall(t); got != "example.com:80" {
		t.Fatalf("dialled %q, want example.com:80", got)
	}

	_ = up.SetReadDeadline(time.Now().Add(2 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(up))
	if err != nil {
		t.Fatalf("upstream read request: %v", err)
	}
	if req.URL.IsAbs() {
		t.Fatalf("upstream got an absolute URI %q", req.URL)
	}
	if req.URL.Path != "/path" {
		t.Fatalf("upstream path %q, want /path", req.URL.Path)
	}
	if req.Header.Get("Proxy-Connection") != "" {
		t.Fatal("hop-by-hop Proxy-Connection header leaked upstream")
	}
}

// The PAC file is the one-URL way to configure a laptop or an iPhone, so it has
// to name the address the client actually reaches us on.
func TestTetherPACNamesTheListenerAddress(t *testing.T) {
	p := newTestTetherProxy(t, failingDial)

	c := dialProxy(t, p)
	if _, err := c.Write([]byte("GET /pac HTTP/1.1\r\nHost: proxy\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	body := make([]byte, 512)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "PROXY "+p.ln.Addr().String()) {
		t.Fatalf("PAC body does not point at %s: %s", p.ln.Addr().String(), body[:n])
	}
}

// Android randomises the local-only hotspot's subnet, so a PAC that hardcoded
// 192.168 sent the client's requests to the phone itself into the proxy — and
// from there into the tunnel, where they had nowhere to arrive.
func TestTetherPACExemptsTheSubnetItIsActuallyOn(t *testing.T) {
	p := newTestTetherProxy(t, failingDial)

	c := dialProxy(t, p)
	if _, err := c.Write([]byte("GET /pac HTTP/1.1\r\nHost: proxy\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body := make([]byte, 512)
	n, _ := resp.Body.Read(body)
	pac := string(body[:n])

	// The test proxy listens on loopback, so that is the subnet the PAC must name.
	if !strings.Contains(pac, `isInNet(host, "127.0.0.0", "255.255.255.0")`) {
		t.Fatalf("PAC does not exempt the subnet it is on: %s", pac)
	}
	if strings.Contains(pac, "192.168.*") {
		t.Fatalf("PAC still hardcodes a 192.168 subnet: %s", pac)
	}
}

func TestPacLocalNetwork(t *testing.T) {
	for _, tc := range []struct{ ip, want string }{
		{"192.168.49.1", "192.168.49.0"},
		{"172.16.5.1", "172.16.5.0"},
		{"fd00::1", "0.0.0.0"},
	} {
		addr := &net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 8888}
		if got := pacLocalNetwork(addr); got != tc.want {
			t.Errorf("pacLocalNetwork(%s) = %s, want %s", tc.ip, got, tc.want)
		}
	}
}

// The handshake deadline bounds how long a client may take to state what it
// wants. It must not also bound the transfer: req.Write streams the request
// BODY, and under one shared deadline an upload slower than five seconds died
// mid-body, with no status written to the client at all.
func TestTetherHTTPForwardSurvivesABodySlowerThanTheHandshakeDeadline(t *testing.T) {
	dial := newRecordingDial()
	p := newTestTetherProxy(t, dial.fn, func(p *tetherProxy) {
		p.handshakeTimeout = 200 * time.Millisecond
	})

	c := dialProxy(t, p)
	const body = "0123456789"
	head := "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	if _, err := c.Write([]byte(head)); err != nil {
		t.Fatalf("write request head: %v", err)
	}

	up := dial.upstream(t)
	_ = up.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := up.Read(make([]byte, 512)); err != nil {
		t.Fatalf("upstream never got the request head: %v", err)
	}

	// A link slower than the handshake deadline — which over TURN is ordinary.
	time.Sleep(400 * time.Millisecond)
	if _, err := c.Write([]byte(body)); err != nil {
		t.Fatalf("write request body: %v", err)
	}

	got := make([]byte, len(body))
	_ = up.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(up, got); err != nil {
		t.Fatalf("upstream never got the body: %v", err)
	}
	if string(got) != body {
		t.Fatalf("upstream got body %q, want %q", got, body)
	}
}

// A proxy connection is not bound to one origin: the client names a host per
// request. Handing the rest of the connection to splice() after forwarding one
// request wrote the NEXT request into the previous origin's socket — and a
// client that pipelines did not even need the origin to misbehave for it.
func TestTetherHTTPForwardDoesNotSpliceTheNextRequestIntoTheSameUpstream(t *testing.T) {
	dial := newRecordingDial()
	p := newTestTetherProxy(t, dial.fn)

	c := dialProxy(t, p)
	// Both at once: the second request is already in the proxy's reader before
	// the first response has even been asked for.
	if _, err := c.Write([]byte(
		"GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n" +
			"GET http://b.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n")); err != nil {
		t.Fatalf("write requests: %v", err)
	}

	upA := dial.upstream(t)
	head := make([]byte, 512)
	_ = upA.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := upA.Read(head)
	if err != nil {
		t.Fatalf("upstream A never got the first request: %v", err)
	}
	if strings.Contains(string(head[:n]), "b.example") {
		t.Fatalf("the second request went into the first origin's socket:\n%s", head[:n])
	}

	// An origin that ignores "Connection: close" and keeps the connection open.
	if _, err := upA.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")); err != nil {
		t.Fatalf("upstream A write: %v", err)
	}

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("client got no response: %v", err)
	}
	defer resp.Body.Close()
	if !resp.Close {
		t.Fatal("the response did not tell the client to retire the connection")
	}

	_ = upA.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := upA.Read(head); err == nil && strings.Contains(string(head[:n]), "b.example") {
		t.Fatalf("the second request reached the first origin after the response:\n%s", head[:n])
	}
	if got := dial.lastCall(t); got != "a.example:80" {
		t.Fatalf("last upstream dialled was %s, want a.example:80", got)
	}
}

// A client that sent no User-Agent has to reach the origin without one.
// http.Request.Write fills in Go's default otherwise, and "Go-http-client/1.1"
// on the wire names this proxy to anyone reading the far end.
func TestTetherHTTPForwardDoesNotStampItsOwnUserAgent(t *testing.T) {
	dial := newRecordingDial()
	p := newTestTetherProxy(t, dial.fn)

	c := dialProxy(t, p)
	if _, err := c.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	up := dial.upstream(t)
	head := make([]byte, 512)
	_ = up.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := up.Read(head)
	if err != nil {
		t.Fatalf("upstream never got the request: %v", err)
	}
	if strings.Contains(string(head[:n]), "Go-http-client") {
		t.Fatalf("the proxy named itself on a request the client sent no User-Agent on:\n%s", head[:n])
	}
}

// isInNet() resolves a hostname through the CLIENT's own DNS, and a tethered
// client has none that works. Unguarded, every request paid two lookups that
// could only fail or hang before the PAC would name the proxy at all.
func TestTetherPACOnlyCallsIsInNetOnLiteralIPs(t *testing.T) {
	p := newTestTetherProxy(t, failingDial)
	pac := p.pacFile()
	guard := strings.Index(pac, `.test(host)`)
	if guard < 0 {
		t.Fatalf("PAC calls isInNet without a literal-IP guard:\n%s", pac)
	}
	if first := strings.Index(pac, "isInNet"); first < guard {
		t.Fatalf("an isInNet call sits ahead of the literal-IP guard:\n%s", pac)
	}
}

// An authority full of colons is not an authority with a port: SplitHostPort
// rightly refuses "[::1]", and treating that as a parse failure turned every
// IPv6-literal URL into a 400.
func TestSplitHostPortDefault(t *testing.T) {
	for _, tc := range []struct {
		in      string
		defPort int
		host    string
		port    int
		wantErr bool
	}{
		{"example.com", 80, "example.com", 80, false},
		{"example.com:8080", 80, "example.com", 8080, false},
		{"[::1]", 80, "::1", 80, false},
		{"[2001:db8::1]:443", 80, "2001:db8::1", 443, false},
		{"::1", 443, "::1", 443, false},
		{"example.com:http", 80, "", 0, true},
		{"", 80, "", 0, true},
	} {
		host, port, err := splitHostPortDefault(tc.in, tc.defPort)
		if tc.wantErr {
			if err == nil {
				t.Errorf("splitHostPortDefault(%q) = %q,%d, want an error", tc.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitHostPortDefault(%q): %v", tc.in, err)
			continue
		}
		if host != tc.host || port != tc.port {
			t.Errorf("splitHostPortDefault(%q) = %q,%d, want %q,%d", tc.in, host, port, tc.host, tc.port)
		}
	}
}

// An "https://" absolute URI names port 443, and some clients do emit one.
// Defaulting to 80 regardless sent it to the origin's cleartext port.
func TestDefaultPortForScheme(t *testing.T) {
	if got := defaultPortForScheme("https"); got != 443 {
		t.Errorf("https defaulted to %d, want 443", got)
	}
	if got := defaultPortForScheme("http"); got != 80 {
		t.Errorf("http defaulted to %d, want 80", got)
	}
}
