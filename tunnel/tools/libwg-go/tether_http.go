/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// hopByHop headers describe the client↔proxy leg and must not be forwarded.
var hopByHop = []string{
	"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
	"Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

// isHTTPStart reports whether a first byte can start an HTTP method. SOCKS5
// starts with 0x05, so a printable uppercase letter is enough to tell them apart.
func isHTTPStart(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

func (p *tetherProxy) serveHTTP(ctx context.Context, c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	switch {
	case req.Method == http.MethodConnect:
		p.httpConnect(ctx, c, br, req)
	case req.URL.IsAbs():
		p.httpForward(ctx, c, req)
	case req.URL.Path == "/pac" || req.URL.Path == "/":
		p.servePAC(c)
	default:
		writeHTTPStatus(c, "404 Not Found")
	}
}

func (p *tetherProxy) httpConnect(ctx context.Context, c net.Conn, br *bufio.Reader, req *http.Request) {
	host, port, err := splitHostPortDefault(req.Host, 443)
	if err != nil {
		writeHTTPStatus(c, "400 Bad Request")
		return
	}
	upstream, err := p.dialUpstream(ctx, c, host, port)
	if err != nil {
		turnLog("[TETHER] CONNECT %s:%d failed: %v", host, port, err)
		writeHTTPStatus(c, "502 Bad Gateway")
		return
	}
	defer p.releaseConn(upstream)

	if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	p.splice(c, br, upstream)
}

// httpForward handles plain-HTTP requests, which arrive in absolute-URI form:
// one request is relayed to the origin, its response is relayed back, and the
// connection ends there.
//
// What it must NOT do is hand the rest of the client connection to splice(),
// which is what it used to do. A proxy connection is not bound to one origin —
// the client names a host per request — so splicing wrote request number two
// into request number one's socket. "Connection: close" on the way out was meant
// to make that unreachable by having the origin hang up first, but an origin is
// free to ignore it, and a client that pipelines never waits for the response at
// all: its second request was already sitting in br and went straight down the
// wire to the wrong server.
//
// One request per connection costs a fresh upstream for every plain-HTTP
// request. That was already the price of "Connection: close", and HTTPS — very
// nearly all of the traffic — goes through CONNECT, where one connection still
// carries everything.
// No bufio.Reader parameter, unlike httpConnect: the request body already reads
// through the one http.ReadRequest was handed, and nothing else on the client
// connection is ours to forward.
func (p *tetherProxy) httpForward(ctx context.Context, c net.Conn, req *http.Request) {
	host, port, err := splitHostPortDefault(req.URL.Host, defaultPortForScheme(req.URL.Scheme))
	if err != nil {
		writeHTTPStatus(c, "400 Bad Request")
		return
	}
	upstream, err := p.dialUpstream(ctx, c, host, port)
	if err != nil {
		turnLog("[TETHER] %s %s failed: %v", req.Method, req.URL, err)
		writeHTTPStatus(c, "502 Bad Gateway")
		return
	}
	defer p.releaseConn(upstream)

	for _, h := range hopByHop {
		req.Header.Del(h)
	}
	// A client that sent no User-Agent has to reach the origin without one.
	// http.Request.Write fills in Go's default otherwise, and stamping
	// "Go-http-client/1.1" on the request names this proxy to anyone reading the
	// far end — the opposite of what the app exists for. A nil entry is how
	// net/http is told to omit a header rather than supply it.
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header["User-Agent"] = nil
	}
	req.Close = true
	outURL := *req.URL
	outURL.Scheme = ""
	outURL.Host = ""
	req.URL = &outURL
	req.RequestURI = ""
	if req.Body != nil {
		req.Body = &countingBody{ReadCloser: req.Body, counter: &p.bytesUp}
	}

	// No deadline over the transfer itself. The handshake deadline bounds how
	// long a client may take to say what it wants; req.Write streams the request
	// BODY, which is data in flight over a TURN path. Under the old deadline an
	// upload larger than five seconds' worth died mid-body with no status written
	// at all — the same mistake dialUpstream exists to undo, one step further
	// along. Liveness from here on is TCP keepalive's job, exactly as in splice().
	_ = c.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	setTetherKeepAlive(c)
	setTetherKeepAlive(upstream)

	if err := req.Write(upstream); err != nil {
		turnLog("[TETHER] %s %s: writing upstream failed: %v", req.Method, host, err)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		turnLog("[TETHER] %s %s: reading upstream failed: %v", req.Method, host, err)
		writeHTTPStatus(c, "502 Bad Gateway")
		return
	}
	defer resp.Body.Close()
	for _, h := range hopByHop {
		resp.Header.Del(h)
	}
	// Say out loud what the relay does anyway, so a client holding a keep-alive
	// proxy pool retires this connection instead of posting its next request into
	// a socket nobody will read again.
	resp.Close = true
	resp.Body = &countingBody{ReadCloser: resp.Body, counter: &p.bytesDown}
	_ = resp.Write(c)
}

// defaultPortForScheme answers the port an absolute-URI request meant when it
// named none. Assuming 80 unconditionally sent an "https://" absolute URI —
// which some clients do emit — to the origin's cleartext port.
func defaultPortForScheme(scheme string) int {
	if strings.EqualFold(scheme, "https") {
		return 443
	}
	return 80
}

func (p *tetherProxy) servePAC(c net.Conn) {
	body := p.pacFile()
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/x-ns-proxy-autoconfig\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	_, _ = c.Write([]byte(resp))
}

// pacFile keeps local addresses DIRECT so the client can still reach the phone
// itself (and the PAC URL) without bouncing through the tunnel.
//
// The local subnet is derived from the address actually bound, not hardcoded to
// 192.168: Android randomises the local-only hotspot's subnet, and it need not
// be a 192.168 one at all (the same fact ApAddress.kt was rewritten around). A
// PAC that guessed wrong sent the client's requests to the phone itself into the
// proxy, and from there into the tunnel, where they had nowhere to arrive.
// The two isInNet() calls are guarded by a literal-IP test on purpose. isInNet
// resolves a hostname through the CLIENT's own DNS, and a tethered client has
// none that works — resolving on the phone is the whole reason this proxy
// exists. Unguarded, every ordinary request paid two lookups that could only
// fail or hang before the PAC would even name the proxy.
func (p *tetherProxy) pacFile() string {
	proxy := p.ln.Addr().String()
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || host == "localhost") return "DIRECT";
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";
    if (isInNet(host, "%s", "255.255.255.0")) return "DIRECT";
  }
  return "PROXY %s";
}
`, pacLocalNetwork(p.ln.Addr()), proxy)
}

// pacLocalNetwork is the /24 the access point sits in. A local-only hotspot is
// always handed a /24, and the mask is not worth plumbing down from Kotlin for
// a hint whose only job is to keep the client's own subnet off the proxy.
func pacLocalNetwork(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "0.0.0.0"
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return "0.0.0.0"
	}
	return net.IPv4(ip[0], ip[1], ip[2], 0).String()
}

func writeHTTPStatus(c net.Conn, status string) {
	_, _ = c.Write([]byte("HTTP/1.1 " + status + "\r\nConnection: close\r\n\r\n"))
}

// splitHostPortDefault splits an authority into host and port, supplying defPort
// when it carries none.
//
// "contains a colon" is not the same question as "has a port": an IPv6 literal
// is all colons. Treating the two as one turned "http://[::1]/x" into a 400,
// because SplitHostPort rightly refused an authority with no port in it.
func splitHostPortDefault(hostport string, defPort int) (string, int, error) {
	if hostport == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	if host, portStr, err := net.SplitHostPort(hostport); err == nil {
		port, perr := strconv.Atoi(portStr)
		if perr != nil {
			return "", 0, perr
		}
		return host, port, nil
	}
	// No port, then. Either a name or an IPv4 literal, or an IPv6 one — which a
	// URL brackets and a CONNECT authority may not.
	host := strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", 0, fmt.Errorf("cannot parse authority %q", hostport)
	}
	return host, defPort, nil
}
