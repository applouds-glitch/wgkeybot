/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Internet sharing ("tether"): the phone raises a local-only Wi-Fi access point
// — one with no NAT of its own — and this proxy is the single door out of it.
//
// The protect policy here is the whole feature, and its two halves are mirror
// images:
//
//   - sockets facing the CLIENT (the listener and every accepted connection) are
//     protected. This app is deliberately kept inside its own tunnel, so without
//     protect() the replies to 192.168.x.x would be routed into the tun and
//     dropped — the destination is not in AllowedIPs (see errSocketNotProtected
//     in turn-client.go for the same lesson learned from the other direction).
//   - sockets facing the INTERNET are deliberately NOT protected. That is the
//     entire point: unprotected means routed into the tunnel, which is what
//     makes a tethered client's traffic come out of the WireGuard server.
//
// Do not "fix" the second half by analogy with the rest of this package.
//
// The client-facing half is protected through tetherProtectControl (see
// tether_export.go), NOT through protectControl, and the difference matters.
// protectControl additionally binds the socket to the cached physical network,
// because a TURN dial must leave over the real uplink. Doing that here installs
// an explicit-network routing rule that outranks the local-network rule for the
// access point's own subnet: replies to a tethered client would be emitted on
// the mobile interface with a 192.168.x.1 source address and never arrive. The
// mark is also inherited by every accepted socket and cannot be removed later
// (bindSocket throws once a socket is connected), so it must never be set.
// Keep the two helpers apart; unifying them breaks one path or the other.

const (
	tetherHandshakeTimeout = 5 * time.Second
	tetherMaxConns         = 512
	tetherBufSize          = 32 * 1024
	tetherKeepAlive        = 30 * time.Second
	tetherClientTTL        = 5 * time.Minute

	// Bounds on the pause after a recoverable Accept error. The realistic one is
	// EMFILE/ENFILE — the phone momentarily out of file descriptors — which is a
	// condition to wait out, not a reason to stop sharing. Starting small keeps a
	// one-off blip invisible; the ceiling keeps a persistent one from spinning
	// the CPU.
	tetherAcceptBackoffMin = 10 * time.Millisecond
	tetherAcceptBackoffMax = time.Second
)

// errTetherStopping is what a dial that finished after stop() had already taken
// its snapshot reports. The socket is closed rather than served: stop() can no
// longer reach it, and an unreachable upstream socket is exactly the thing that
// outlives the tunnel.
var errTetherStopping = errors.New("sharing is stopping")

// tetherDialFunc reaches the internet through the tunnel. It is a field rather
// than a package function so tests can run the whole proxy against a fake
// upstream.
type tetherDialFunc func(ctx context.Context, host string, port int) (net.Conn, error)

type tetherStats struct {
	Port    int   `json:"port"`
	Clients int   `json:"clients"`
	Conns   int64 `json:"conns"`
	Up      int64 `json:"up"`
	Down    int64 `json:"down"`
}

type tetherProxy struct {
	ln               net.Listener
	dial             tetherDialFunc
	protect          func(net.Conn) error
	maxConns         int
	handshakeTimeout time.Duration
	cancel           context.CancelFunc
	// onFatal retires this proxy after an Accept error no retry can fix. Wired to
	// stopTetherProxy by startTetherProxy; a field so tether_proxy.go stays free
	// of the cgo half and so tests can observe it.
	onFatal func()

	wg        sync.WaitGroup
	conns     atomic.Int64
	bytesUp   atomic.Int64
	bytesDown atomic.Int64

	mu      sync.Mutex
	clients map[string]time.Time
	// live holds every socket this proxy owns and is still using — both halves
	// of every connection being served — so stop() can close them instead of
	// leaving them running past the tunnel. The upstream half belongs here just
	// as much as the client half does; see stop().
	live    map[net.Conn]struct{}
	stopped bool
}

func newTetherProxy(ln net.Listener, dial tetherDialFunc) *tetherProxy {
	return &tetherProxy{
		ln:               ln,
		dial:             dial,
		protect:          defaultTetherProtect,
		maxConns:         tetherMaxConns,
		handshakeTimeout: tetherHandshakeTimeout,
		clients:          make(map[string]time.Time),
		live:             make(map[net.Conn]struct{}),
	}
}

func (p *tetherProxy) serve(ctx context.Context) {
	var backoff time.Duration
	for {
		c, err := p.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isTemporaryAcceptError(err) {
				// Recoverable: wait it out rather than end sharing. Returning here
				// used to leave tetherCurrent non-nil, so wgTetherStats kept
				// reporting a healthy session over a proxy that accepted nothing.
				backoff = nextAcceptBackoff(backoff)
				turnLog("[TETHER] accept failed: %v; retrying in %v", err, backoff)
				select {
				case <-time.After(backoff):
					continue
				case <-ctx.Done():
					return
				}
			}
			// Genuinely fatal (the listener is gone and nobody asked for that).
			// Retire the whole proxy so the Kotlin side sees an empty session
			// instead of an Active one that can never serve another client.
			turnLog("[TETHER] accept failed fatally: %v; shutting sharing down", err)
			if p.onFatal != nil {
				// Not inline: onFatal calls stop(), which waits on connections
				// this goroutine is not part of but must not block ahead of.
				go p.onFatal()
			}
			return
		}
		backoff = 0
		if p.conns.Load() >= int64(p.maxConns) {
			turnLog("[TETHER] connection cap %d reached, dropping %s", p.maxConns, c.RemoteAddr())
			_ = c.Close()
			continue
		}
		if err := p.protect(c); err != nil {
			turnLog("[TETHER] protect failed: %v, closing connection from %s", err, c.RemoteAddr())
			_ = c.Close()
			continue
		}
		if !p.trackConn(c) {
			// stop() already walked the live set, so nothing would ever close
			// this one. Drop it here rather than serve a connection the shutdown
			// path can no longer reach.
			_ = c.Close()
			continue
		}
		p.noteClient(c.RemoteAddr())
		p.conns.Add(1)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.conns.Add(-1)
			defer p.untrackConn(c)
			defer c.Close()
			p.handle(ctx, c)
		}()
	}
}

// isTemporaryAcceptError reports whether Accept can be expected to work again
// shortly. Descriptor and buffer exhaustion are the phone being briefly busy;
// ECONNABORTED is a client that vanished between SYN and accept; EINTR is noise.
// net.Error.Temporary() is deprecated and lies, so the errnos are named here.
func isTemporaryAcceptError(err error) bool {
	switch {
	case errors.Is(err, syscall.EMFILE),
		errors.Is(err, syscall.ENFILE),
		errors.Is(err, syscall.ENOBUFS),
		errors.Is(err, syscall.ENOMEM),
		errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, syscall.EINTR):
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func nextAcceptBackoff(current time.Duration) time.Duration {
	if current == 0 {
		return tetherAcceptBackoffMin
	}
	if next := current * 2; next < tetherAcceptBackoffMax {
		return next
	}
	return tetherAcceptBackoffMax
}

// trackConn registers a live client connection with stop(). It reports false
// once the proxy is stopping: at that point stop() has already taken its
// snapshot, and an entry added afterwards would never be closed.
func (p *tetherProxy) trackConn(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return false
	}
	p.live[c] = struct{}{}
	return true
}

// untrackConn drops a finished connection so the live set tracks reality rather
// than every connection this proxy has ever accepted.
func (p *tetherProxy) untrackConn(c net.Conn) {
	p.mu.Lock()
	delete(p.live, c)
	p.mu.Unlock()
}

// releaseConn closes a socket and drops it from the live set in one step. Every
// socket this proxy owns leaves through here or through stop(); a handler that
// closes one without untracking would leave stop() holding a stale entry.
func (p *tetherProxy) releaseConn(c net.Conn) {
	p.untrackConn(c)
	_ = c.Close()
}

func (p *tetherProxy) noteClient(addr net.Addr) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[host] = now
	for k, seen := range p.clients {
		if now.Sub(seen) > tetherClientTTL {
			delete(p.clients, k)
		}
	}
}

// dialUpstream reaches the internet on behalf of a client connection, and owns
// the client socket's deadline while it does.
//
// The handshake deadline bounds how long a client may take to state what it
// wants; it must not also bound how long we take to get there. The dial behind
// it resolves through the tunnel and connects over TURN relays, which routinely
// costs more than the five seconds a handshake gets. With one deadline covering
// both, a slow-but-successful dial ended with the "200 Connection established"
// write failing on a timeout that had passed while the upstream was still being
// opened — the client saw a silently dropped connection and the site "sometimes
// not loading". So the clock is stopped for the dial and restarted afterwards,
// which also gives the error replies below a deadline they can be written under.
func (p *tetherProxy) dialUpstream(ctx context.Context, c net.Conn, host string, port int) (net.Conn, error) {
	_ = c.SetDeadline(time.Time{})
	upstream, err := p.dial(ctx, host, port)
	_ = c.SetDeadline(time.Now().Add(p.handshakeTimeout))
	if err != nil {
		return nil, err
	}
	// Registered for the same reason the client socket is, and it is not optional:
	// stop() closes what the live set can reach, and an upstream it cannot reach
	// is one that outlives the tunnel. See stop().
	if !p.trackConn(upstream) {
		_ = upstream.Close()
		return nil, errTetherStopping
	}
	return upstream, nil
}

func (p *tetherProxy) handle(ctx context.Context, c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(p.handshakeTimeout))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	p.dispatch(ctx, c, br, first[0])
}

// dispatch routes by the first byte, the same trick PdaNet uses on its :8000
// port. Protocol handlers arrive in the next two tasks; until then every client
// is unrecognised.
func (p *tetherProxy) dispatch(ctx context.Context, c net.Conn, br *bufio.Reader, first byte) {
	switch {
	case first == socksVersion5:
		p.serveSocks5(ctx, c, br)
	case isHTTPStart(first):
		p.serveHTTP(ctx, c, br)
	default:
		turnLog("[TETHER] unrecognised first byte 0x%02x from %s", first, c.RemoteAddr())
	}
}

// splice moves bytes both ways until either side is done. The handshake deadline
// is cleared first: past the handshake a connection may legitimately idle for
// hours (websockets, long polls), so liveness is left to TCP keepalive.
//
// clientSrc, not client, is the read side: the handshake was parsed through a
// bufio.Reader, and a client that pipelined its payload (a TLS ClientHello right
// after CONNECT is the common case) already has those bytes sitting in that
// buffer. Reading the raw conn here would silently drop them.
func (p *tetherProxy) splice(client net.Conn, clientSrc io.Reader, upstream net.Conn) {
	_ = client.SetDeadline(time.Time{})
	setTetherKeepAlive(client)
	setTetherKeepAlive(upstream)

	done := make(chan struct{}, 2)
	go func() {
		p.pipe(upstream, clientSrc, &p.bytesUp)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		p.pipe(client, upstream, &p.bytesDown)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// tetherBufPool holds the splice buffers between connections. At the connection
// cap this is 512 × two directions × 32 KB — 32 MB the collector would otherwise
// chase on a phone that is already running a VPN and a Wi-Fi radio.
var tetherBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, tetherBufSize)
		return &b
	},
}

func (p *tetherProxy) pipe(dst io.Writer, src io.Reader, counter *atomic.Int64) {
	bufp := tetherBufPool.Get().(*[]byte)
	defer tetherBufPool.Put(bufp)
	buf := *bufp
	for {
		n, err := src.Read(buf)
		if n > 0 {
			// Counted after the write, not before: the sheet presents these as
			// traffic the tethered client got, and bytes that were read here but
			// never reached the other side are not that.
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			counter.Add(int64(n))
		}
		if err != nil {
			return
		}
	}
}

// countingBody tallies an HTTP body against one of the proxy's counters, so a
// forwarded request means the same thing to the sharing sheet as a spliced
// tunnel does. httpForward relays through net/http rather than splice(), and
// without this its traffic would simply not appear in the numbers.
type countingBody struct {
	io.ReadCloser
	counter *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.counter.Add(int64(n))
	}
	return n, err
}

func setTetherKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(tetherKeepAlive)
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func (p *tetherProxy) stats() tetherStats {
	now := time.Now()
	p.mu.Lock()
	clients := 0
	for _, seen := range p.clients {
		if now.Sub(seen) <= tetherClientTTL {
			clients++
		}
	}
	p.mu.Unlock()
	port := 0
	if tcpAddr, ok := p.ln.Addr().(*net.TCPAddr); ok {
		port = tcpAddr.Port
	}
	return tetherStats{
		Port:    port,
		Clients: clients,
		Conns:   p.conns.Load(),
		Up:      p.bytesUp.Load(),
		Down:    p.bytesDown.Load(),
	}
}

func (p *tetherProxy) stop() {
	if p.cancel != nil {
		p.cancel()
	}
	_ = p.ln.Close()

	// Closing every live socket is not tidiness, it is the whole point of stop().
	// The context only reaches the dial, and splice() blocks until BOTH
	// directions finish, so without this a connection with an idle peer parks
	// forever. Its upstream socket is deliberately unprotected, so once the
	// tunnel is gone that connection egresses straight out the carrier with the
	// user's real IP — precisely the leak the sharing sheet promises cannot
	// happen.
	//
	// BOTH ends have to be closed. This used to close only the client one, on the
	// theory that the handler's own defers would take the upstream with it. They
	// do not: the upstream→client pipe is parked in upstream.Read, which closing
	// the client socket does not disturb, and the closeWrite() the other pipe
	// performs only half-closes the upstream. A peer that does not answer that
	// FIN — any idle keep-alive or websocket connection — left the handler in
	// Read for good: goroutine and both descriptors leaked, p.conns stuck above
	// zero, and every tunnel teardown paying the full backstop below. The tests
	// agreed with the old comment only because net.Pipe has no CloseWrite, so
	// closeWrite() closed it outright; a real TCP upstream does not.
	p.mu.Lock()
	p.stopped = true
	live := make([]net.Conn, 0, len(p.live))
	for c := range p.live {
		live = append(live, c)
	}
	p.live = make(map[net.Conn]struct{})
	p.mu.Unlock()
	for _, c := range live {
		_ = c.Close()
	}

	waited := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		// Backstop only: with the live set closed above this should never fire.
		// If it does, something is blocked on a socket we do not know about.
		turnLog("[TETHER] stop: %d connections still draining", p.conns.Load())
	}
}
