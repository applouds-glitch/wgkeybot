/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Reaching the relay over TCP.
//
// UDP is the transport everywhere it works: one relay allocation per datagram
// socket, no head-of-line blocking under WireGuard. TCP to the relay is here for
// the networks where UDP to it does not carry a session at all. The known one is
// Rostelecom's mobile network behind a whitelist (field reports from another
// client of the same relays, July–August 2026): the replies to Allocate and
// CreatePermission come back over UDP, but nothing the relay forwards down to
// the phone ever arrives, so no stream gets through its data-plane handshake.
// TURN over TCP to the very same relay address works there.
//
// Only the client↔relay leg changes. The allocation is still a UDP relay and the
// relay↔server leg is UDP either way, so the server side needs nothing. VK's
// relays take TURN over TCP on the same port as UDP (checked 2026-09-19: Allocate
// over TCP to :19302 draws the same 401 challenge, realm okcdn.ru); they speak no
// TLS there, and 443/3478/5349 are closed.
//
// The cost is WireGuard inside TCP streams — a lost segment stalls the whole
// stream until it is retransmitted — which is why this is a per-network choice
// and not the default.

// relayTransport values pushed down with the physical network (wgSetNetwork).
const (
	relayTransportAsConfigured int32 = iota // what #@wgt:UseUDP says
	relayTransportUDP
	relayTransportTCP
)

// relayTransportChoice is read by every dial, not once per proxy start: a
// session that moves from Wi-Fi to a network that needs TCP redials at once
// (network_switch.go), and that dial has to go out over TCP already — waiting
// for the handshake watchdog to rebuild the transport would cost minutes, on a
// network reported to penalise failed attempts with minutes of its own.
var relayTransportChoice atomic.Int32

func setRelayTransport(choice int32) {
	switch choice {
	case relayTransportUDP, relayTransportTCP:
	default:
		choice = relayTransportAsConfigured
	}
	if old := relayTransportChoice.Swap(choice); old != choice {
		turnLog("[NETWORK] relay transport: %s", relayTransportName(choice))
	}
}

func relayTransportName(choice int32) string {
	switch choice {
	case relayTransportUDP:
		return "UDP"
	case relayTransportTCP:
		return "TCP"
	default:
		return "as configured"
	}
}

// relayOverTCP reports whether the next dial reaches the relay over TCP.
func relayOverTCP(cfg WorkerGroupConfig) bool {
	switch relayTransportChoice.Load() {
	case relayTransportUDP:
		return false
	case relayTransportTCP:
		return true
	default:
		return !cfg.UseUDP
	}
}

// relayTCPConnectTimeout bounds the TCP connect to a relay. The dialer's 30s was
// never meant for it (a UDP "dial" sends nothing); on the network this exists
// for, connects to a relay were seen hanging by the hundred, and every hung one
// holds its worker. The kernel gives up a SYN after 1+2+4s of retransmissions
// anyway — 6s keeps the first two and drops the wait for the third's answer.
const relayTCPConnectTimeout = 6 * time.Second

// dialRelayTCP is the seam tests replace to make a relay's connect hang: a
// blackholed SYN cannot be staged on loopback.
var dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
	return d.DialContext(ctx, "tcp", addr)
}

// connectRelayTCP connects to a relay and returns the connection all TURN
// traffic to it is written through.
func connectRelayTCP(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
	d.Timeout = relayTCPConnectTimeout
	// Before the connect: the limit has to be in the SYN for the relay to keep to
	// it (see relayTCPMaxSegment). After whatever the dialer already does there —
	// protecting the socket.
	before := d.Control
	d.Control = func(network, address string, c syscall.RawConn) error {
		if before != nil {
			if err := before(network, address, c); err != nil {
				return err
			}
		}
		if err := setTCPMaxSegment(c, relayTCPMaxSegment); err != nil {
			maxSegmentRefused.Do(func() {
				turnLog("[NETWORK] TCP_MAXSEG refused (%v) — segments to and from a relay stay as large as the interface allows", err)
			})
		}
		return nil
	}
	c, err := dialRelayTCP(ctx, d, addr)
	if err != nil {
		return nil, err
	}
	// After the connect, so the SYN keeps its own, shorter limit above.
	if tc, ok := c.(*net.TCPConn); ok {
		if err := setTCPUserTimeout(tc, relayTCPUserTimeout); err != nil {
			userTimeoutRefused.Do(func() {
				turnLog("[NETWORK] TCP_USER_TIMEOUT refused (%v) — a hung flow to a relay is left to the kernel's default", err)
			})
		}
	}
	return &splitFirstWriteConn{Conn: &relayFlowConn{Conn: c, gaveUp: make(chan struct{})}}, nil
}

// relayTCPMaxSegment caps the TCP segments between the phone and a relay, in both
// directions: set before the connect it is the MSS our SYN announces, which the
// relay may not exceed, and the ceiling on our own.
//
// The tunnel's MTU is capped at 1200 because on cellular paths whose real MTU is
// ~1350-1400 large datagrams were lost while small ones passed (TURN_MAX_MTU).
// Over TCP that cap does nothing for this leg: the relay writes ChannelData into
// a byte stream and the kernels cut it by MSS, not by packet — under load that is
// full segments, 1460-byte packets on an interface that says 1460 (field log
// 19.09), over the very kind of path the cap exists for, with ICMP filtered so
// that nobody learns. A lost full-size segment is retransmitted at the same size
// for ever; everything behind it in the stream waits, the keepalive echo
// included, and the relay's TCP eventually gives up. It would look like what the
// field showed: flows going deaf under load and reset half a minute later, idle
// ones and small transactions fine — "only text goes through".
//
// Not proven to be the cause there: the log had no socket telemetry yet (see
// silentSocketLine for what will tell). But the cost is a few per cent more
// segments, and 1240 makes packets of at most 1280 — the IPv6 minimum, below
// what the 1200 cap already puts on the same paths over UDP (~1310).
const relayTCPMaxSegment = 1240

var maxSegmentRefused sync.Once

// relayTCPUserTimeout is how long a connection to a relay may make no progress
// — data the relay has not acknowledged, or will not open its window for —
// before the kernel gives it up (TCP_USER_TIMEOUT).
//
// Without it the kernel keeps retransmitting for a quarter of an hour, and
// nothing above it cuts that short for a flow that hangs while it carries
// traffic: the stream's writer is blocked in the socket, its keepalive queues up
// behind the writer on the same descriptor, and the dead-stream detector lives
// in the keepalive's loop — so the one stream that most needs replacing is the
// one that cannot notice. It stays "ready", is skipped as stale after 35s, and
// the pool is a stream short for good. On the network TCP is here for, flows
// hang one by one (field log 19.09: four of ten within a minute of coming up).
//
// 30s, from both sides. The hangs seen to clear on their own there lasted 2-8s,
// so this is four times clear of them. And past ~25s waiting stops being worth
// it even for a path that comes back: the retransmission timer doubles each
// time (0.4, 1.2, 2.8, 6, 12, 25, 51s… from a 400ms start), so a flow silent for
// 30s will not try again until the 51st second, while a redial takes a second
// or a few. It also lands before dispatchStaleAfter: the stream is replaced
// rather than parked.
//
// The kernel applies the same limit to its keepalive probes (Go turns them on,
// 15s idle), so an idle flow that has gone dark is given up within the minute
// too, not only one with a writer stuck in it.
//
// A var for the host tests, which cannot wait 30s.
var relayTCPUserTimeout = 30 * time.Second

var userTimeoutRefused sync.Once

// relayFlowConn is the TCP connection to a relay with one thing added: it notes
// the kernel giving the flow up. That verdict is delivered once, as ETIMEDOUT,
// to whichever call meets it first — pion's read loop, which swallows it, as
// often as the stream's writer — and every call after that sees only a broken
// pipe. runSession needs to know either way: to end the session at once rather
// than at the next failed write, and to keep the relay out of the blame (see
// there). A deadline of our own expiring is a different error and is not this.
type relayFlowConn struct {
	net.Conn
	gaveUp chan struct{}
	once   sync.Once
}

func (c *relayFlowConn) note(err error) {
	if errors.Is(err, syscall.ETIMEDOUT) {
		c.once.Do(func() { close(c.gaveUp) })
	}
}

func (c *relayFlowConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.note(err)
	}
	return n, err
}

func (c *relayFlowConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.note(err)
	}
	return n, err
}

// relayFlow finds the flow under a dialed relay conn; nil over UDP.
func relayFlow(c net.Conn) *relayFlowConn {
	if split, ok := c.(*splitFirstWriteConn); ok {
		c = split.Conn
	}
	flow, _ := c.(*relayFlowConn)
	return flow
}

// relayFlowGaveUp is closed when the kernel gives the relay's flow up. Over UDP
// it is nil, which a select waits on for ever.
func relayFlowGaveUp(c net.Conn) <-chan struct{} {
	if flow := relayFlow(c); flow != nil {
		return flow.gaveUp
	}
	return nil
}

func relayFlowTimedOut(c net.Conn) bool {
	select {
	case <-relayFlowGaveUp(c):
		return true
	default:
		return false
	}
}

// firstWriteSplit is where the first write to a relay over TCP is cut in two:
// inside the STUN header, ahead of the magic cookie at bytes 4..8, so that no
// single segment opens with a complete STUN header. A shallow DPI rule that
// classifies a flow by its first segment does not see TURN there. Whether
// Rostelecom's filter needs this is not known; the client that works there does
// it, the relays answer a split request exactly as a whole one (checked
// 2026-09-19), and it costs one extra segment per connection.
const (
	firstWriteSplit      = 6
	firstWriteSplitPause = 20 * time.Millisecond
)

// splitFirstWriteConn sends the first write as two segments (Go sets
// TCP_NODELAY, so two writes are two segments) and is transparent after that.
type splitFirstWriteConn struct {
	net.Conn
	done atomic.Bool
}

func (c *splitFirstWriteConn) Write(p []byte) (int, error) {
	if len(p) <= firstWriteSplit || !c.done.CompareAndSwap(false, true) {
		return c.Conn.Write(p)
	}
	n, err := c.Conn.Write(p[:firstWriteSplit])
	if err != nil {
		return n, err
	}
	time.Sleep(firstWriteSplitPause)
	m, err := c.Conn.Write(p[firstWriteSplit:])
	return n + m, err
}

// relayCloseWriteBudget is how long closing a relay over TCP may spend writing.
//
// Closing the relay conn is how every teardown here starts — the transports do
// it to unblock their reads, the blackhole watchdog to recycle an allocation,
// runSession on the way out — and pion's Close makes one synchronous write, the
// Refresh(lifetime=0) that releases the allocation. Over UDP a write never
// waits. Over TCP it waits for room in the socket's send buffer, and a flow
// that has stopped moving (field log 19.09, Rostelecom: flows to a relay hang
// for seconds at a time, some for good) has none to give: the stream's writer
// is already blocked in that socket with the buffer full behind it, the release
// queues up behind the writer, the transport waits for the writer, and
// runSession's raw.Close() — the one call that would free them all — is a defer
// that never runs. The worker is held until the kernel gives the connection up,
// a quarter of an hour; a stop or a move to another network leaves it behind on
// the old one. pion's relay conn has no write deadline to set (its
// SetWriteDeadline is a stub), so the deadline goes on the socket beneath it:
// it frees the blocked writer and bounds the release at once. vk-turn-proxy-ios
// found the same hang on a real allocation (2026-09-06) and bounds it the same
// way, with the same half second.
//
// A release that does not make it out in time fails Close with a timeout, which
// trackedRelay already reads as "this relay still holds our quota".
const relayCloseWriteBudget = 500 * time.Millisecond

// boundedCloseRelay is a relay allocated over a TCP connection: its first Close
// puts relayCloseWriteBudget on that connection's writes before pion makes its
// own. Later Closes (pion answers them "already closed" without writing) leave
// the deadline where the first one put it.
type boundedCloseRelay struct {
	net.PacketConn
	sock net.Conn
	once sync.Once
}

func boundRelayClose(relay net.PacketConn, sock net.Conn) net.PacketConn {
	return &boundedCloseRelay{PacketConn: relay, sock: sock}
}

func (r *boundedCloseRelay) Close() error {
	r.once.Do(func() {
		_ = r.sock.SetWriteDeadline(time.Now().Add(relayCloseWriteBudget))
	})
	return r.PacketConn.Close()
}
