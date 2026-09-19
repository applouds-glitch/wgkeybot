/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"sync/atomic"
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
	c, err := dialRelayTCP(ctx, d, addr)
	if err != nil {
		return nil, err
	}
	return &splitFirstWriteConn{Conn: c}, nil
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
