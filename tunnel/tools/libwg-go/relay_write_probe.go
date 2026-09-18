/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// relayWriteProbe times the first packet a transport writes to the peer through
// a TURN relay, so a failed data-plane handshake can say which side of the relay
// it died on.
//
// The transports themselves only report "context deadline exceeded". But pion's
// relay WriteTo blocks on the first packet to a peer until the relay answers
// CreatePermission (internal/client/udp_conn.go createPermission: up to seven
// transmissions, ~7.8s) and returns a refusal as the write error, so that one
// write separates the faults:
//   - still blocked when the handshake gave up: the relay never answered
//     CreatePermission;
//   - failed: the relay refused the permission, or the socket died under it;
//   - returned: the relay granted the permission, and nothing came back through
//     it — the relay's path to the peer, or the peer itself.
//
// Field log 18.09: 193.203.43.43 allocated in 200ms and then failed every SRTP
// handshake for an hour, and nothing in the log could say which of these it was.
//
// After the first write the probe costs one atomic load per packet.
type relayWriteProbe struct {
	net.PacketConn

	once sync.Once
	// started is set once the first write has begun; startAt before it.
	started atomic.Bool
	startAt time.Time
	// done is set once the first write has returned; took and err before it.
	done atomic.Bool
	took time.Duration
	err  error
}

func newRelayWriteProbe(relay net.PacketConn) *relayWriteProbe {
	return &relayWriteProbe{PacketConn: relay}
}

func (p *relayWriteProbe) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.started.Load() {
		return p.PacketConn.WriteTo(b, addr)
	}
	var start time.Time
	p.once.Do(func() {
		start = time.Now()
		p.startAt = start
		p.started.Store(true)
	})
	if start.IsZero() {
		// A concurrent writer got there first; its write is the one timed.
		return p.PacketConn.WriteTo(b, addr)
	}
	n, err := p.PacketConn.WriteTo(b, addr)
	p.took, p.err = time.Since(start), err
	p.done.Store(true)
	return n, err
}

// describe says what the first write through the relay tells about a handshake
// that has just failed, as of now.
func (p *relayWriteProbe) describe(now time.Time) string {
	switch {
	case !p.started.Load():
		return "nothing was written to the peer through the relay"
	case !p.done.Load():
		return fmt.Sprintf("the first packet to the peer was still waiting on CreatePermission after %v — the relay never answered it",
			now.Sub(p.startAt).Round(time.Millisecond))
	case p.err != nil:
		return fmt.Sprintf("the first packet to the peer failed after %v: %v", p.took.Round(time.Millisecond), p.err)
	default:
		return fmt.Sprintf("the relay granted the peer permission in %v, but no reply came back through it",
			p.took.Round(time.Millisecond))
	}
}
