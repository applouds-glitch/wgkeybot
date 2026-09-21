/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/android/srtpwrap"
)

// srtpTestPeer is the far end of an SRTP stream: it completes the handshake of
// whoever dials it through a relay and drains what they send.
func srtpTestPeer(t *testing.T) *net.UDPAddr {
	t.Helper()
	srv, err := srtpwrap.Listen(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("srtp peer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var readers sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		srv.Close()
		readers.Wait()
	})
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			c, err := srv.Accept(ctx)
			if err != nil {
				return
			}
			// The server closes no session of its own accord, and a reader of one
			// waits for ever.
			stop := context.AfterFunc(ctx, func() { c.Close() })
			readers.Add(1)
			go func() {
				defer readers.Done()
				defer stop()
				defer c.Close()
				buf := make([]byte, 2048)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	return srv.Addr().(*net.UDPAddr)
}

// The reset of TestResetTCPFlowOnAnIdleTunnelIsReplacedAtOnce, over the transport
// the field runs. Everything that ends a session early — the blackhole watchdog,
// a flow the kernel gave up, pion's reader gone — does it by closing the relay,
// and under SRTP that ended nothing: the reader waits on a channel the demux
// feeds, and the demux retried the closed relay's error for ever (see
// srtpwrap.runDemuxFromPacketConn). On an idle tunnel the stream stayed ready
// until the dead-stream detector, the very 90s those three exist to cut short.
func TestResetTCPFlowUnderSRTPIsReplacedAtOnce(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	front := startStallingFront(t, relay.addr)
	overTCP(t)

	h := runWorkersOfType(t, 124, 1, []string{front.addr}, srtpTestPeer(t), "srtp")
	t.Cleanup(front.close)
	waitFor(t, "an SRTP stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })

	front.resetDownstream()
	waitFor(t, "the stream back up on a new connection", 8*time.Second, func() bool {
		return front.accepted.Load() >= 2 && h.ready() == 1
	})

	serverHealthState.Lock()
	failures := healthEntryLocked(front.addr).failures
	serverHealthState.Unlock()
	if failures != 0 {
		t.Fatalf("the relay took %d strike(s) for a flow that was reset", failures)
	}
}

// The kernel's verdict on a hung flow, delivered to pion's reader on an idle
// tunnel (TestFlowGivenUpUnderThePionReaderEndsTheSessionAtOnce), under SRTP.
func TestFlowGivenUpUnderSRTPEndsTheSessionAtOnce(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)

	cue := make(chan struct{})
	prev := dialRelayTCP
	first := true
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		c, err := prev(ctx, d, addr)
		if err != nil || !first {
			return c, err
		}
		first = false
		return &cuedTimeoutConn{Conn: c, cue: cue}, nil
	}
	t.Cleanup(func() { dialRelayTCP = prev })

	h := runWorkersOfType(t, 125, 1, []string{relay.addr}, srtpTestPeer(t), "srtp")
	waitFor(t, "an SRTP stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })

	close(cue)
	waitFor(t, "the stream back up on a new connection", 8*time.Second, func() bool {
		return relay.ln.accepted.Load() >= 2 && h.ready() == 1
	})
}

// The blackhole watchdog, over UDP: nothing is wrong with the socket, so no
// read or write of the session's own fails — closing the relay is all that
// ends it, and the session has to end there and then, with the watchdog's
// reason as its error.
func TestBlackholedAllocationUnderSRTPEndsTheSessionAtOnce(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	relay := startTestRelay(t, listenFakeRelay(t), 0)
	cfg := WorkerGroupConfig{GroupID: 126, Link: "test", UseUDP: true, PeerType: "srtp", PeerAddr: srtpTestPeer(t)}

	s, _ := newNoDTLSTestStream(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, raw, relayConn, rtt, perm, err := dialAndAllocate(ctx, s, t.Name(), "pass", relay.addr, cfg, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() {
		ended <- s.runSession(ctx, winner{client: client, raw: raw, relay: relayConn, addr: relay.addr, rtt: rtt, perm: perm}, cfg)
	}()
	waitFor(t, "an SRTP stream over UDP", 5*time.Second, func() bool { return s.ready.Load() })

	perm.markDead("refresh allocation failed: test")
	select {
	case err := <-ended:
		if err == nil || !strings.Contains(err.Error(), "TURN blackhole") {
			t.Fatalf("the session ended with %v, want the watchdog's reason", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the session is still running 3s after the watchdog closed its relay")
	}
}
