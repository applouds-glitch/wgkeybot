/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"testing"
	"time"
)

// fakeWGH1Relay answers like a wrap-server that speaks WGH1 (plain framing):
// an ACK for a HELLO, carrying the HELLO's nonce, and an echo for any other
// STUN keepalive — the relay-proof probe is still a plain Binding Indication.
func fakeWGH1Relay(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc := listenFakeRelay(t)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if kind, nonce, _, _, ok := parseFeedback(buf[:n]); ok && kind == feedbackHello {
				pc.WriteTo(feedbackHeader(feedbackAck, nonce), from)
				continue
			}
			if isStunKeepalive(buf[:n]) {
				pc.WriteTo(buf[:n], from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// wireGuardSide stands in for the local WireGuard endpoint the stream forwards
// downlink payloads to, so a test can prove control packets never reach it.
func wireGuardSide(t *testing.T, s *stream) net.PacketConn {
	t.Helper()
	wg := listenFakeRelay(t)
	var addr net.Addr = wg.LocalAddr()
	s.peer.Store(&addr)
	return wg
}

func assertNothingForwarded(t *testing.T, wg net.PacketConn) {
	t.Helper()
	wg.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 2048)
	if n, _, err := wg.ReadFrom(buf); err == nil {
		t.Fatalf("a %d-byte control packet was forwarded to WireGuard", n)
	}
}

func runUntilReady(t *testing.T, s *stream, relayConn net.PacketConn, peer *net.UDPAddr) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { s.runNoDTLS(ctx, relayConn, peer) }()
	deadline := time.Now().Add(relayProofTimeout)
	for !s.ready.Load() {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the stream never went ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cancel
}

// The hook end to end: the HELLO sent the moment the stream goes ready reaches
// the server, its ACK makes this attempt capable, and the ACK itself — like any
// control packet — stays out of WireGuard.
func TestNoDTLSFeedbackNegotiatesWithAWGH1Server(t *testing.T) {
	defer resetServerHealth()
	resetServerHealth()

	s, relayConn := newNoDTLSTestStream(t)
	s.feedbackEnabled = true
	wg := wireGuardSide(t, s)

	// The regular keepalive is a HELLO too, so a grid tick inside the window
	// would negotiate on its own and hide a missing post-ready HELLO (it did, in
	// one mutation run out of six). Start just past a tick: the next is ~25s out.
	if next := nextKeepaliveGrid(time.Now(), s.kaPhase); time.Until(next) < 4*time.Second {
		time.Sleep(time.Until(next) + 100*time.Millisecond)
	}
	cancel := runUntilReady(t, s, relayConn, fakeWGH1Relay(t))
	defer cancel()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if c := s.control.Load(); c != nil && c.capable.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a WGH1 server's ACK never made the stream capable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	assertNothingForwarded(t, wg)
}

// A server that predates WGH1 reflects the HELLO as a plain keepalive. That
// must neither enable reports nor leak into WireGuard, and the stream must
// work exactly as before.
func TestNoDTLSFeedbackStaysOffAgainstALegacyServer(t *testing.T) {
	defer resetServerHealth()
	resetServerHealth()

	s, relayConn := newNoDTLSTestStream(t)
	s.feedbackEnabled = true
	wg := wireGuardSide(t, s)
	answer := make(chan struct{})
	close(answer)
	cancel := runUntilReady(t, s, relayConn, fakeRelay(t, answer))
	defer cancel()

	time.Sleep(300 * time.Millisecond) // the reflected HELLO has come back by now
	if c := s.control.Load(); c == nil || c.capable.Load() {
		t.Fatalf("legacy echo: control=%v, want present and not capable", c)
	}
	assertNothingForwarded(t, wg)
}

// Feedback off (a peer type that does not end at vk-turn-proxy) keeps the
// exact keepalive the stream always sent.
func TestFeedbackOffKeepsThePlainKeepalive(t *testing.T) {
	s := &stream{sessionID: make([]byte, 16)}
	if c := s.newFeedbackControl(); c != nil || string(c.keepalive()) != string(stunBindingIndication) {
		t.Fatal("feedback off changed the keepalive")
	}
	s.feedbackEnabled = true
	c := s.newFeedbackControl()
	if kind, nonce, _, _, ok := parseFeedback(c.keepalive()); !ok || kind != feedbackHello || nonce != c.nonce {
		t.Fatal("feedback on did not turn the keepalive into this attempt's HELLO")
	}
}
