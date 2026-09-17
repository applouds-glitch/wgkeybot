/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// fakeRelay stands in for a TURN relay plus the wrap-server behind it. Echoing a
// keepalive is what the real server does ("echo it straight back to this
// stream", server/main.go); a relay that echoes nothing is the failure these
// tests exist for — an allocation that succeeds and then swallows everything.
//
// answer gates the echo, so a test can hold the round trip open and watch what
// the stream does while the relay is still silent. A nil answer never echoes.
func fakeRelay(t *testing.T, answer <-chan struct{}) *net.UDPAddr {
	t.Helper()
	pc := listenFakeRelay(t)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if answer == nil || !isStunKeepalive(buf[:n]) || !closed(answer) {
				continue
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// fakeWrapRelay answers with a WRAP-obfuscated keepalive, the shape the
// wireguard peer type actually runs in. It replies to anything it receives
// rather than inspecting the uplink: WRAP is directional (wrapTxDir uplink,
// wrapRxDir downlink), so opening the client's packets here would mean a second
// copy of unwrapPacket in the test — and what is under test is whether the
// client takes proof from a downlink packet, not what the server made of the
// uplink.
func fakeWrapRelay(t *testing.T, answer <-chan struct{}, key []byte) *net.UDPAddr {
	t.Helper()
	pc := listenFakeRelay(t)
	tx := newWrapTxState()
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if !closed(answer) {
				continue
			}
			pc.WriteTo(serverWrap(key, stunBindingIndication, tx), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// serverWrap builds a downlink WRAP packet the way the wrap-server does: same
// framing and primitives as wrapPacketInto, but keyed for the other direction,
// which is the only reason the client can open it at all.
func serverWrap(key, payload []byte, tx *wrapTxState) []byte {
	ssrc, counter := tx.next()
	plainLen := len(payload) + wrapPadLen
	out := make([]byte, wrapHdrLen+plainLen)
	putHeader(out[:wrapHdrLen], counter, plainLen, clientCipher, ssrc)
	plaintext := out[wrapHdrLen:]
	copy(plaintext, payload)
	binary.BigEndian.PutUint16(plaintext[plainLen-wrapPadLen:], 0)
	xorKeystream(clientCipher, key, counter, ssrc, wrapRxDir, plaintext)
	return out
}

func listenFakeRelay(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake relay listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func newNoDTLSTestStream(t *testing.T) (*stream, net.PacketConn) {
	t.Helper()
	relayConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay conn listen: %v", err)
	}
	t.Cleanup(func() { relayConn.Close() })

	out, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("out conn listen: %v", err)
	}
	t.Cleanup(func() { out.Close() })

	return &stream{
		id:         3,
		in:         make(chan []byte, 8),
		out:        out,
		sessionID:  make([]byte, 16),
		serverAddr: healthTestAddr,
		okFunc:     func() {},
	}, relayConn
}

// A stream is ready when the relay has carried a round trip, not when we have
// finished shouting into it. The old blind 200ms sleep made a blackholed relay
// indistinguishable from a working one, so the dispatcher kept feeding it — and
// WireGuard's handshake retries went into the hole until the tunnel gave up.
func TestNoDTLSMarksStreamReadyOnlyAfterTheRelayAnswers(t *testing.T) {
	defer resetServerHealth()
	resetServerHealth()

	s, relayConn := newNoDTLSTestStream(t)
	answer := make(chan struct{})
	peer := fakeRelay(t, answer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.runNoDTLS(ctx, relayConn, peer) }()

	// Well past the old sleep, and still nothing has come back.
	time.Sleep(relayProbeInterval + 300*time.Millisecond)
	if s.ready.Load() {
		t.Fatal("the stream went ready before the relay had answered anything")
	}

	close(answer)
	deadline := time.Now().Add(relayProofTimeout)
	for !s.ready.Load() {
		if time.Now().After(deadline) {
			t.Fatal("an answering relay never made the stream ready")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runNoDTLS did not unwind after cancellation")
	}
}

// The blackhole case: Allocate succeeded, so nothing upstream counts this
// against the server, and the relay answers nothing. The stream must stay out of
// the dispatcher and fail with a verdict runSession can act on immediately.
func TestNoDTLSFailsTheStreamWhenTheRelayNeverAnswers(t *testing.T) {
	defer resetServerHealth()
	resetServerHealth()

	s, relayConn := newNoDTLSTestStream(t)
	peer := fakeRelay(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.runNoDTLS(ctx, relayConn, peer) }()

	select {
	case err := <-done:
		if !errors.Is(err, errDataPlaneHandshake) {
			t.Fatalf("a silent relay returned %v, not a data-plane handshake failure", err)
		}
		if s.ready.Load() {
			t.Fatal("a stream over a silent relay was offered to the dispatcher")
		}
	case <-time.After(relayProofTimeout + 5*time.Second):
		t.Fatal("a silent relay never failed the stream")
	}
}

// The proof is also what vouches for the uplink when a sibling on another server
// fails its own handshake in the same window (see noteServerHandshakeFailure).
func TestNoDTLSRecordsTheHandshakeAgainstItsServer(t *testing.T) {
	defer resetServerHealth()
	resetServerHealth()

	s, relayConn := newNoDTLSTestStream(t)
	answer := make(chan struct{})
	close(answer)
	peer := fakeRelay(t, answer)

	attemptStart := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { s.runNoDTLS(ctx, relayConn, peer) }()

	deadline := time.Now().Add(relayProofTimeout)
	for !s.ready.Load() {
		if time.Now().After(deadline) {
			t.Fatal("an answering relay never made the stream ready")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !siblingProvedAnotherServer(healthTestPeerAddr, attemptStart, time.Now()) {
		t.Fatalf("a completed handshake left no proof against %s", healthTestAddr)
	}
}

// The wireguard peer type runs WRAP-obfuscated, and only a packet that unwraps
// counts as proof there. That branch has its own accounting, so it gets its own
// test: an echo the key cannot open must not make the stream ready.
func TestNoDTLSTakesProofOnlyFromPacketsThatUnwrap(t *testing.T) {
	defer resetServerHealth()
	resetServerHealth()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	s, relayConn := newNoDTLSTestStream(t)
	s.wrapKey = key
	s.wrapTx = newWrapTxState()

	answer := make(chan struct{})
	close(answer)
	wrongKey := make([]byte, 32)
	peer := fakeWrapRelay(t, answer, wrongKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.runNoDTLS(ctx, relayConn, peer) }()

	select {
	case err := <-done:
		if !errors.Is(err, errDataPlaneHandshake) {
			t.Fatalf("a relay talking another key returned %v", err)
		}
	case <-time.After(relayProofTimeout + 5*time.Second):
		t.Fatal("a relay talking another key never failed the stream")
	}
	if s.ready.Load() {
		t.Fatal("the stream went ready on packets it could not unwrap")
	}
}

// ...and the matching positive case: a relay speaking the same key proves the
// path exactly as a plain one does.
func TestNoDTLSTakesProofFromAWrappedEcho(t *testing.T) {
	defer resetServerHealth()
	resetServerHealth()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	s, relayConn := newNoDTLSTestStream(t)
	s.wrapKey = key
	s.wrapTx = newWrapTxState()

	answer := make(chan struct{})
	close(answer)
	peer := fakeWrapRelay(t, answer, key)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { s.runNoDTLS(ctx, relayConn, peer) }()

	deadline := time.Now().Add(relayProofTimeout)
	for !s.ready.Load() {
		if time.Now().After(deadline) {
			t.Fatal("a wrapped echo never made the stream ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
