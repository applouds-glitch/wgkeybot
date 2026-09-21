/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// queuedStream is a test stream with both queues at their production sizes.
func queuedStream(t *testing.T) *stream {
	t.Helper()
	s, _ := newNoDTLSTestStream(t)
	s.in = make(chan []byte, 512)
	s.priority = make(chan []byte, tcpPriorityQueueSize)
	return s
}

func pooled(payload string) []byte {
	b := packetPool.Get().([]byte)[:len(payload)]
	copy(b, payload)
	return b
}

func TestDrainOutboundEmptiesBothQueues(t *testing.T) {
	s := queuedStream(t)
	for i := 0; i < cap(s.in); i++ {
		s.in <- pooled("old data")
	}
	for i := 0; i < cap(s.priority); i++ {
		s.priority <- pooled("old ack")
	}
	if got, want := s.drainOutbound(), cap(s.in)+cap(s.priority); got != want {
		t.Fatalf("dropped %d packets, want all %d", got, want)
	}
	if len(s.in) != 0 || len(s.priority) != 0 {
		t.Fatalf("left %d + %d packets queued", len(s.in), len(s.priority))
	}
	if got := s.drainOutbound(); got != 0 {
		t.Fatalf("a second drain dropped %d", got)
	}
	// The test streams of other files have no priority queue at all.
	if got := (&stream{in: make(chan []byte, 1)}).drainOutbound(); got != 0 {
		t.Fatalf("a stream without a priority queue dropped %d", got)
	}
}

// On the way out: what the dispatcher queued for a session that has ended does
// not wait for the next one.
func TestQueuesAreDrainedWhenAnAttemptEnds(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	s := queuedStream(t)
	s.in <- pooled("old data")
	s.priority <- pooled("old ack")
	s.ready.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	silent := listenFakeRelay(t)
	_ = s.runWithCreds(ctx, t.Name(), "pass", []string{silent.LocalAddr().String()},
		WorkerGroupConfig{GroupID: 132, Link: "test", UseUDP: true, PeerType: "wireguard", PeerAddr: fakeRelay(t, nil)})

	if s.ready.Load() {
		t.Fatal("the stream is still ready")
	}
	if n := len(s.in) + len(s.priority); n != 0 {
		t.Fatalf("%d packet(s) left queued for the next session", n)
	}
}

// recordingPeer answers the relay proof and keeps everything else it is sent.
type recordingPeer struct {
	mu   sync.Mutex
	seen [][]byte
}

func (p *recordingPeer) has(payload string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.seen {
		if bytes.Equal(b, []byte(payload)) {
			return true
		}
	}
	return false
}

func startRecordingPeer(t *testing.T) (*recordingPeer, *net.UDPAddr) {
	t.Helper()
	pc := listenFakeRelay(t)
	p := &recordingPeer{}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if isStunKeepalive(buf[:n]) {
				pc.WriteTo(buf[:n], from)
				continue
			}
			p.mu.Lock()
			p.seen = append(p.seen, append([]byte(nil), buf[:n]...))
			p.mu.Unlock()
		}
	}()
	return p, pc.LocalAddr().(*net.UDPAddr)
}

// On the way in: whatever reached the queues while the stream was reconnecting
// is gone before the new session's writer starts — which in runNoDTLS is before
// the relay proof, so "before ready" would be too late. The session then
// carries what is queued for it.
func TestNewSessionDoesNotSendWhatWasQueuedBeforeIt(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	relay := startTestRelay(t, listenFakeRelay(t), 0)
	peer, peerAddr := startRecordingPeer(t)
	cfg := WorkerGroupConfig{GroupID: 133, Link: "test", UseUDP: true, PeerType: "wireguard", PeerAddr: peerAddr}

	s := queuedStream(t)
	ctx, cancel := context.WithCancel(context.Background())
	client, raw, relayConn, rtt, perm, err := dialAndAllocate(ctx, s, t.Name(), "pass", relay.addr, cfg, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Queued while the stream was reconnecting.
	s.in <- pooled("old data, queued before this session")
	s.priority <- pooled("old ack, queued before this session")

	ended := make(chan struct{})
	go func() {
		defer close(ended)
		s.runSession(ctx, winner{client: client, raw: raw, relay: relayConn, addr: relay.addr, rtt: rtt, perm: perm}, cfg)
	}()
	defer func() {
		cancel()
		<-ended
	}()
	waitFor(t, "the stream", 5*time.Second, func() bool { return s.ready.Load() })

	s.in <- pooled("fresh data")
	waitFor(t, "the fresh packet at the peer", 3*time.Second, func() bool { return peer.has("fresh data") })
	for _, old := range []string{"old data, queued before this session", "old ack, queued before this session"} {
		if peer.has(old) {
			t.Fatalf("the new session sent %q", old)
		}
	}
}
