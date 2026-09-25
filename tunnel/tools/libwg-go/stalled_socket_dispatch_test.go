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
)

// stalledStream is a ready TCP stream that hears its relay, with the given
// sendStalled — the field case: the direction up dead, the one down alive.
func stalledStream(id int, stalled bool, now time.Time) *stream {
	s := dispatchStream(id, true, now, 8)
	s.priority = make(chan []byte, tcpPriorityQueueSize)
	s.overTCP.Store(true)
	s.sendStalled.Store(stalled)
	return s
}

// The point of it: a stream whose socket stopped taking what we send gets
// nothing while a sibling moves, although its relay is heard and its queue has
// room — neither of which the dispatcher used to look past.
func TestDispatchPassesOverAStalledSocket(t *testing.T) {
	now := time.Now()
	stuck, moving := stalledStream(0, true, now), stalledStream(1, false, now)
	streams := []*stream{stuck, moving}
	steered := dispatchSteeredCount.Load()

	for _, size := range []int{1200, 96} { // bulk, and a priority-sized packet
		if sent, anyReady := dispatchPacket(streams, 0, now, make([]byte, size)); !sent || !anyReady {
			t.Fatalf("%d bytes: sent=%v anyReady=%v", size, sent, anyReady)
		}
	}
	if n := len(stuck.in) + len(stuck.priority); n != 0 {
		t.Fatalf("the stalled stream was handed %d packet(s)", n)
	}
	if len(moving.in) != 1 || len(moving.priority) != 1 {
		t.Fatalf("the moving stream got %d bulk and %d small, want 1 and 1", len(moving.in), len(moving.priority))
	}
	if d := dispatchSteeredCount.Load() - steered; d != 2 {
		t.Fatalf("%d packet(s) counted as steered, want 2", d)
	}

	// A sibling taking the packet on its own turn is not steering: nothing
	// stalled was passed over.
	steered = dispatchSteeredCount.Load()
	dispatchPacket(streams, 1, now, make([]byte, 1200))
	if d := dispatchSteeredCount.Load() - steered; d != 0 {
		t.Fatalf("a packet on the rotation's own stream counted as steered (%d)", d)
	}
}

// With no other ready stream to take it there is nowhere better: the packet
// goes where the rotation points, as before, and is counted as such — not
// dropped.
func TestDispatchFallsBackIntoStalledSocketsWhenNoneMoves(t *testing.T) {
	now := time.Now()
	a, b := stalledStream(0, true, now), stalledStream(1, true, now)
	steered, into := dispatchSteeredCount.Load(), dispatchIntoStalledCount.Load()

	if sent, anyReady := dispatchPacket([]*stream{a, b}, 1, now, make([]byte, 1200)); !sent || !anyReady {
		t.Fatalf("sent=%v anyReady=%v, want true/true", sent, anyReady)
	}
	if len(b.in) != 1 || len(a.in) != 0 {
		t.Fatalf("start=1 must keep the rotation's own slot: a=%d b=%d", len(a.in), len(b.in))
	}
	if d := dispatchIntoStalledCount.Load() - into; d != 1 {
		t.Fatalf("%d packet(s) counted into stalled sockets, want 1", d)
	}
	if d := dispatchSteeredCount.Load() - steered; d != 0 {
		t.Fatalf("a fallback counted as steered (%d)", d)
	}

	// A stream the relay has gone quiet on but that still sends is the better
	// fallback: what is put there at least leaves the phone. The stalled one
	// is the rotation's slot and is passed over all the same.
	stale := stalledStream(2, false, now.Add(-2*dispatchStaleAfter))
	steered, into = dispatchSteeredCount.Load(), dispatchIntoStalledCount.Load()
	if sent, _ := dispatchPacket([]*stream{b, stale}, 0, now, make([]byte, 1200)); !sent {
		t.Fatal("dropped with a stale stream that could take it")
	}
	if len(stale.in) != 1 || len(b.in) != 1 {
		t.Fatalf("stale got %d, stalled has %d; want 1 and still 1", len(stale.in), len(b.in))
	}
	if dispatchSteeredCount.Load()-steered != 1 || dispatchIntoStalledCount.Load() != into {
		t.Fatal("a packet taken past the stalled socket to a stale one was not counted as steered")
	}
}

// The watcher sets the flag on the stream the socket belongs to at the second
// timeout in a row — the first is ordinary tail loss — and lets go of it the
// moment the socket moves again.
func TestWatcherMarksAStreamWhoseSocketStopped(t *testing.T) {
	h := newWatchHarness()
	s0, s1 := &stream{id: 0}, &stream{id: 1}
	h.streams = []*stream{s0, s1}
	c := h.socket(0, "relay-a")

	h.set(c, relaySocketSample{timeouts: 1, backlog: 2400})
	h.tick()
	if s0.sendStalled.Load() {
		t.Fatal("one timeout marked the stream")
	}
	h.set(c, relaySocketSample{timeouts: relayStallSkipTimeouts, backlog: 2400})
	h.tick()
	if !s0.sendStalled.Load() || s1.sendStalled.Load() {
		t.Fatalf("after %d timeouts: stream 0 %v, stream 1 %v; want true, false",
			relayStallSkipTimeouts, s0.sendStalled.Load(), s1.sendStalled.Load())
	}
	h.set(c, relaySocketSample{})
	h.tick()
	if s0.sendStalled.Load() {
		t.Fatal("the mark outlived the socket moving again")
	}

	// Unanswered probes count the same: a keepalive or window probe going
	// unanswered twice is a flow nothing gets through.
	h.set(c, relaySocketSample{timeouts: 2, probing: true})
	h.tick()
	if !s0.sendStalled.Load() {
		t.Fatal("two unanswered probes did not mark the stream")
	}
}

// The mark belongs to the session's socket: the session ending takes it away,
// and a late unregister of a replaced socket does not take the next one's.
func TestWatcherMarkEndsWithTheSession(t *testing.T) {
	h := newWatchHarness()
	s0 := &stream{id: 0}
	h.streams = []*stream{s0}

	old := h.socket(0, "relay-a")
	h.set(old, relaySocketSample{timeouts: 5})
	h.tick()
	h.w.unregister(old, h.now)
	if s0.sendStalled.Load() {
		t.Fatal("the next session would start out passed over")
	}

	cur := h.socket(0, "relay-b")
	h.set(cur, relaySocketSample{timeouts: 3})
	h.tick()
	h.w.unregister(old, h.now)
	if !s0.sendStalled.Load() {
		t.Fatal("unregistering a replaced socket cleared the current one's mark")
	}
}

// The mark goes to the stream whose session registered the socket, whichever
// run of the watcher samples it: a run leaving with its proxy can sample the
// next proxy's sockets, with the old proxy's streams in hand. Looking the
// stream up by id there once let the session's end clear the wrong stream and
// leave the live one passed over — for good, if its next session was on UDP.
func TestWatcherMarksTheStreamThatRegisteredTheSocket(t *testing.T) {
	h := newWatchHarness()
	gone, next := &stream{id: 0}, &stream{id: 0}

	h.streams = []*stream{next}
	c := h.socket(0, "relay-a")
	h.set(c, relaySocketSample{timeouts: 3})
	h.tick() // the next proxy's run
	h.streams = []*stream{gone}
	h.tick() // the leaving run, last to sample
	if !next.sendStalled.Load() || gone.sendStalled.Load() {
		t.Fatalf("next %v, gone %v; want the mark on the socket's own stream only",
			next.sendStalled.Load(), gone.sendStalled.Load())
	}
	h.w.unregister(c, h.now)
	if next.sendStalled.Load() {
		t.Fatal("the session's end left its stream passed over")
	}
}

// A worker of a stopped proxy that outlived the stop's drain can register a
// session under the id a stream of the next proxy is using. Both sockets stay
// watched, each marking and clearing its own stream: keyed by id, the late one
// evicted the live one, whose mark then outlived its session.
func TestLateSocketOfAStoppedProxyDoesNotEvictTheLiveOne(t *testing.T) {
	h := newWatchHarness()
	gone, live := &stream{id: 3}, &stream{id: 3}

	h.streams = []*stream{live}
	mine := h.socket(3, "relay-a")
	h.set(mine, relaySocketSample{timeouts: 3})
	h.tick()
	h.streams = []*stream{gone}
	late := h.socket(3, "relay-b")
	h.tick()
	if n := h.w.count(); n != 2 {
		t.Fatalf("%d socket(s) watched, want both", n)
	}

	h.w.unregister(late, h.now)
	h.set(mine, relaySocketSample{})
	h.tick()
	if live.sendStalled.Load() {
		t.Fatal("the live socket stopped being watched when the late one came and went")
	}
	h.set(mine, relaySocketSample{timeouts: 3})
	h.tick()
	h.w.unregister(mine, h.now)
	if live.sendStalled.Load() {
		t.Fatal("the live stream's mark outlived its session")
	}
}

// What the dispatcher did about stalled sockets reaches the summary, and is
// reason enough to print one on an otherwise quiet window.
func TestSummaryCountsPacketsSteeredPastStalledSockets(t *testing.T) {
	h := newWatchHarness()
	h.socket(0, "relay-a")
	h.tick() // the window opens at its first sample
	dispatchSteeredCount.Add(3)
	dispatchIntoStalledCount.Add(2)

	h.ticks(10)
	line := h.only(t)
	for _, want := range []string{"3 packet(s) steered past stalled sockets", "2 packet(s) into stalled sockets, no other ready stream could take them"} {
		if !strings.Contains(line, want) {
			t.Fatalf("no %q in %q", want, line)
		}
	}
}

// A report is something we send, too: it does not ride a stalled stream while
// another can carry it — and does when none other can. The mask is untouched:
// the stream is still heard, and whether the server should stop sending down
// it is not what its stalled upload says.
func TestFeedbackReportAvoidsAStalledCarrier(t *testing.T) {
	now := time.Now()
	stuck, moving := feedbackTestStream(0, now), feedbackTestStream(1, now)
	stuck.sendStalled.Store(true)
	var r downlinkReporter

	r.update([]*stream{stuck, moving}, now)
	_, mask := readFeedbackReport(t, moving)
	if len(stuck.in) != 0 {
		t.Fatal("a report was put on the stalled stream while another could carry it")
	}
	if !mask.contains(0) || !mask.contains(1) {
		t.Fatal("the stalled stream left the mask")
	}

	var alone downlinkReporter
	alone.update([]*stream{stuck}, now)
	readFeedbackReport(t, stuck)
}

// The wiring end to end: real workers, real TCP sessions, only the kernel's
// answer staged. The session's socket is found under the proxy's streams, the
// right stream is marked while the other stays in play, and tearing the
// sessions down leaves no mark behind for the next ones.
func TestStalledSocketMarksItsStreamThroughTheRunningWatcher(t *testing.T) {
	stuckRelay := startTCPTestRelay(t, listenTCPRelay(t))
	movingRelay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)

	prev := relaySockets
	relaySockets = newRelaySocketWatch()
	t.Cleanup(func() { relaySockets = prev })
	relaySockets.sample = func(c *net.TCPConn) (relaySocketSample, bool) {
		if c.RemoteAddr().String() == stuckRelay.addr {
			return relaySocketSample{timeouts: 4, backlog: 12 << 10}, true
		}
		return relaySocketSample{}, true
	}

	h := runWorkersAgainst(t, 122, 2, []string{stuckRelay.addr, movingRelay.addr})
	waitFor(t, "both streams over TCP", 5*time.Second, func() bool { return h.ready() == 2 })

	ctx, cancel := context.WithCancel(context.Background())
	var watching sync.WaitGroup
	watching.Add(1)
	go func() {
		defer watching.Done()
		relaySockets.run(ctx, h.streams)
	}()
	t.Cleanup(func() { cancel(); watching.Wait() })

	waitFor(t, "a stream marked stalled", 5*time.Second, func() bool {
		return h.streams[0].sendStalled.Load() || h.streams[1].sendStalled.Load()
	})
	if h.streams[0].sendStalled.Load() == h.streams[1].sendStalled.Load() {
		t.Fatal("both streams marked: the mark is not per socket")
	}

	h.cancel()
	h.done.Wait()
	for _, s := range h.streams {
		if s.sendStalled.Load() {
			t.Fatalf("stream %d still marked after its session ended", s.id)
		}
	}
}
