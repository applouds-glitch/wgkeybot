/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// watchHarness drives a relaySocketWatch with staged samples and a clock of its
// own, and keeps the lines it printed.
type watchHarness struct {
	w       *relaySocketWatch
	mu      sync.Mutex
	samples map[*net.TCPConn]relaySocketSample
	lines   []string
	now     time.Time
	streams []*stream
}

func newWatchHarness() *watchHarness {
	h := &watchHarness{
		w:       newRelaySocketWatch(),
		samples: map[*net.TCPConn]relaySocketSample{},
		now:     time.Unix(1_800_000_000, 0),
	}
	h.w.sample = func(c *net.TCPConn) (relaySocketSample, bool) {
		h.mu.Lock()
		defer h.mu.Unlock()
		s, ok := h.samples[c]
		return s, ok
	}
	h.w.logf = func(format string, args ...interface{}) {
		h.lines = append(h.lines, fmt.Sprintf(format, args...))
	}
	return h
}

// socket registers a fake connection for a stream.
func (h *watchHarness) socket(stream int, relay string) *net.TCPConn {
	c := &net.TCPConn{}
	h.w.register(stream, relay, c)
	h.set(c, relaySocketSample{})
	return c
}

func (h *watchHarness) set(c *net.TCPConn, s relaySocketSample) {
	h.mu.Lock()
	h.samples[c] = s
	h.mu.Unlock()
}

// tick advances the clock one sample interval and observes.
func (h *watchHarness) tick() {
	h.now = h.now.Add(relaySocketSampleInterval)
	h.w.observe(h.streams, h.now)
}

func (h *watchHarness) ticks(n int) {
	for i := 0; i < n; i++ {
		h.tick()
	}
}

func (h *watchHarness) only(t *testing.T) string {
	t.Helper()
	if len(h.lines) != 1 {
		t.Fatalf("printed %d line(s), want 1:\n%s", len(h.lines), strings.Join(h.lines, "\n"))
	}
	return h.lines[0]
}

func wantParts(t *testing.T, line string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(line, p) {
			t.Fatalf("line lacks %q:\n%s", p, line)
		}
	}
}

// A tunnel that carries keepalives and nothing else says nothing: a line every
// ten seconds for as long as the VPN is up would push the lines that matter out
// of the kept log.
func TestIdleRelaySocketsPrintNothing(t *testing.T) {
	h := newWatchHarness()
	a, b := h.socket(0, "relay-a"), h.socket(1, "relay-a")

	for i := 1; i <= 35; i++ {
		// A keepalive and its echo now and then: a couple of kilobytes a window.
		h.set(a, relaySocketSample{acked: uint64(i * 100), received: uint64(i * 100), rtt: 120 * time.Millisecond})
		h.set(b, relaySocketSample{acked: uint64(i * 100), received: uint64(i * 100), rtt: 130 * time.Millisecond})
		h.tick()
	}
	if len(h.lines) != 0 {
		t.Fatalf("an idle tunnel printed:\n%s", strings.Join(h.lines, "\n"))
	}
}

// The summary of a window with traffic: what each socket moved is added up from
// its own counters, and the peaks name the stream they were seen on.
func TestRelaySocketSummaryAddsUpTheWindow(t *testing.T) {
	h := newWatchHarness()
	a, b := h.socket(3, "relay-a"), h.socket(7, "relay-b")
	queued := &stream{id: 7, in: make(chan []byte, 512)}
	h.streams = []*stream{{id: 3, in: make(chan []byte, 512)}, queued}
	for i := 0; i < 38; i++ {
		queued.in <- nil
	}

	// First sample: the connections' life so far (their Allocate) counts too —
	// a new socket counts from zero.
	h.set(a, relaySocketSample{acked: 1024, received: 1024, segsOut: 4, rtt: 95 * time.Millisecond})
	h.set(b, relaySocketSample{acked: 1024, received: 1024, segsOut: 4, rtt: 420 * time.Millisecond})
	h.tick()
	for len(queued.in) > 0 {
		<-queued.in
	}
	h.set(a, relaySocketSample{
		acked: 1024 + 600<<10, received: 1024 + 4000<<10, segsOut: 504, retrans: 10,
		backlog: 310 << 10, rtt: 95 * time.Millisecond,
		busy: 4 * time.Second, waitedOnPeerWindow: time.Second, waitedOnSendBuffer: 0,
	})
	h.set(b, relaySocketSample{
		acked: 1024 + 400<<10, received: 1024 + 2000<<10, segsOut: 504, retrans: 10,
		backlog: 20 << 10, rtt: 420 * time.Millisecond,
		busy: 4 * time.Second, waitedOnPeerWindow: time.Second,
	})
	h.ticks(10) // the first window closes ten seconds after its first sample

	wantParts(t, h.only(t),
		"[TCP] last 10s over 2 socket(s)",
		"up 1002 KB, down 6002 KB",
		"20 of 1008 segments retransmitted (2.0%)",
		"rtt 95ms-420ms, median 420ms",
		"socket backlog peaked at 310 KB (stream 3)",
		"stream queue at 38/512 (stream 7)",
		"25% waited on the relay's window and 0% on our send buffer",
	)

	// The next window starts from these counters, not from zero again.
	h.ticks(10)
	if len(h.lines) != 1 {
		t.Fatalf("a window in which nothing moved printed:\n%s", h.lines[len(h.lines)-1])
	}
}

// A stall is a connection whose head segment keeps timing out with nothing
// acknowledged. It gets a line of its own when it ends; a single timeout that is
// over by the next sample is ordinary loss recovery and gets none.
func TestRelaySocketStallIsReportedWhenItEnds(t *testing.T) {
	h := newWatchHarness()
	c := h.socket(4, "193.203.43.23:19302")

	h.set(c, relaySocketSample{timeouts: 1, backlog: 8 << 10})
	h.tick()
	h.set(c, relaySocketSample{})
	h.tick()
	if len(h.lines) != 0 {
		t.Fatalf("one timeout, recovered within a sample, printed:\n%s", strings.Join(h.lines, "\n"))
	}

	for i := 1; i <= 6; i++ {
		h.set(c, relaySocketSample{timeouts: i, backlog: i * 14 << 10})
		h.tick()
	}
	if len(h.lines) != 0 {
		t.Fatalf("a stall still in progress printed a line of its own:\n%s", strings.Join(h.lines, "\n"))
	}
	h.set(c, relaySocketSample{})
	h.tick()

	wantParts(t, h.lines[0],
		"[TCP] stream 4 (193.203.43.23:19302) stalled for ~6s",
		"6 retransmission timeout(s) in a row unanswered",
		"up to 84 KB waiting in the socket",
		"moving again",
	)

	// And the window it ended in says so even though no traffic to speak of moved.
	h.ticks(10)
	wantParts(t, h.lines[len(h.lines)-1], "1 stall(s) ended, longest 6s")
}

// A closed receive window is probed, not retransmitted into, and the line says
// which it was: the relay not reading is a different finding from a silent path.
func TestRelaySocketStallOnAClosedWindowSaysSo(t *testing.T) {
	h := newWatchHarness()
	c := h.socket(2, "relay-a")
	for i := 1; i <= 3; i++ {
		h.set(c, relaySocketSample{timeouts: i, probing: true, backlog: 40 << 10})
		h.tick()
	}
	h.set(c, relaySocketSample{})
	h.tick()
	wantParts(t, h.only(t), "the relay's receive window closed, 3 window probe(s) unanswered")
}

// The stall that matters most is the one that never ends. While it lasts the
// summaries list it; when the session is torn down under it, it is reported as
// what it was.
func TestRelaySocketStallThatNeverEndsIsNotLost(t *testing.T) {
	h := newWatchHarness()
	c := h.socket(9, "relay-a")
	for i := 1; i <= 12; i++ {
		h.set(c, relaySocketSample{timeouts: i, backlog: 100 << 10})
		h.tick()
	}
	wantParts(t, h.only(t), "stalled now: stream 9 for 10s")

	h.now = h.now.Add(30 * time.Second)
	h.w.unregister(9, c, h.now)
	wantParts(t, h.lines[len(h.lines)-1],
		"stream 9 (relay-a) stalled for ~41s",
		"had not moved again when the session ended",
	)
	if h.w.count() != 0 {
		t.Fatalf("%d socket(s) still watched after the session ended", h.w.count())
	}
}

// A stream that reconnects brings a new socket whose counters start over. It is
// counted from zero — not as a negative delta, and not as the old socket's
// total all over again.
func TestReconnectedStreamCountsItsNewSocketFromZero(t *testing.T) {
	h := newWatchHarness()
	old := h.socket(1, "relay-a")
	h.set(old, relaySocketSample{acked: 900 << 10})
	h.ticks(11)
	wantParts(t, h.only(t), "up 900 KB")

	h.w.unregister(1, old, h.now)
	fresh := h.socket(1, "relay-b")
	h.set(fresh, relaySocketSample{acked: 100 << 10})
	h.ticks(10)
	wantParts(t, h.lines[len(h.lines)-1], "up 100 KB")

	// A stale unregister — the old session's defer running late — must not take
	// the new socket with it.
	h.w.unregister(1, old, h.now)
	if h.w.count() != 1 {
		t.Fatalf("the old session's unregister removed the stream's new socket")
	}
}

// Past the budget a stall is still counted, just not given a line.
func TestRelaySocketStallLinesAreBudgeted(t *testing.T) {
	h := newWatchHarness()
	c := h.socket(0, "relay-a")
	for n := 0; n < relayStallLogBudget+5; n++ {
		for i := 1; i <= 3; i++ {
			h.set(c, relaySocketSample{timeouts: i})
			h.tick()
		}
		h.set(c, relaySocketSample{})
		h.tick()
	}
	stalls, notice := 0, 0
	for _, l := range h.lines {
		switch {
		case strings.Contains(l, "stalled for ~"):
			stalls++
		case strings.Contains(l, "only counted in the summaries"):
			notice++
		}
	}
	if stalls != relayStallLogBudget || notice != 1 {
		t.Fatalf("%d stall lines and %d budget notice(s), want %d and 1", stalls, notice, relayStallLogBudget)
	}

	// One more, of a length no earlier one had, in a window of its own.
	h.ticks(11)
	for i := 1; i <= 5; i++ {
		h.set(c, relaySocketSample{timeouts: i})
		h.tick()
	}
	h.set(c, relaySocketSample{})
	h.ticks(11)
	wantParts(t, h.lines[len(h.lines)-1], "1 stall(s) ended, longest 5s")
}

// The platform sampler against a real connection: the counters the summary is
// built from have to be the kernel's, not zeros that happen to parse.
func TestReadRelaySocketReadsTheKernelCounters(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("TCP_INFO is read on Linux only")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Less comes back than went out, so that the two directions cannot be
		// mistaken for one another.
		if _, err := io.ReadFull(c, make([]byte, 20<<10)); err == nil {
			c.Write(make([]byte, 5<<10))
		}
		io.Copy(io.Discard, c)
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	const sent, echoed = 20 << 10, 5 << 10
	if _, err := c.Write(make([]byte, sent)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, echoed)); err != nil {
		t.Fatal(err)
	}

	s, ok := readRelaySocket(c.(*net.TCPConn))
	if !ok {
		t.Fatal("the socket could not be sampled")
	}
	if s.acked < sent || s.received < echoed || s.received >= sent || s.segsOut == 0 || s.rtt <= 0 || s.timeouts != 0 {
		t.Fatalf("after %d bytes out and %d back: %+v", sent, echoed, s)
	}
	if tc := relayTCPConn(&splitFirstWriteConn{Conn: c}); tc != c.(*net.TCPConn) {
		t.Fatal("the TCP connection under a relay conn was not found")
	}
}

// The watcher costs nothing while no stream is on TCP — which is every session
// but the ones on the networks TCP exists for — and starts on its own when the
// first one is.
func TestRelaySocketWatcherSleepsUntilAStreamIsOnTCP(t *testing.T) {
	h := newWatchHarness()
	var sampled atomic.Int32
	h.w.sample = func(*net.TCPConn) (relaySocketSample, bool) {
		sampled.Add(1)
		return relaySocketSample{}, true
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.w.run(ctx, nil)
	}()

	time.Sleep(relaySocketSampleInterval + 300*time.Millisecond)
	if n := sampled.Load(); n != 0 {
		t.Fatalf("sampled %d time(s) with nothing to watch", n)
	}
	h.w.register(0, "relay-a", &net.TCPConn{})
	waitFor(t, "the watcher to start sampling", 3*relaySocketSampleInterval, func() bool { return sampled.Load() > 0 })

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher outlived its context")
	}
}

// The wiring: a session over TCP is watched from the moment it runs until it is
// torn down, and a session over UDP never is.
func TestOnlyTCPSessionsAreWatched(t *testing.T) {
	if n := relaySockets.count(); n != 0 {
		t.Fatalf("%d socket(s) watched before any session ran", n)
	}

	udp := startTestRelay(t, listenFakeRelay(t), 0)
	h := runWorkersAgainst(t, 117, 1, []string{udp.addr})
	waitFor(t, "a stream over UDP", 5*time.Second, func() bool { return h.ready() == 1 })
	if n := relaySockets.count(); n != 0 {
		t.Fatalf("a UDP session put %d socket(s) under watch", n)
	}
	h.cancel()
	h.done.Wait()

	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	h = runWorkersAgainst(t, 118, 1, []string{relay.addr})
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	if n := relaySockets.count(); n != 1 {
		t.Fatalf("%d socket(s) watched with one session over TCP, want 1", n)
	}
	h.cancel()
	h.done.Wait()
	if n := relaySockets.count(); n != 0 {
		t.Fatalf("%d socket(s) still watched after the session was torn down", n)
	}
}

// A run that is leaving must not take its successor's wake-up with it: the next
// session's only stream over TCP would then go unwatched for as long as it
// stayed up.
func TestLeavingWatcherLeavesTheWakeUpBehind(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Which of the two ready cases a select takes is random: enough rounds that
	// the unlucky one is certain to come up.
	for i := 0; i < 64; i++ {
		h := newWatchHarness()
		h.w.register(0, "relay-a", &net.TCPConn{})
		h.w.run(ctx, nil)
		if len(h.w.arrived) != 1 {
			t.Fatalf("round %d: the stopped watcher left no wake-up for the next one", i)
		}
	}
}
