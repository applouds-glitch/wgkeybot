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

// socket registers a fake connection for a stream: the one of h.streams with
// that id, or a bare one.
func (h *watchHarness) socket(id int, relay string) *net.TCPConn {
	st := &stream{id: id}
	for _, s := range h.streams {
		if s.id == id {
			st = s
		}
	}
	c := &net.TCPConn{}
	h.w.register(st, relay, c)
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
	h.w.unregister(c, h.now)
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

	h.w.unregister(old, h.now)
	fresh := h.socket(1, "relay-b")
	h.set(fresh, relaySocketSample{acked: 100 << 10})
	h.ticks(10)
	wantParts(t, h.lines[len(h.lines)-1], "up 100 KB")

	// A stale unregister — the old session's defer running late — must not take
	// the new socket with it.
	h.w.unregister(old, h.now)
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
	h.w.register(&stream{}, "relay-a", &net.TCPConn{})
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
		h.w.register(&stream{}, "relay-a", &net.TCPConn{})
		h.w.run(ctx, nil)
		if len(h.w.arrived) != 1 {
			t.Fatalf("round %d: the stopped watcher left no wake-up for the next one", i)
		}
	}
}

// newShrinkHarness is a watchHarness with ready streams of these ids, whose
// replacements are recorded instead of ending sessions.
func newShrinkHarness(ids ...int) (*watchHarness, *[]int) {
	h := newWatchHarness()
	replaced := &[]int{}
	h.w.replace = func(s *watchedRelaySocket) bool {
		*replaced = append(*replaced, s.stream)
		return true
	}
	for _, id := range ids {
		st := &stream{id: id}
		st.ready.Store(true)
		h.streams = append(h.streams, st)
	}
	return h, replaced
}

// redialLines are the lines that announced a replacement.
func (h *watchHarness) redialLines() []string {
	var out []string
	for _, l := range h.lines {
		if strings.Contains(l, "redialing") {
			out = append(out, l)
		}
	}
	return out
}

// calmTicks is how many samples a socket has to be quiet for to count as calm.
var calmTicks = int(relayShrunkCalm / relaySocketSampleInterval)

// The 17.10 field log: a stall all sockets lived through left them at 512, 256,
// 128 and 64 bytes a segment where they began with 1228, and there they stayed.
// A connection cut to half its size or less is redialed — once the path has
// been calm long enough that the redial is not a dial into the same stall.
func TestShrunkRelaySocketIsReplacedOnceThePathIsCalm(t *testing.T) {
	h, replaced := newShrinkHarness(0, 1)
	cut := h.socket(0, "95.163.34.168:19302")
	other := h.socket(1, "90.156.234.252:19302")
	h.set(cut, relaySocketSample{sndMSS: 1228})
	h.set(other, relaySocketSample{sndMSS: 1228})
	h.tick()

	// A stall: the head segment keeps timing out and the kernel halves the
	// segments at each timeout.
	for i, mss := range []int{1024, 512, 256, 128} {
		h.set(cut, relaySocketSample{timeouts: i + 1, sndMSS: mss})
		h.tick()
	}
	h.set(cut, relaySocketSample{sndMSS: 128})
	h.ticks(calmTicks - 1)
	if len(*replaced) != 0 {
		t.Fatalf("replaced %v before the path had been calm for %v", *replaced, relayShrunkCalm)
	}
	h.tick()
	if len(*replaced) != 1 || (*replaced)[0] != 0 {
		t.Fatalf("replaced %v, want stream 0", *replaced)
	}
	lines := h.redialLines()
	if len(lines) != 1 {
		t.Fatalf("%d replacement line(s):\n%s", len(lines), strings.Join(h.lines, "\n"))
	}
	wantParts(t, lines[0], "[TCP] stream 0 (95.163.34.168:19302): the kernel cut its segments to 128 bytes from 1228")

	// Its session is on its way out: until it has let go of the socket, the
	// socket is not picked again.
	h.ticks(3 * int(relayShrunkGap/relaySocketSampleInterval))
	if len(*replaced) != 1 {
		t.Fatalf("the socket already being replaced was replaced again: %v", *replaced)
	}
}

// The first cut, to tcp_base_mss, still carries a tunnel packet in two
// segments, as the full size does: not worth a reconnect.
func TestRelaySocketAtTheFirstCutIsKept(t *testing.T) {
	h, replaced := newShrinkHarness(0, 1)
	c := h.socket(0, "relay-a")
	h.set(c, relaySocketSample{sndMSS: 1228})
	h.tick()
	h.set(c, relaySocketSample{timeouts: 3, sndMSS: 1024})
	h.tick()
	h.set(c, relaySocketSample{sndMSS: 1024})
	h.ticks(10 * calmTicks)
	if len(*replaced) != 0 {
		t.Fatalf("a socket cut only to 1024 from 1228 was replaced: %v", *replaced)
	}
}

// One stall cuts every socket that lived through it. They are replaced one at
// a time, the most cut first, relayShrunkGap apart — not all at once, which
// would take the tunnel down for the length of a reconnect.
func TestShrunkRelaySocketsAreReplacedOneAtATime(t *testing.T) {
	h, replaced := newShrinkHarness(0, 1, 2, 3)
	cutTo := map[int]int{0: 256, 1: 64, 2: 512, 3: 1228}
	socks := map[int]*net.TCPConn{}
	for id := 0; id <= 3; id++ {
		socks[id] = h.socket(id, "relay-a")
		h.set(socks[id], relaySocketSample{sndMSS: 1228})
	}
	h.tick()
	for id, c := range socks {
		h.set(c, relaySocketSample{timeouts: 4, sndMSS: cutTo[id]})
	}
	h.tick()
	for id, c := range socks {
		h.set(c, relaySocketSample{sndMSS: cutTo[id]})
	}

	var at []time.Time
	for i := 0; i < 6*calmTicks; i++ {
		n := len(*replaced)
		h.tick()
		if len(*replaced) > n {
			at = append(at, h.now)
		}
	}
	if want := []int{1, 0, 2}; fmt.Sprint(*replaced) != fmt.Sprint(want) {
		t.Fatalf("replaced %v, want %v: the most cut first, the uncut one never", *replaced, want)
	}
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap != relayShrunkGap {
			t.Fatalf("replacements %d and %d came %v apart, want %v", i-1, i, gap, relayShrunkGap)
		}
	}
}

// A replacement is planned, so it waits for another stream to carry the
// traffic meanwhile: not while the only other stream is reconnecting, nor
// while its socket is stalled.
func TestShrunkRelaySocketWaitsForASiblingThatCarries(t *testing.T) {
	h, replaced := newShrinkHarness(0, 1)
	sibling := h.streams[1]
	sibling.ready.Store(false)
	c := h.socket(0, "relay-a")
	h.set(c, relaySocketSample{sndMSS: 1228})
	h.tick()
	h.set(c, relaySocketSample{timeouts: 5, sndMSS: 64})
	h.tick()
	h.set(c, relaySocketSample{sndMSS: 64})
	h.ticks(2 * calmTicks)
	if len(*replaced) != 0 {
		t.Fatalf("replaced %v with no other stream ready", *replaced)
	}

	sibling.ready.Store(true)
	sibling.sendStalled.Store(true)
	h.ticks(2)
	if len(*replaced) != 0 {
		t.Fatalf("replaced %v with the only other stream stalled", *replaced)
	}

	sibling.sendStalled.Store(false)
	h.tick()
	if len(*replaced) != 1 {
		t.Fatalf("replaced %v once a sibling carried, want stream 0", *replaced)
	}
}

// A path that keeps stalling is never calm long enough: the socket is left
// alone, and the kernel's 30s limit or the dead-stream detector deal with it.
func TestShrunkRelaySocketOnAPathThatKeepsStallingIsKept(t *testing.T) {
	h, replaced := newShrinkHarness(0, 1)
	c := h.socket(0, "relay-a")
	h.set(c, relaySocketSample{sndMSS: 1228})
	h.tick()
	for i := 0; i < 8*calmTicks; i++ {
		s := relaySocketSample{sndMSS: 128}
		if i%(calmTicks-2) == 0 {
			s.timeouts = 3
		}
		h.set(c, s)
		h.tick()
	}
	if len(*replaced) != 0 {
		t.Fatalf("replaced %v on a path that stalled every %d samples", *replaced, calmTicks-2)
	}
}

// A session that could not be ended (its attempt already over) costs no
// spacing and no line: the next sample tries again.
func TestFailedReplacementIsNotBooked(t *testing.T) {
	h, replaced := newShrinkHarness(0, 1)
	refuse := true
	h.w.replace = func(s *watchedRelaySocket) bool {
		if refuse {
			refuse = false
			return false
		}
		*replaced = append(*replaced, s.stream)
		return true
	}
	c := h.socket(0, "relay-a")
	h.set(c, relaySocketSample{sndMSS: 1228})
	h.tick()
	h.set(c, relaySocketSample{timeouts: 4, sndMSS: 256})
	h.tick()
	h.set(c, relaySocketSample{sndMSS: 256})
	h.ticks(calmTicks)
	if len(*replaced) != 0 || len(h.redialLines()) != 0 {
		t.Fatalf("a refused replacement was booked: %v\n%s", *replaced, strings.Join(h.lines, "\n"))
	}
	h.tick()
	if len(*replaced) != 1 || len(h.redialLines()) != 1 {
		t.Fatalf("the next sample did not replace it: %v\n%s", *replaced, strings.Join(h.lines, "\n"))
	}
}

// The replacement ends the attempt the way a network move does, so its worker
// reconnects at once and counts no failure.
func TestReplaceSocketSessionRecyclesItsAttempt(t *testing.T) {
	if replaceSocketSession(&watchedRelaySocket{}) {
		t.Fatalf("a socket registered with no attempt reported its session ended")
	}
	h := beginAttempt(context.Background(), WorkerGroupConfig{})
	defer h.end()
	if !replaceSocketSession(&watchedRelaySocket{attempt: h.a}) {
		t.Fatalf("the attempt was not recycled")
	}
	select {
	case <-h.ctx.Done():
	default:
		t.Fatalf("the attempt's context is still live")
	}
	if !h.moved() {
		t.Fatalf("the attempt was not marked moved: its worker would count a failure and back off")
	}
}

// Codex review, 18.10: the attempt ended is the one whose session registered
// the socket, not whatever the stream runs by the time the replacement comes.
// The stream's attempt can already be the next one — the session ended and its
// worker began again, or sits in the wait after it — and recycling that would
// cut the wait short or kill a healthy new session.
func TestShrunkReplacementEndsTheAttemptThatOwnsTheSocket(t *testing.T) {
	owner := beginAttempt(context.Background(), WorkerGroupConfig{})
	defer owner.end()
	next := beginAttempt(context.Background(), WorkerGroupConfig{})
	defer next.end()

	h := newWatchHarness()
	h.w.replace = replaceSocketSession
	cut, sibling := &stream{id: 0}, &stream{id: 1}
	cut.ready.Store(true)
	sibling.ready.Store(true)
	h.streams = []*stream{cut, sibling}
	cut.attempt.Store(owner.a)
	c := h.socket(0, "relay-a")
	cut.attempt.Store(next.a) // the stream has moved on; the socket's session has not let go yet

	h.set(c, relaySocketSample{sndMSS: 1228})
	h.tick()
	h.set(c, relaySocketSample{timeouts: 4, sndMSS: 128})
	h.tick()
	h.set(c, relaySocketSample{sndMSS: 128})
	h.ticks(calmTicks)

	if !owner.moved() {
		t.Fatalf("the attempt that owns the cut socket was not recycled")
	}
	if next.moved() {
		t.Fatalf("the stream's next attempt was recycled for a socket it never had")
	}
}

// End to end over a real TURN server on TCP, with only the kernel's view of the
// sockets made up: the replacement ends the session of the stream it names and
// no other, releases its allocation, and the worker dials a new connection at
// once — no failure, no backoff — and is back up on it.
func TestShrunkRelaySocketIsRedialedEndToEnd(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	h := runWorkersAgainst(t, 119, 2, []string{relay.addr})
	waitFor(t, "two streams over TCP", 5*time.Second, func() bool { return h.ready() == 2 })
	accepted := relay.ln.accepted.Load()

	socketsOf := func(id int) []*net.TCPConn {
		relaySockets.mu.Lock()
		defer relaySockets.mu.Unlock()
		var out []*net.TCPConn
		for c, s := range relaySockets.socks {
			if s.stream == id {
				out = append(out, c)
			}
		}
		return out
	}
	cut, sibling := socketsOf(0), socketsOf(1)
	if len(cut) != 1 || len(sibling) != 1 {
		t.Fatalf("watched sockets: stream 0 has %d, stream 1 has %d, want one each", len(cut), len(sibling))
	}

	var shrunk atomic.Bool
	var mu sync.Mutex
	var lines []string
	prevSample, prevLog := relaySockets.sample, relaySockets.logf
	relaySockets.mu.Lock()
	relaySockets.lastReplaced = time.Time{}
	relaySockets.sample = func(c *net.TCPConn) (relaySocketSample, bool) {
		if c == cut[0] && shrunk.Load() {
			return relaySocketSample{sndMSS: 64}, true
		}
		return relaySocketSample{sndMSS: 1228}, true
	}
	relaySockets.logf = func(format string, args ...interface{}) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	relaySockets.mu.Unlock()
	t.Cleanup(func() {
		relaySockets.mu.Lock()
		relaySockets.sample, relaySockets.logf = prevSample, prevLog
		relaySockets.lastReplaced = time.Time{}
		relaySockets.mu.Unlock()
	})

	now := time.Now()
	relaySockets.observe(h.streams, now)
	shrunk.Store(true)
	relaySockets.observe(h.streams, now.Add(time.Second))
	if got := relay.ln.accepted.Load(); got != accepted {
		t.Fatalf("a socket that had not been calm for %v was redialed", relayShrunkCalm)
	}
	replacedAt := time.Now()
	relaySockets.observe(h.streams, now.Add(relayShrunkCalm+time.Second))

	waitFor(t, "stream 0 on a new connection", 5*time.Second, func() bool {
		s := socketsOf(0)
		return len(s) == 1 && s[0] != cut[0] && h.streams[0].ready.Load()
	})
	if took := time.Since(replacedAt); took > 3*time.Second {
		t.Fatalf("the redial took %v: the worker waited out a backoff", took)
	}
	if got := relay.ln.accepted.Load(); got != accepted+1 {
		t.Fatalf("the relay took %d new connection(s), want 1: only the cut stream redials", got-accepted)
	}
	if s := socketsOf(1); len(s) != 1 || s[0] != sibling[0] {
		t.Fatalf("the sibling's connection was replaced too")
	}
	allocationBook.Lock()
	key := relayIdentity{user: t.Name(), relay: relay.addr}
	orphans, releasedAt := len(allocationBook.orphanedTill), allocationBook.releasedAt[key]
	allocationBook.Unlock()
	if orphans != 0 || releasedAt.Before(replacedAt) {
		t.Fatalf("the replaced session's allocation was not released: %d orphaned, last release at %v, replaced at %v", orphans, releasedAt, replacedAt)
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, l := range lines {
		if strings.Contains(l, "stream 0") && strings.Contains(l, "cut its segments to 64 bytes from 1228") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no line said why stream 0 was redialed:\n%s", strings.Join(lines, "\n"))
	}
}
