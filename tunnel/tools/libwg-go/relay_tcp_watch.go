/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// What the TCP connections to the relays are doing while they carry traffic.
//
// Over UDP the log needs nothing of the kind: a datagram is sent or it is not,
// and what is lost shows up as loss. Over TCP a write that returns has only been
// copied into the socket — it can sit there for seconds behind a segment the
// network is not acknowledging, and every line this client prints still reads
// "delivered". The first field log of the TCP path (19.09, Rostelecom) was that
// case exactly: all ten streams up, WireGuard rekeying on schedule, not one
// error — and the tester's report was "only text goes through in Telegram". The
// connect phase of the same log shows the network is capable of it (half of the
// flows to a relay hung for 1–8s while their neighbours to the same address took
// 200ms), but once the streams were up the log had nothing to say about them.
//
// So the sockets are asked directly. Once a second the kernel's own view of
// every relay connection is read (TCP_INFO; one getsockopt each, nothing on the
// packet path), and two things come out of it:
//
//   - a line per stall: a connection that went relayStallReportAfter or longer
//     with its head segment timing out and nothing acknowledged — how long, how
//     deep the timeouts went, how much was waiting behind it;
//   - a summary every relaySocketLogInterval in which traffic moved or something
//     stalled: bytes each way, retransmissions, the rtt spread across the pool,
//     the deepest socket backlog and stream queue, and how much of the sending
//     time went on waiting for the relay's window or for our own send buffer.
//
// An idle tunnel — keepalives and nothing else — stays silent. The watcher does
// not tick at all while no stream is on TCP.
//
// vk-turn-proxy-ios, whose default transport is TCP to these same relays, reads
// the same counters for the same reason (its sockstats.go); the measurements it
// made with them are why "the relay's window" is a column here.

const (
	relaySocketSampleInterval = time.Second
	relaySocketLogInterval    = 10 * time.Second

	// relayStallReportAfter separates a stall from ordinary loss recovery: a
	// single retransmission timeout is over within one sample on any path this
	// runs on; two seconds without an acknowledgement is already several in a
	// row, and is long enough for the TCP inside the tunnel to notice.
	relayStallReportAfter = 2 * time.Second

	// relayStallLogBudget caps the per-stall lines of one proxy session. On a
	// network that stalls flows by the minute they would crowd everything else
	// out of the log; past the budget the summaries still count every stall.
	relayStallLogBudget = 40

	// relayTrafficWorthALine is the traffic below which a window prints no
	// summary: ten streams' keepalives and echoes are a few kilobytes.
	relayTrafficWorthALine = 64 << 10
)

// relaySocketSample is one look at a relay connection. The counters are
// cumulative since the connection opened; a kernel that does not keep one
// leaves it zero.
type relaySocketSample struct {
	acked    uint64 // bytes the relay has acknowledged
	received uint64 // bytes received from the relay
	segsOut  uint64 // data segments sent
	retrans  uint64 // segments retransmitted

	// backlog is what the socket holds unacknowledged: in flight plus not yet
	// sent. In flight is counted in whole segments, so it is an upper bound.
	backlog int

	// timeouts is how many times in a row the segment at the head has timed out
	// unanswered; zero while the connection is moving. probing says the count is
	// of window probes: the relay's receive window is closed, rather than the
	// path silent.
	timeouts int
	probing  bool

	rtt time.Duration

	// How the time with data to send was spent, per the kernel's own accounting.
	busy, waitedOnPeerWindow, waitedOnSendBuffer time.Duration
}

type watchedRelaySocket struct {
	stream int
	relay  string
	conn   *net.TCPConn

	last relaySocketSample // zero until first sampled: a new socket counts from zero

	stalledSince  time.Time // zero while moving
	stallTimeouts int
	stallBacklog  int
	stallProbing  bool
}

// relaySocketWindow is what accumulates between two summaries.
type relaySocketWindow struct {
	start                   time.Time
	up, down                uint64
	segsOut, retrans        uint64
	busy, peerWindow, sndBf time.Duration
	backlogPeak             int
	backlogStream           int
	queuePeak, queueCap     int
	queueStream             int
	stallsEnded             int
	longestStall            time.Duration
	drops                   uint64
}

type relaySocketWatch struct {
	mu    sync.Mutex
	socks map[int]*watchedRelaySocket
	// arrived wakes the watcher when the first socket registers.
	arrived chan struct{}

	window     relaySocketWindow
	stallLines int
	lastDrops  uint64

	// Seams for the host tests: the platform sampler and the log.
	sample func(*net.TCPConn) (relaySocketSample, bool)
	logf   func(format string, args ...interface{})
}

func newRelaySocketWatch() *relaySocketWatch {
	return &relaySocketWatch{
		socks:   map[int]*watchedRelaySocket{},
		arrived: make(chan struct{}, 1),
		sample:  readRelaySocket,
		logf:    turnLog,
	}
}

// relaySockets watches the relay connections of the running proxy.
var relaySockets = newRelaySocketWatch()

// relayTCPConn is the TCP connection under a dialed relay conn, nil over UDP.
func relayTCPConn(c net.Conn) *net.TCPConn {
	if split, ok := c.(*splitFirstWriteConn); ok {
		c = split.Conn
	}
	if flow, ok := c.(*relayFlowConn); ok {
		c = flow.Conn
	}
	tc, _ := c.(*net.TCPConn)
	return tc
}

// register starts watching a session's connection; nil (a UDP session) is
// ignored. The caller unregisters before it closes the connection.
func (w *relaySocketWatch) register(stream int, relay string, conn *net.TCPConn) {
	if conn == nil {
		return
	}
	w.mu.Lock()
	w.socks[stream] = &watchedRelaySocket{stream: stream, relay: relay, conn: conn}
	w.mu.Unlock()
	w.nudge()
}

// nudge wakes the watcher; one pending wake-up is as good as many.
func (w *relaySocketWatch) nudge() {
	select {
	case w.arrived <- struct{}{}:
	default:
	}
}

// unregister stops watching a stream's connection. A stall that never ended is
// reported here — it is the one the summaries could only ever list as "now".
func (w *relaySocketWatch) unregister(stream int, conn *net.TCPConn, now time.Time) {
	if conn == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.socks[stream]
	if s == nil || s.conn != conn {
		return
	}
	delete(w.socks, stream)
	w.endStallLocked(s, now, "and had not moved again when the session ended")
}

func (w *relaySocketWatch) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.socks)
}

// run samples while any stream is on TCP and sleeps while none is.
func (w *relaySocketWatch) run(ctx context.Context, streams []*stream) {
	// The watch outlives a proxy session, its runs do not: one that is on its way
	// out can take the wake-up meant for its successor (a stop and the next
	// start's first stream, moments apart). It leaves one behind instead — a
	// spare wake-up costs the next run one look at an empty list.
	defer w.nudge()

	w.mu.Lock()
	w.window = relaySocketWindow{}
	w.stallLines = 0
	w.lastDrops = dispatchDropCount.Load()
	w.mu.Unlock()

	for {
		// Asleep until a stream is on TCP. A wake-up left over from a socket that
		// has come and gone finds nothing to watch and comes straight back here.
		select {
		case <-ctx.Done():
			return
		case <-w.arrived:
		}
		ticker := time.NewTicker(relaySocketSampleInterval)
		for w.count() > 0 {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case now := <-ticker.C:
				w.observe(streams, now)
			}
		}
		ticker.Stop()
		// The last socket left mid-window: say what it had carried.
		w.mu.Lock()
		w.flushLocked(time.Now())
		w.mu.Unlock()
	}
}

// observe takes one sample of every watched socket and of the stream queues,
// and prints the summary when a window is over.
func (w *relaySocketWatch) observe(streams []*stream, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.window.start.IsZero() {
		w.window.start = now
	}
	for _, s := range w.socks {
		cur, ok := w.sample(s.conn)
		if !ok {
			continue
		}
		w.window.up += counterDelta(cur.acked, s.last.acked)
		w.window.down += counterDelta(cur.received, s.last.received)
		w.window.segsOut += counterDelta(cur.segsOut, s.last.segsOut)
		w.window.retrans += counterDelta(cur.retrans, s.last.retrans)
		w.window.busy += durationDelta(cur.busy, s.last.busy)
		w.window.peerWindow += durationDelta(cur.waitedOnPeerWindow, s.last.waitedOnPeerWindow)
		w.window.sndBf += durationDelta(cur.waitedOnSendBuffer, s.last.waitedOnSendBuffer)
		if cur.backlog > w.window.backlogPeak {
			w.window.backlogPeak, w.window.backlogStream = cur.backlog, s.stream
		}
		s.last = cur

		if cur.timeouts > 0 {
			if s.stalledSince.IsZero() {
				s.stalledSince = now
				s.stallTimeouts, s.stallBacklog = 0, 0
			}
			s.stallProbing = cur.probing
			if cur.timeouts > s.stallTimeouts {
				s.stallTimeouts = cur.timeouts
			}
			if cur.backlog > s.stallBacklog {
				s.stallBacklog = cur.backlog
			}
		} else {
			w.endStallLocked(s, now, "— moving again")
		}
	}
	for _, st := range streams {
		if n := len(st.in); n > w.window.queuePeak {
			w.window.queuePeak, w.window.queueCap, w.window.queueStream = n, cap(st.in), st.id
		}
	}
	if now.Sub(w.window.start) >= relaySocketLogInterval {
		w.flushLocked(now)
	}
}

// endStallLocked closes a socket's stall, if it is in one, and reports it when
// it lasted long enough to be one.
func (w *relaySocketWatch) endStallLocked(s *watchedRelaySocket, now time.Time, how string) {
	if s.stalledSince.IsZero() {
		return
	}
	lasted := now.Sub(s.stalledSince)
	s.stalledSince = time.Time{}
	if lasted < relayStallReportAfter {
		return
	}
	w.window.stallsEnded++
	if lasted > w.window.longestStall {
		w.window.longestStall = lasted
	}
	if w.stallLines >= relayStallLogBudget {
		return
	}
	w.stallLines++
	what := fmt.Sprintf("%d retransmission timeout(s) in a row unanswered", s.stallTimeouts)
	if s.stallProbing {
		what = fmt.Sprintf("the relay's receive window closed, %d window probe(s) unanswered", s.stallTimeouts)
	}
	w.logf("[TCP] stream %d (%s) stalled for ~%v: %s, up to %s waiting in the socket %s",
		s.stream, s.relay, lasted.Round(time.Second), what, kilobytes(uint64(s.stallBacklog)), how)
	if w.stallLines == relayStallLogBudget {
		w.logf("[TCP] %d stalls reported this session — further ones are only counted in the summaries", relayStallLogBudget)
	}
}

// flushLocked prints the window's summary, if it has anything to say, and
// starts the next window.
func (w *relaySocketWatch) flushLocked(now time.Time) {
	win := w.window
	drops := dispatchDropCount.Load()
	win.drops = counterDelta(drops, w.lastDrops)
	w.lastDrops = drops
	// The next window runs from here, so that it is as long as it says it is;
	// with nothing left to watch it starts at the next sample instead.
	w.window = relaySocketWindow{}
	if len(w.socks) > 0 {
		w.window.start = now
	}
	if win.start.IsZero() {
		return
	}

	var rtts []time.Duration
	var stalledNow []string
	streams := make([]int, 0, len(w.socks))
	for id := range w.socks {
		streams = append(streams, id)
	}
	sort.Ints(streams)
	for _, id := range streams {
		s := w.socks[id]
		if s.last.rtt > 0 {
			rtts = append(rtts, s.last.rtt)
		}
		if !s.stalledSince.IsZero() && now.Sub(s.stalledSince) >= relayStallReportAfter {
			stalledNow = append(stalledNow, fmt.Sprintf("stream %d for %v", id, now.Sub(s.stalledSince).Round(time.Second)))
		}
	}

	if win.up+win.down < relayTrafficWorthALine && win.stallsEnded == 0 && len(stalledNow) == 0 && win.drops == 0 {
		return
	}
	w.logf("%s", relaySocketSummary(win, now.Sub(win.start), len(w.socks), rtts, stalledNow))
}

// relaySocketSummary renders one window. Parts with nothing to report, or that
// this kernel does not count, are left out rather than printed as zeros.
func relaySocketSummary(win relaySocketWindow, span time.Duration, sockets int, rtts []time.Duration, stalledNow []string) string {
	parts := []string{fmt.Sprintf("up %s, down %s", kilobytes(win.up), kilobytes(win.down))}

	if win.segsOut > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d segments retransmitted (%.1f%%)",
			win.retrans, win.segsOut, 100*float64(win.retrans)/float64(win.segsOut)))
	} else if win.retrans > 0 {
		parts = append(parts, fmt.Sprintf("%d segments retransmitted", win.retrans))
	}
	if len(rtts) > 0 {
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		parts = append(parts, fmt.Sprintf("rtt %v-%v, median %v",
			rtts[0].Round(time.Millisecond), rtts[len(rtts)-1].Round(time.Millisecond), rtts[len(rtts)/2].Round(time.Millisecond)))
	}
	if win.backlogPeak > 0 {
		parts = append(parts, fmt.Sprintf("socket backlog peaked at %s (stream %d)", kilobytes(uint64(win.backlogPeak)), win.backlogStream))
	}
	if win.queuePeak > 0 {
		parts = append(parts, fmt.Sprintf("stream queue at %d/%d (stream %d)", win.queuePeak, win.queueCap, win.queueStream))
	}
	if win.drops > 0 {
		parts = append(parts, fmt.Sprintf("dispatcher dropped %d packet(s)", win.drops))
	}
	if win.busy > 0 {
		parts = append(parts, fmt.Sprintf("of the time with data to send, %d%% waited on the relay's window and %d%% on our send buffer",
			percentOf(win.peerWindow, win.busy), percentOf(win.sndBf, win.busy)))
	}
	if win.stallsEnded > 0 {
		parts = append(parts, fmt.Sprintf("%d stall(s) ended, longest %v", win.stallsEnded, win.longestStall.Round(time.Second)))
	}
	if len(stalledNow) > 0 {
		parts = append(parts, "stalled now: "+strings.Join(stalledNow, ", "))
	}
	return fmt.Sprintf("[TCP] last %v over %d socket(s): %s", span.Round(time.Second), sockets, strings.Join(parts, "; "))
}

// counterDelta is how far a cumulative counter moved. A counter that went
// backwards is a new socket under the same stream, counted from zero.
func counterDelta(cur, prev uint64) uint64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

func durationDelta(cur, prev time.Duration) time.Duration {
	if cur < prev {
		return cur
	}
	return cur - prev
}

func percentOf(part, whole time.Duration) int {
	if whole <= 0 {
		return 0
	}
	return int((100*part + whole/2) / whole)
}

func kilobytes(n uint64) string {
	return fmt.Sprintf("%d KB", (n+512)/1024)
}
