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
// packet path), and four things come out of it:
//
//   - stream.sendStalled on a stream whose socket has its head segment timing
//     out (relayStallSkipTimeouts in a row): the dispatcher takes traffic past
//     it until the socket moves again. The 22.09 field log is why: the
//     direction up died on its own, flows were fed until a reset or the
//     kernel's 30s limit, and nothing that judges a stream by what it hears
//     ever noticed;
//   - a line per stall: a connection that went relayStallReportAfter or longer
//     with its head segment timing out and nothing acknowledged — how long, how
//     deep the timeouts went, how much was waiting behind it;
//   - a summary every relaySocketLogInterval in which traffic moved or something
//     stalled: bytes each way, retransmissions, the rtt spread across the pool,
//     the deepest socket backlog and stream queue, how much of the sending time
//     went on waiting for the relay's window or for our own send buffer, and
//     how many packets the dispatcher steered past stalled sockets;
//   - a connection whose segments the kernel has cut and left cut (see
//     relayShrunkMSS) is redialed, one at a time, once the path is calm again.
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

	// relayStallSkipTimeouts is how many timeouts in a row of the head segment
	// take a stream out of dispatch (stream.sendStalled) until the socket moves
	// again. One is ordinary tail loss on a healthy path; the retransmission
	// timing out as well is roughly a second without any acknowledgement at the
	// rtts seen on these relays, which a flow that is merely lossy does not do.
	// Unanswered probes count the same, and two keep a single keepalive probe
	// caught in flight by the sample from counting. A relay that answers its
	// window probes with the window still closed resets the count: that flow is
	// slow, not gone, and is not marked.
	relayStallSkipTimeouts = 2

	// relayShrunkCalm is how long a connection whose segments were cut has to
	// have gone without a retransmission timeout before it is replaced: the
	// path is back, so the redial is not a dial into the same darkness, which
	// would fail and cost the stream its slot for a backoff.
	relayShrunkCalm = 10 * time.Second

	// relayShrunkGap spaces the replacements over the pool. One stall cuts every
	// socket that lived through it, and redialing them all at once would take
	// the tunnel down for the length of a reconnect and fire six Allocates at
	// the relays together; one at a time, the siblings carry the traffic.
	relayShrunkGap = 15 * time.Second
)

// relayShrunkMSS says whether a connection to a relay has had its segments cut
// to half the size it began with or less, which is when it is replaced.
//
// The kernel does that by itself. A connection whose head segment keeps timing
// out past tcp_retries1 is taken for one into a path-MTU black hole: with
// tcp_mtu_probing on, the segment size drops to tcp_base_mss, 1024, and halves
// again at each timeout after that. Stock Android leaves it off (a Pixel 6a on
// Android 17 reads 0), and there this never fires; the Xiaomi of the 17.10
// field log (HyperOS, Rostelecom, TCP) has it on and did it in every stall:
// the streams that went silent had 512, 256, 128, 80 and 64 bytes a segment
// where they began with 1228. A stall on
// these paths is the whole radio going dark (both relays, every socket, fresh
// dials too), not big segments being dropped, so the cut buys nothing. And it
// stays: the kernel grows the size back only by MTU probes, which it sends only
// with a deep queue of unsent data and a congestion window of eleven segments
// or more — a long upload, not a tunnel whose way up is mostly the
// acknowledgements of a download. In the log, streams went into a stall
// already at 128 or 64 bytes after three to five timeouts, too few to get
// there from 1228 within it: the cut of a stall minutes before was still in
// place.
//
// What that costs is the way up. A full packet of the tunnel, ~1.3 KB on this
// leg, goes to the relay as ~20 segments of 64 bytes instead of two, with 52
// bytes of headers on each; the congestion window counts segments, so an
// upload crawls at a few kilobytes per round trip; and a segment lost anywhere
// holds the whole packet, and every one behind it in the stream. A new
// connection starts at full size.
//
// Half, not any cut: the first one, to 1024, still moves a packet in two
// segments, the same as 1228, and is not worth a reconnect.
func relayShrunkMSS(peak, now int) bool {
	return peak > 0 && now > 0 && 2*now <= peak
}

// replaceSocketSession ends the session that carries s the way a network move
// ends it: its worker reconnects at once and counts no failure
// (network_switch.go). The session closes its relay on the way out, which
// releases the allocation — the socket is moving, so the release goes out.
//
// The attempt is the one the session was running when it registered the socket,
// not the stream's attempt of the moment. Read at the time of the replacement,
// that could already be the next one: the session ended, and its worker began
// another attempt or sat in the wait after this one, which a recycle would cut
// short with the streak cleared (Codex review, 18.10).
func replaceSocketSession(s *watchedRelaySocket) bool {
	if s.attempt == nil {
		return false
	}
	recycleAttempt(s.attempt)
	return true
}

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

	// Only for the line about a stream that went silent (silentSocketLine).
	sinceData, sinceAck time.Duration // since the relay's last data / last ACK
	sndMSS, rcvMSS      int
	pathMTU             int
}

type watchedRelaySocket struct {
	stream int
	relay  string
	conn   *net.TCPConn

	// st is the stream whose session the socket carries: the one sendStalled is
	// set on, and cleared on when the session lets go of the socket. Given at
	// registration rather than looked up by id, which is ambiguous for as long
	// as a run of the watcher leaving with its proxy can still sample the
	// sockets of the next one.
	st *stream

	last relaySocketSample // zero until first sampled: a new socket counts from zero

	// attempt is the worker attempt whose session registered the socket: the one
	// replaceSocketSession ends.
	attempt *networkAttempt

	// For relayShrunkMSS: the largest segment size the connection has had, and
	// the last sample that found its head segment timing out (the first sample
	// until one does). replaced is set once its session has been told to go.
	peakMSS     int
	lastTimeout time.Time
	replaced    bool

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
	steered, intoStalled    uint64
}

type relaySocketWatch struct {
	mu sync.Mutex
	// socks is keyed by the connection, not the stream id: a worker of a stopped
	// proxy that outlived the stop's drain can still register a session under an
	// id the next proxy's stream is using, and one entry per id would then evict
	// the live socket — unwatched, and with its stream's mark past clearing.
	socks map[*net.TCPConn]*watchedRelaySocket
	// arrived wakes the watcher when the first socket registers.
	arrived chan struct{}

	window     relaySocketWindow
	stallLines int
	// The dispatcher's counters as of the last summary; a window reports what
	// they moved by.
	lastDrops, lastSteered, lastIntoStalled uint64

	// lastReplaced is when a connection was last replaced for its cut segments
	// (relayShrunkGap).
	lastReplaced time.Time

	// Seams for the host tests: the platform sampler, the log, and what ends a
	// session.
	sample  func(*net.TCPConn) (relaySocketSample, bool)
	logf    func(format string, args ...interface{})
	replace func(*watchedRelaySocket) bool
}

// newRelaySocketWatch counts the dispatcher's counters from now; run does the
// same for each proxy session.
func newRelaySocketWatch() *relaySocketWatch {
	return &relaySocketWatch{
		socks:           map[*net.TCPConn]*watchedRelaySocket{},
		arrived:         make(chan struct{}, 1),
		sample:          readRelaySocket,
		logf:            turnLog,
		replace:         replaceSocketSession,
		lastDrops:       dispatchDropCount.Load(),
		lastSteered:     dispatchSteeredCount.Load(),
		lastIntoStalled: dispatchIntoStalledCount.Load(),
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

// register starts watching the connection of a session of st; nil (a UDP
// session) is ignored. The caller unregisters before it closes the connection.
func (w *relaySocketWatch) register(st *stream, relay string, conn *net.TCPConn) {
	if conn == nil {
		return
	}
	w.mu.Lock()
	w.socks[conn] = &watchedRelaySocket{stream: st.id, relay: relay, conn: conn, st: st, attempt: st.attempt.Load()}
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

// unregister stops watching a session's connection. A stall that never ended
// is reported here — it is the one the summaries could only ever list as "now".
func (w *relaySocketWatch) unregister(conn *net.TCPConn, now time.Time) {
	if conn == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.socks[conn]
	if s == nil {
		return
	}
	delete(w.socks, conn)
	// The stream's next session starts clear, whatever its transport. Under the
	// lock observe sets the mark under, so no sample of this socket lands after.
	s.st.sendStalled.Store(false)
	w.endStallLocked(s, now, "and had not moved again when the session ended")
}

// silentSocketLine describes the socket of a stream the dispatcher has just
// found silent; "" over UDP. Silence is judged by the keepalive echo, which the
// relay writes into this same TCP stream — so which of the two directions still
// moves tells the causes apart, and the phone is the only place it can be read:
//
//   - ACKs fresh, data old: the relay hears us and answers, its small segments
//     arrive and what it SENDS does not. A data segment lost over and over while
//     ACKs pass is loss by size — a path MTU below what both ends believe, with
//     the ICMP that would say so filtered — and the echo is stuck behind it.
//   - both old, timeouts counting: nothing comes down at all, or nothing of ours
//     goes up. The flow is dark, not its big segments.
//   - data fresh: the socket is fine and the silence is further out — the relay
//     forwards nothing from the server on this allocation.
func (w *relaySocketWatch) silentSocketLine(st *stream) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var s *watchedRelaySocket
	for _, sock := range w.socks {
		if sock.st == st {
			s = sock
		}
	}
	if s == nil {
		return ""
	}
	cur, ok := w.sample(s.conn)
	if !ok {
		return ""
	}
	up := "nothing of ours unacknowledged"
	if cur.backlog > 0 {
		up = fmt.Sprintf("up to %s of ours unacknowledged", kilobytes(uint64(cur.backlog)))
		if cur.timeouts > 0 {
			up += fmt.Sprintf(" after %d timeout(s) in a row", cur.timeouts)
		}
	}
	return fmt.Sprintf("[TCP] stream %d (%s) went silent with its socket at: last data from the relay %v ago, last ACK %v ago; %s; %s received in all; mss %d out / %d in, path mtu %d",
		s.stream, s.relay, cur.sinceData.Round(100*time.Millisecond), cur.sinceAck.Round(100*time.Millisecond),
		up, kilobytes(cur.received), cur.sndMSS, cur.rcvMSS, cur.pathMTU)
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
	w.lastSteered = dispatchSteeredCount.Load()
	w.lastIntoStalled = dispatchIntoStalledCount.Load()
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
// prints the summary when a window is over, and replaces a connection whose
// segments the kernel has cut.
func (w *relaySocketWatch) observe(streams []*stream, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.observeLocked(streams, now)

	// Picked and ended under the lock: while the socket is in the map, the
	// session that registered it is still running — it lets go of the socket
	// first thing on its way out — so the attempt it carries is still that
	// session's. Ending it only cancels a context; the session unregisters
	// later, on its own goroutine. (The lock order is this one then the
	// network switch's, which never calls in here.)
	shrunk := w.pickShrunkLocked(streams, now)
	if shrunk == nil || !w.replace(shrunk) {
		return
	}
	shrunk.replaced = true
	w.lastReplaced = now
	w.logf("[TCP] stream %d (%s): the kernel cut its segments to %d bytes from %d in a stall and has not grown them back — redialing it for a connection at full size",
		shrunk.stream, shrunk.relay, shrunk.last.sndMSS, shrunk.peakMSS)
}

// pickShrunkLocked chooses the connection to replace for its cut segments now,
// if any; the caller ends its session. The most cut goes first. None goes
// while another went less than relayShrunkGap ago, or while no other stream
// could take the traffic: the replacement is a planned one, and a stream lost
// to a reconnect with nothing beside it is the tunnel lost to it.
func (w *relaySocketWatch) pickShrunkLocked(streams []*stream, now time.Time) *watchedRelaySocket {
	if !w.lastReplaced.IsZero() && now.Sub(w.lastReplaced) < relayShrunkGap {
		return nil
	}
	var pick *watchedRelaySocket
	for _, s := range w.socks {
		if s.replaced || !relayShrunkMSS(s.peakMSS, s.last.sndMSS) || now.Sub(s.lastTimeout) < relayShrunkCalm {
			continue
		}
		if pick == nil || s.last.sndMSS < pick.last.sndMSS ||
			(s.last.sndMSS == pick.last.sndMSS && s.stream < pick.stream) {
			pick = s
		}
	}
	if pick == nil || !anotherStreamCarries(streams, pick.st) {
		return nil
	}
	return pick
}

// anotherStreamCarries reports whether a stream other than st is ready and
// taking what is sent to it.
func anotherStreamCarries(streams []*stream, st *stream) bool {
	for _, o := range streams {
		if o != st && o.ready.Load() && !o.sendStalled.Load() {
			return true
		}
	}
	return false
}

func (w *relaySocketWatch) observeLocked(streams []*stream, now time.Time) {
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
		if cur.sndMSS > s.peakMSS {
			s.peakMSS = cur.sndMSS
		}
		if cur.timeouts > 0 || s.lastTimeout.IsZero() {
			s.lastTimeout = now
		}

		s.st.sendStalled.Store(cur.timeouts >= relayStallSkipTimeouts)

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
		if n := len(st.in) + len(st.priority); n > w.window.queuePeak {
			w.window.queuePeak, w.window.queueCap, w.window.queueStream = n, cap(st.in)+cap(st.priority), st.id
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
	steered, into := dispatchSteeredCount.Load(), dispatchIntoStalledCount.Load()
	win.steered, win.intoStalled = counterDelta(steered, w.lastSteered), counterDelta(into, w.lastIntoStalled)
	w.lastSteered, w.lastIntoStalled = steered, into
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
	socks := make([]*watchedRelaySocket, 0, len(w.socks))
	for _, s := range w.socks {
		socks = append(socks, s)
	}
	sort.Slice(socks, func(i, j int) bool { return socks[i].stream < socks[j].stream })
	for _, s := range socks {
		if s.last.rtt > 0 {
			rtts = append(rtts, s.last.rtt)
		}
		if !s.stalledSince.IsZero() && now.Sub(s.stalledSince) >= relayStallReportAfter {
			stalledNow = append(stalledNow, fmt.Sprintf("stream %d for %v", s.stream, now.Sub(s.stalledSince).Round(time.Second)))
		}
	}

	if win.up+win.down < relayTrafficWorthALine && win.stallsEnded == 0 && len(stalledNow) == 0 &&
		win.drops == 0 && win.steered == 0 && win.intoStalled == 0 {
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
	if win.steered > 0 {
		parts = append(parts, fmt.Sprintf("%d packet(s) steered past stalled sockets", win.steered))
	}
	if win.intoStalled > 0 {
		parts = append(parts, fmt.Sprintf("%d packet(s) into stalled sockets, no other ready stream could take them", win.intoStalled))
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
