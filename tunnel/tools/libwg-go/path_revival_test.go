/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// What the dark leaves behind and what a relay says: only the first is cured by
// a session getting through afterwards.
func TestPathWideFailuresAreToldFromTheRelaysAnswers(t *testing.T) {
	dialTimeout := fmt.Errorf("TURN TCP dial: %w", &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded})
	allocateSilence := fmt.Errorf("TURN allocate: %w", fmt.Errorf("%w %s", errors.New("all retransmissions failed for"), "dHJhbnNhY3Rpb24="))
	refused := fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeForbidden))

	for name, err := range map[string]error{
		"connect timed out (Go)":       dialTimeout,
		"connect timed out (kernel)":   fmt.Errorf("TURN TCP dial: %w", opErr("connect", syscall.ETIMEDOUT)),
		"Allocate unanswered":          allocateSilence,
		"Allocate retransmit unsent":   fmt.Errorf("TURN allocate: %w", fmt.Errorf("%w %s", errors.New("turn: failed to retransmit transaction"), "key")),
		"relay proof unanswered":       fmt.Errorf("%w: %w", errDataPlaneHandshake, fmt.Errorf("%w in %v", errRelayNeverAnswered, relayProofTimeoutTCP)),
		"DTLS handshake unanswered":    fmt.Errorf("%w: DTLS handshake failed: %w", errDataPlaneHandshake, context.DeadlineExceeded),
		"session gone deaf":            &deadStreamError{silent: 90 * time.Second},
		"reset by the relay":           fmt.Errorf("the relay connection is no longer read: %w", opErr("read", syscall.ECONNRESET)),
		"written after a reset":        fmt.Errorf("relay TX: %w", opErr("write", syscall.EPIPE)),
		"given up by the kernel":       fmt.Errorf("%w: no progress for %v: %w", errRelayFlowTimedOut, relayTCPUserTimeout, net.ErrClosed),
		"kernel give-up met by write":  fmt.Errorf("relay TX: %w", opErr("write", syscall.ETIMEDOUT)),
		"write refused by the stack":   fmt.Errorf("relay TX: %w", writeErr(50819, syscall.EPERM)),
		"no route":                     fmt.Errorf("TURN allocate: %w", writeErr(50819, syscall.ENETUNREACH)),
		"both relays silent":           newRaceError([]relayAttemptError{{err: allocateSilence}, {err: dialTimeout}}),
		"one relay silent, one unsent": newRaceError([]relayAttemptError{{err: dialTimeout}, {err: fmt.Errorf("TURN allocate: %w", writeErr(1, syscall.EPERM))}}),
	} {
		if !pathWideFailure(err) {
			t.Errorf("%s (%v): not read as the dark's doing", name, err)
		}
	}

	for name, err := range map[string]error{
		"none":                       nil,
		"quota":                      fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeAllocQuotaReached)),
		"credential":                 fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeUnauthorized)),
		"allocation mismatch":        fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeAllocMismatch)),
		"forbidden":                  refused,
		"connect refused":            fmt.Errorf("TURN TCP dial: %w", opErr("connect", syscall.ECONNREFUSED)),
		"flow closed by the relay":   fmt.Errorf("the relay connection is no longer read: %w", io.EOF),
		"blackhole":                  fmt.Errorf("TURN blackhole: %s", "allocation refresh failed"),
		"DTLS handshake refused":     fmt.Errorf("%w: DTLS handshake failed: %w", errDataPlaneHandshake, errors.New("alert: bad certificate")),
		"sentinel's text alone":      errors.New("all retransmissions failed for 10.0.0.1"),
		"one silent, one answering":  newRaceError([]relayAttemptError{{err: refused}, {err: dialTimeout}}),
		"one answering 486":          newRaceError([]relayAttemptError{{err: dialTimeout}, {err: fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeAllocQuotaReached))}}),
		"something not known at all": errors.New("TURN listen: something else"),
	} {
		if pathWideFailure(err) {
			t.Errorf("%s (%v): read as the dark's doing", name, err)
		}
	}
}

// A proof wakes the waits over its own transport, and every one of them: the
// channel a worker holds is closed by the next proof, and the next worker to
// ask gets a fresh one. Each proof is booked on the stream that made it.
func TestAProofClosesTheWaitsOverItsTransport(t *testing.T) {
	udpWait, tcpWait := nextPathProof(false), nextPathProof(true)
	if nextPathProof(true) != tcpWait {
		t.Fatal("two workers asking before any proof were given different waits")
	}

	s := &stream{}
	s.overTCP.Store(true)
	s.notePathProven()
	if !closed(tcpWait) {
		t.Fatal("a proof over TCP did not end the wait over TCP")
	}
	if closed(udpWait) {
		t.Fatal("a proof over TCP ended the wait over UDP")
	}
	if closed(nextPathProof(true)) {
		t.Fatal("the wait handed out after a proof is already over")
	}
	if s.pathProofs.Load() != 1 {
		t.Fatalf("the stream booked %d proofs, want 1", s.pathProofs.Load())
	}
	(&stream{}).notePathProven()
	if !closed(udpWait) {
		t.Fatal("a proof over UDP did not end the wait over UDP")
	}
}

func pinRevivalGap(t *testing.T, d time.Duration) {
	t.Helper()
	prev := revivalGap
	revivalGap = func() time.Duration { return d }
	resetRevivalPacing()
	t.Cleanup(func() {
		revivalGap = prev
		resetRevivalPacing()
	})
}

func resetRevivalPacing() {
	revivalPacing.Lock()
	revivalPacing.next = time.Time{}
	revivalPacing.Unlock()
}

// Woken together, gone one at a time: the first at once, the rest a gap apart.
// A worker whose own delay ends first goes then, and holds nobody up; one whose
// attempt ends meanwhile does not go at all.
func TestWokenWorkersReconnectOneAtATime(t *testing.T) {
	const gap = 150 * time.Millisecond
	pinRevivalGap(t, gap)

	start := time.Now()
	far := start.Add(time.Minute)
	var mu sync.Mutex
	var went []time.Duration
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !awaitRevivalSlot(context.Background(), far) {
				t.Error("a waiter with a live context was turned away")
			}
			mu.Lock()
			went = append(went, time.Since(start))
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(went, func(i, j int) bool { return went[i] < went[j] })
	if went[0] > 50*time.Millisecond {
		t.Fatalf("the first woken worker waited %v", went[0])
	}
	for i := 1; i < len(went); i++ {
		if d := went[i] - went[i-1]; d < gap-30*time.Millisecond {
			t.Fatalf("woken workers went %v apart (%v), want at least %v", d, went, gap)
		}
	}

	// The next slot is a gap away; a worker whose delay runs out sooner goes at
	// its own time and takes no slot.
	revivalPacing.Lock()
	next := time.Now().Add(gap)
	revivalPacing.next = next
	revivalPacing.Unlock()
	soon := time.Now().Add(gap / 3)
	if !awaitRevivalSlot(context.Background(), soon) {
		t.Fatal("a worker reaching its own deadline was turned away")
	}
	if late := time.Since(soon); late < 0 || late > 40*time.Millisecond {
		t.Fatalf("a worker whose delay ran out went %v after it", late)
	}
	revivalPacing.Lock()
	taken := !revivalPacing.next.Equal(next)
	revivalPacing.Unlock()
	if taken {
		t.Fatal("a worker that went at its own deadline took a slot")
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if awaitRevivalSlot(ctx, far) {
		t.Fatal("a worker whose attempt ended was still let go")
	}
}

// relayDials stands in for the TCP connects to the relays. While dark is set
// every one fails at once with a dial timeout: the radio path gone while the
// network stays up. A blackholed SYN cannot be staged on loopback, and sitting
// out relayTCPConnectTimeout would only make the test slower. The connects
// that do go out are timed.
type relayDials struct {
	dark  atomic.Bool
	tried atomic.Int32 // every connect, dark or not
	mu    sync.Mutex
	out   []time.Time
}

func stageRelayDials(t *testing.T) *relayDials {
	t.Helper()
	dials := &relayDials{}
	prev := dialRelayTCP
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, to string) (net.Conn, error) {
		dials.tried.Add(1)
		if dials.dark.Load() {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
		}
		dials.mu.Lock()
		dials.out = append(dials.out, time.Now())
		dials.mu.Unlock()
		return prev(ctx, d, to)
	}
	t.Cleanup(func() { dialRelayTCP = prev })
	return dials
}

func (d *relayDials) sent() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.out...)
}

// waitsOf reports every wait a worker goes into, through the seam runWorker
// calls as it enters one; seen, if set, is called first, in the worker.
func waitsOf(t *testing.T, seen func(workerWait)) <-chan workerWait {
	t.Helper()
	entered := make(chan workerWait, 64)
	prev := workerWaits
	workerWaits = func(w workerWait) {
		if seen != nil {
			seen(w)
		}
		select {
		case entered <- w:
		default:
		}
	}
	t.Cleanup(func() { workerWaits = prev })
	return entered
}

// awaitLongWaits returns the first long wait of each of n workers.
func awaitLongWaits(t *testing.T, entered <-chan workerWait, n int) map[int]workerWait {
	t.Helper()
	got := map[int]workerWait{}
	timeout := time.After(15 * time.Second)
	for len(got) < n {
		select {
		case w := <-entered:
			if _, ok := got[w.stream]; !ok && w.delay >= 5*time.Second {
				got[w.stream] = w
			}
		case <-timeout:
			t.Fatalf("%d of %d workers went into a long wait: the test staged nothing", len(got), n)
		}
	}
	return got
}

// startSibling runs one more worker of the group, on stream id.
func startSibling(t *testing.T, group, id int, peer *net.UDPAddr) *stream {
	t.Helper()
	s, _ := newNoDTLSTestStream(t)
	s.id = id
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWorker(ctx, WorkerGroupConfig{GroupID: group, Link: "test", UseUDP: true, PeerType: "wireguard", PeerAddr: peer}, s, 0)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return s
}

func echoingPeer(t *testing.T) *net.UDPAddr {
	t.Helper()
	answer := make(chan struct{})
	close(answer)
	return fakeRelay(t, answer)
}

// The field case, 17.10 and the reproduction of 18.10: the path went dark, a
// worker's redials went into it and it backed off for 7-17s; the path came
// back, and it slept on next to it. Once another stream's session gets through,
// it has to be back within a second or two, not at the end of its delay.
func TestASiblingGettingThroughWakesAWorkerBackingOffFromTheDark(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	resetRevivalPacing()
	dials := stageRelayDials(t)
	dials.dark.Store(true)
	entered := waitsOf(t, nil)
	peer := echoingPeer(t)
	h := runWorkersAgainstPeer(t, 141, 1, []string{relay.addr}, peer)

	// Two connects into the dark: the second wait is reconnectDelay(2), 7-17s.
	w := awaitLongWaits(t, entered, 1)[0]
	if !w.wakeable || !w.revivable {
		t.Fatalf("the wait after connects timing out is wakeable=%v revivable=%v, want both", w.wakeable, w.revivable)
	}
	slept := time.Now()

	// The path is back, and nothing says so yet: the worker sleeps on.
	dials.dark.Store(false)
	time.Sleep(time.Second)
	if n := relay.ln.accepted.Load(); n != 0 {
		t.Fatalf("the relay took %d connection(s) before any session got through", n)
	}

	sibling := startSibling(t, 141, 1, peer)
	waitFor(t, "the sibling's session", 3*time.Second, sibling.ready.Load)
	through := time.Now()
	waitFor(t, "the sleeping worker's redial", 2*time.Second, func() bool { return relay.ln.accepted.Load() >= 2 })
	waitFor(t, "the sleeping worker back", 3*time.Second, func() bool { return h.ready() == 1 })
	t.Logf("back %v after the sibling got through, %v into a wait of %v", time.Since(through).Round(time.Millisecond),
		time.Since(slept).Round(time.Millisecond), w.delay.Round(time.Millisecond))
	if took := time.Since(slept); took >= w.delay {
		t.Fatalf("back %v into a wait of %v: it was sat out", took, w.delay)
	}
}

// Nine woken at once must not dial at once. Over TCP the connects to one relay
// are spaced anyway, so that spacing is taken off here: what is left is the
// wake-up's own — the first at once, the rest a gap apart.
func TestWorkersWokenTogetherReconnectOneAtATime(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	const gap = 300 * time.Millisecond
	pinRevivalGap(t, gap)
	pinRelayConnectGap(t, 0)
	dials := stageRelayDials(t)
	dials.dark.Store(true)
	entered := waitsOf(t, nil)
	peer := echoingPeer(t)
	h := runWorkersAgainstPeer(t, 142, 3, []string{relay.addr}, peer)
	for id, w := range awaitLongWaits(t, entered, 3) {
		if !w.revivable {
			t.Fatalf("worker %d's wait after connects timing out cannot be woken", id)
		}
	}

	dials.dark.Store(false)
	sibling := startSibling(t, 142, 3, peer)
	waitFor(t, "the sibling's session", 3*time.Second, sibling.ready.Load)
	waitFor(t, "the three back", 2*gap+3*time.Second, func() bool { return h.ready() == 3 })

	// The sibling's connect, then one per woken worker.
	sent := dials.sent()
	if len(sent) != 4 {
		t.Fatalf("%d connect(s) once the path was back, want the sibling's and one per woken worker", len(sent))
	}
	if d := sent[1].Sub(sent[0]); d > time.Second {
		t.Fatalf("the first woken worker dialed %v after the sibling", d)
	}
	for i := 2; i < len(sent); i++ {
		if d := sent[i].Sub(sent[i-1]); d < gap-20*time.Millisecond {
			t.Fatalf("woken workers dialed %v apart, want at least %v", d, gap)
		}
	}
	t.Logf("connects after the sibling's: %v, %v, %v", sent[1].Sub(sent[0]).Round(time.Millisecond),
		sent[2].Sub(sent[0]).Round(time.Millisecond), sent[3].Sub(sent[0]).Round(time.Millisecond))
}

// A session's own proof is not evidence for its own worker: it came up, then
// the relay reset it within the minute, and the path coming back since is what
// nobody has shown. It sits its delay out like any other.
func TestAWorkersOwnSessionDoesNotWakeIt(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	front := startStallingFront(t, relay.addr)
	t.Cleanup(front.close)
	overTCP(t)
	resetRevivalPacing()
	dials := stageRelayDials(t)
	dials.dark.Store(true)
	// The first connect goes into the dark, the second gets through.
	entered := waitsOf(t, func(w workerWait) {
		if w.delay < 5*time.Second {
			dials.dark.Store(false)
		}
	})
	h := runWorkersAgainstPeer(t, 143, 1, []string{front.addr}, echoingPeer(t))
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })

	front.resetDownstream()
	w := awaitLongWaits(t, entered, 1)[0]
	if !w.revivable {
		t.Fatal("the wait after a reset by the relay cannot be woken by another stream")
	}
	time.Sleep(2500 * time.Millisecond)
	if n := front.accepted.Load(); n != 1 {
		t.Fatalf("the worker redialed %d time(s) within 2.5s of a delay of %v that nobody else's session ended", n-1, w.delay)
	}
}

// What a session getting through must not end: a relay's answer, and above all
// the cooldown after a 486 on a credential that is still current — the quota is
// the credential's on the relay, and the path coming back frees none of it.
func TestASiblingGettingThroughDoesNotCutARelaysAnswer(t *testing.T) {
	t.Run("486 on the current credential", func(t *testing.T) {
		resetAllocationBook(t)
		resetNetworkSwitch(t)
		resetNetworkAvailabilityForTest()
		defer resetNetworkAvailabilityForTest()
		resetServerHealth()
		const group = 144
		dropCredSlot(t, group)
		refuser, _ := startInitialRefusalServer(t, 1000, stun.CodeAllocQuotaReached)
		addr := refuser.LocalAddr().String()
		// Just rotated: the 486 cannot rotate again, so the worker takes the
		// long cooldown (5-13s).
		cache := getStreamCache(group * streamsPerCredValue())
		cache.refreshMu.Lock()
		cache.lastRefresh = time.Now()
		cache.refreshMu.Unlock()

		entered := waitsOf(t, nil)
		ctx, cancel := context.WithCancel(context.Background())
		done := runWorkerAgainst(t, ctx, group, addr, fixedCredsAt(t.Name(), addr))
		defer func() {
			cancel()
			<-done
		}()
		w := awaitLongWaits(t, entered, 1)[3]
		if w.wakeable || w.revivable {
			t.Fatalf("the quota cooldown is wakeable=%v revivable=%v, want neither", w.wakeable, w.revivable)
		}
		dials := refuser.count()
		(&stream{}).notePathProven()
		time.Sleep(3 * time.Second)
		if n := refuser.count() - dials; n != 0 {
			t.Fatalf("%d dial(s) within 3s of another stream's session getting through: the quota cooldown was cut short", n)
		}
	})

	t.Run("refused", func(t *testing.T) {
		refuser, _ := startInitialRefusalServer(t, 1000, stun.CodeForbidden)
		entered := waitsOf(t, nil)
		runWorkersAgainst(t, 145, 1, []string{refuser.LocalAddr().String()})
		w := awaitLongWaits(t, entered, 1)[0]
		if !w.wakeable || w.revivable {
			t.Fatalf("the wait after a refusal is wakeable=%v revivable=%v, want only wakeable", w.wakeable, w.revivable)
		}
		dials := refuser.count()
		(&stream{}).notePathProven()
		time.Sleep(3 * time.Second)
		if n := refuser.count() - dials; n != 0 {
			t.Fatalf("%d dial(s) within 3s of another stream's session getting through: a refusal's delay was cut short", n)
		}
	})
}

// Who is parked while the path is dark: whoever failed into the dark, but never
// on a reset — that is the relay getting through — nor on an answer.
func TestWhoIsParkedWhileThePathIsDark(t *testing.T) {
	giveUp := fmt.Errorf("%w: no progress for %v: %w", errRelayFlowTimedOut, relayTCPUserTimeout, opErr("write", syscall.EPIPE))
	for name, err := range map[string]error{
		"connect timed out":           fmt.Errorf("TURN TCP dial: %w", &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}),
		"Allocate unanswered":         fmt.Errorf("TURN allocate: %w", fmt.Errorf("%w %s", errors.New("all retransmissions failed for"), "key")),
		"given up by the kernel":      giveUp,
		"write refused by the stack":  fmt.Errorf("relay TX: %w", writeErr(1, syscall.EPERM)),
		"relay proof unanswered":      fmt.Errorf("%w: %w", errDataPlaneHandshake, fmt.Errorf("%w in %v", errRelayNeverAnswered, relayProofTimeoutTCP)),
		"session deaf to the relay":   &deadStreamError{silent: 90 * time.Second},
		"two relays silent in a race": newRaceError([]relayAttemptError{{err: giveUp}, {err: fmt.Errorf("TURN TCP dial: %w", opErr("connect", syscall.ETIMEDOUT))}}),
	} {
		if !parksInTheDark(err) {
			t.Errorf("%s (%v): not parked", name, err)
		}
	}
	reset := fmt.Errorf("TURN TCP dial: %w", opErr("read", syscall.ECONNRESET))
	silence := fmt.Errorf("TURN TCP dial: %w", opErr("connect", syscall.ETIMEDOUT))
	for name, err := range map[string]error{
		"reset by the relay":    fmt.Errorf("the relay connection is no longer read: %w", opErr("read", syscall.ECONNRESET)),
		"written after a reset": fmt.Errorf("relay TX: %w", opErr("write", syscall.EPIPE)),
		// Whichever came in last: the race's chain carries only its spokesman.
		"a reset, then a silence, in a race": newRaceError([]relayAttemptError{{err: reset}, {err: silence}}),
		"a silence, then a reset, in a race": newRaceError([]relayAttemptError{{err: silence}, {err: reset}}),
		"quota":                              fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeAllocQuotaReached)),
		"refused":                            fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeForbidden)),
		"none":                               nil,
	} {
		if parksInTheDark(err) {
			t.Errorf("%s (%v): parked", name, err)
		}
	}
}

// lookout is a stream that is up, as far as the park reads it.
func lookout(overTCP, stalled bool, heard time.Time) *stream {
	s := &stream{}
	s.ready.Store(true)
	s.overTCP.Store(overTCP)
	s.sendStalled.Store(stalled)
	if !heard.IsZero() {
		s.activity.Store(newStreamActivity(heard, 0))
	}
	return s
}

// What the streams that are up have to say for the path to be dark: a socket
// stalled, and nobody hearing.
func TestWhenThePathLooksDark(t *testing.T) {
	now := time.Now()
	silent := now.Add(-pathDarkQuiet - time.Second)
	heard := now.Add(-pathDarkQuiet / 2)
	down := lookout(true, true, silent)
	down.ready.Store(false)

	for name, tc := range map[string]struct {
		streams []*stream
		dark    bool
	}{
		"nobody up":                    {nil, false},
		"stalled, silent":              {[]*stream{lookout(true, true, silent)}, true},
		"stalled, no clock yet":        {[]*stream{lookout(true, true, time.Time{})}, true},
		"stalled, still hearing":       {[]*stream{lookout(true, true, heard)}, false},
		"stalled beside a quiet one":   {[]*stream{lookout(true, true, silent), lookout(true, false, silent)}, true},
		"stalled beside a hearing one": {[]*stream{lookout(true, true, silent), lookout(true, false, heard)}, false},
		"stalled beside UDP hearing":   {[]*stream{lookout(true, true, silent), lookout(false, false, heard)}, false},
		"quiet, nothing stalled":       {[]*stream{lookout(true, false, silent), lookout(true, false, silent)}, false},
		"UDP quiet":                    {[]*stream{lookout(false, false, silent)}, false},
		"the stalled one is down":      {[]*stream{down, lookout(true, false, silent)}, false},
		"the hearing one is down, too": {[]*stream{lookout(true, true, silent), func() *stream { s := lookout(true, false, heard); s.ready.Store(false); return s }()}, true},
		"a stall mark over UDP":        {[]*stream{lookout(false, true, silent)}, false},
	} {
		if got := pathLooksDark(tc.streams, now); got != tc.dark {
			t.Errorf("%s: dark=%v, want %v", name, got, tc.dark)
		}
	}
}

// publishLookout makes the proxy's stream set the worker's streams and a
// lookout stream that is up: stalled over TCP, its relay last heard a minute ago.
func publishLookout(t *testing.T, streams []*stream) *stream {
	t.Helper()
	l := lookout(true, true, time.Now().Add(-time.Minute))
	set := append(append([]*stream(nil), streams...), l)
	activeStreams.Store(&set)
	t.Cleanup(func() { activeStreams.Store(nil) })
	return l
}

// The blackout runs of 18.10: with every socket stalled and no relay heard, a
// worker whose session ended redialed into the dark again and again. Now it
// redials once, finds the dark, and waits — no failure counted, no further dial
// — until a stream hears its relay; then it is back within a second or so.
func TestAWorkerFailingIntoADarkPathIsParkedUntilARelayIsHeard(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	resetRevivalPacing()
	dials := stageRelayDials(t)
	entered := waitsOf(t, nil)
	h := runWorkersAgainstPeer(t, 146, 1, []string{relay.addr}, echoingPeer(t))
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	l := publishLookout(t, h.streams)

	dials.dark.Store(true)
	tried := dials.tried.Load()
	recycleAttempt(h.streams[0].attempt.Load())
	var w workerWait
	select {
	case w = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker never went into a wait")
	}
	if !w.parked {
		t.Fatalf("the wait after a connect into the dark is %+v, want parked", w)
	}
	time.Sleep(3 * time.Second)
	if n := dials.tried.Load() - tried; n != 1 {
		t.Fatalf("%d connect(s) while the path was dark, want the one that found it dark", n)
	}

	dials.dark.Store(false)
	heard := time.Now()
	l.activity.Load().noteRx(heard)
	waitFor(t, "the parked worker back", 3*time.Second, func() bool { return h.ready() == 1 })
	t.Logf("back %v after a relay was heard", time.Since(heard).Round(time.Millisecond))
}

// Codex review, 18.10: a sibling getting through in a lit gap of a flapping
// path, while this worker's attempt is still under way, must not end the park
// the attempt goes into when the dark is back and it fails into it. The park
// waited on the proof attemptOnce took at the start of the attempt, already
// closed by then, and ended the moment it began: a second dial into the dark.
func TestAProofBeforeTheParkDoesNotEndIt(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	resetRevivalPacing()
	dials := stageRelayDials(t)
	sibling := &stream{}
	sibling.overTCP.Store(true)
	var proved atomic.Bool
	staged := dialRelayTCP
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, to string) (net.Conn, error) {
		if dials.dark.Load() && proved.CompareAndSwap(false, true) {
			sibling.notePathProven() // the lit gap, inside this attempt
		}
		return staged(ctx, d, to)
	}
	t.Cleanup(func() { dialRelayTCP = staged })
	entered := waitsOf(t, nil)
	h := runWorkersAgainstPeer(t, 148, 1, []string{relay.addr}, echoingPeer(t))
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	publishLookout(t, h.streams)

	dials.dark.Store(true)
	tried := dials.tried.Load()
	recycleAttempt(h.streams[0].attempt.Load())
	select {
	case w := <-entered:
		if !w.parked {
			t.Fatalf("the wait after a connect into the dark is %+v, want parked", w)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the worker never went into a wait")
	}
	if !proved.Load() {
		t.Fatal("the sibling's proof was never made")
	}
	time.Sleep(2 * time.Second)
	if n := dials.tried.Load() - tried; n != 1 {
		t.Fatalf("%d connect(s) with the path dark, want the one that found it dark: a proof made before the park ended it", n)
	}
}

// However long the path stays dark, its relays are dialed again: a relay set
// that has really died is not left alone. That used to be the park's limit;
// with the dark found it is the scout's turn (dark_scout.go).
func TestARelaySetDarkForLongIsStillDialed(t *testing.T) {
	prev := pathDarkParkMax
	pathDarkParkMax = 1500 * time.Millisecond
	t.Cleanup(func() { pathDarkParkMax = prev })
	// The turn is counted from the start of the attempt that found the dark,
	// half a second of connect pacing before the park.
	pinDarkScout(t, darkScoutGap, pathDarkParkMax+500*time.Millisecond, darkEvidenceMin)
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	resetRevivalPacing()
	dials := stageRelayDials(t)
	entered := waitsOf(t, nil)
	h := runWorkersAgainstPeer(t, 147, 1, []string{relay.addr}, echoingPeer(t))
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	publishLookout(t, h.streams)

	dials.dark.Store(true)
	tried := dials.tried.Load()
	recycleAttempt(h.streams[0].attempt.Load())
	select {
	case w := <-entered:
		if !w.parked {
			t.Fatalf("the wait after a connect into the dark is %+v, want parked", w)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the worker never went into a wait")
	}
	parked := time.Now()
	waitFor(t, "a connect at the scout's turn", 3*time.Second, func() bool { return dials.tried.Load()-tried >= 2 })
	if took := time.Since(parked); took < pathDarkParkMax-200*time.Millisecond {
		t.Fatalf("the relay set was dialed again %v in, before the turn was due (%v), with the path still dark", took, pathDarkParkMax)
	}
}

// A burst of resets right after a blackout is VK's relays giving up on their own
// retransmissions: the light is back, and the redial goes at once even while
// the lookout still says dark.
func TestAResetIsNeverParked(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	front := startStallingFront(t, relay.addr)
	t.Cleanup(front.close)
	overTCP(t)
	resetRevivalPacing()
	entered := waitsOf(t, nil)
	h := runWorkersAgainstPeer(t, 148, 1, []string{front.addr}, echoingPeer(t))
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	publishLookout(t, h.streams)

	front.resetDownstream()
	select {
	case w := <-entered:
		if w.parked {
			t.Fatal("a worker whose session the relay reset was parked")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the worker never went into a wait")
	}
	waitFor(t, "the redial after the reset", 2*time.Second, func() bool { return front.accepted.Load() >= 2 })
}
