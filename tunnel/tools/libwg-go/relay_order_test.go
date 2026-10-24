package main

import (
	"math"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

func orderRelay(s relayOrderSample, relay string) relayOrderRelay {
	for _, r := range s.relays {
		if r.relay == relay {
			return r
		}
	}
	return relayOrderRelay{relay: relay}
}

// In order, nothing is late, nothing is a hole.
func TestRelayOrderInOrderIsNotLate(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	for ctr := uint64(0); ctr < 10000; ctr++ {
		relay := "A"
		if (ctr/8)%2 == 1 {
			relay = "B"
		}
		tr.observe(wgTransport(7, ctr), relay, now)
	}
	s := tr.take(now.Add(time.Minute))
	if s.got != 10000 || s.late != 0 || s.dup != 0 || s.neverCame != 0 || len(s.pairs) != 0 {
		t.Fatalf("got %+v, want 10000 in order", s)
	}
}

// Chunks of 8 dealt out to A and B in turn, every B chunk arriving after the
// A chunk behind it, 5 ms late: all of B is late, by 1 to 8 counters, each
// hole 5 ms old, and A overtakes B.
func TestRelayOrderMeasuresTheSlowerRelaysLag(t *testing.T) {
	start := time.Now()
	tr := newRelayOrder(start)
	at := start
	for chunk := uint64(0); chunk < 1000; chunk += 2 {
		b, a := chunk*8, (chunk+1)*8
		for i := uint64(0); i < 8; i++ {
			tr.observe(wgTransport(7, a+i), "A", at)
		}
		for i := uint64(0); i < 8; i++ {
			tr.observe(wgTransport(7, b+i), "B", at.Add(5*time.Millisecond))
		}
		at = at.Add(10 * time.Millisecond)
	}
	s := tr.take(at)
	if s.got != 8000 || s.late != 4000 || s.neverCame != 0 || s.dup != 0 {
		t.Fatalf("got %d late %d never came %d dup %d; want 8000, 4000, 0, 0", s.got, s.late, s.neverCame, s.dup)
	}
	if a, b := orderRelay(s, "A"), orderRelay(s, "B"); a.late != 0 || b.late != 4000 {
		t.Fatalf("late through A %d, B %d; want 0, 4000", a.late, b.late)
	}
	// B's chunk arrives with A's newest counter 8 above its last: lags 15..8.
	if s.lag.quantile(0) != 8 || s.lag.max != 15 || s.lateDupAcks != 4000 {
		t.Fatalf("lag min %d max %d, by 3+ %d; want 8, 15, 4000", s.lag.quantile(0), s.lag.max, s.lateDupAcks)
	}
	if p50 := s.hole.quantile(0.5); p50 < 4500 || p50 > 5000 {
		t.Fatalf("hole p50 %dµs, want ~5ms", p50)
	}
	if len(s.pairs) != 1 || s.pairs[0] != (relayOrderPair{ahead: "A", behind: "B", n: 4000}) {
		t.Fatalf("pairs %+v, want B overtaken by A 4000 times", s.pairs)
	}
}

// A duplicate is no late packet, and a counter that never comes is a hole
// written off once the window passes it.
func TestRelayOrderTellsDuplicatesAndHolesApart(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	for ctr := uint64(0); ctr < 3*relayOrderRing; ctr++ {
		if ctr == 100 || ctr == 200 {
			continue
		}
		tr.observe(wgTransport(7, ctr), "A", now)
		if ctr == 50 {
			tr.observe(wgTransport(7, 50), "A", now)
		}
	}
	s := tr.take(now)
	if s.dup != 1 || s.late != 0 || s.neverCame != 2 || s.got != 3*relayOrderRing-2 {
		t.Fatalf("got %+v; want 1 duplicate, 2 never came, nothing late", s)
	}
}

// A hole open past relayOrderHoleExpire when the window is taken never came;
// the counter turning up after that is not booked as late.
func TestRelayOrderWritesOffAnOldHole(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	for ctr := uint64(0); ctr < 100; ctr++ {
		if ctr != 40 {
			tr.observe(wgTransport(7, ctr), "A", now)
		}
	}
	if s := tr.take(now.Add(relayOrderHoleExpire / 2)); s.neverCame != 0 {
		t.Fatalf("young hole written off: %+v", s)
	}
	s := tr.take(now.Add(relayOrderHoleExpire))
	if s.neverCame != 1 {
		t.Fatalf("never came %d, want 1", s.neverCame)
	}
	tr.observe(wgTransport(7, 40), "A", now.Add(3*time.Second))
	if s := tr.take(now.Add(3 * time.Second)); s.late != 0 || s.afterWriteOff != 1 || s.got != 0 {
		t.Fatalf("got %+v; want the straggler after the write-off and nothing late", s)
	}
}

// Each keypair has its own counters: two receiver indexes interleaved are not
// reordering, and a counter older than the window is not booked as late.
func TestRelayOrderKeepsKeypairsApart(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	for ctr := uint64(0); ctr < 2000; ctr++ {
		tr.observe(wgTransport(1, 5000+ctr), "A", now)
		tr.observe(wgTransport(2, ctr), "B", now)
	}
	tr.observe(wgTransport(1, 100), "A", now)
	s := tr.take(now)
	if s.late != 0 || s.got != 4000 || s.neverCame != 0 || s.afterWriteOff != 1 {
		t.Fatalf("got %+v; want 4000 in order and one straggler past the window", s)
	}
}

// A new keypair's first counters can come in behind its next ones: holes from
// 0. A book started mid-keypair has no holes behind its first counter.
func TestRelayOrderStartsAKeypairAtZero(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	for _, ctr := range []uint64{3, 4, 0, 1, 2} {
		tr.observe(wgTransport(9, ctr), "A", now)
	}
	for _, ctr := range []uint64{90000, 89990} {
		tr.observe(wgTransport(10, ctr), "A", now)
	}
	if s := tr.take(now); s.late != 3 || s.got != 6 || s.neverCame != 0 {
		t.Fatalf("got %+v; want 3 of 6 late and no holes", s)
	}
}

// A run of counters longer than the window is written off whole.
func TestRelayOrderJumpPastTheWindow(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	tr.observe(wgTransport(7, 0), "A", now)
	tr.observe(wgTransport(7, 10), "A", now)
	tr.observe(wgTransport(7, 10+2*relayOrderRing), "A", now)
	tr.observe(wgTransport(7, 11+2*relayOrderRing), "A", now)
	// The 9 holes below 10, the relayOrderRing counters above them that never
	// got into the window, and its oldest hole, pushed out by the last counter.
	if s := tr.take(now); s.neverCame != 9+relayOrderRing+1 || s.got != 4 {
		t.Fatalf("got %+v", s)
	}
	tr.observe(wgTransport(7, 9+2*relayOrderRing), "B", now.Add(time.Millisecond))
	if s := tr.take(now); s.late != 1 || s.lag.max != 2 {
		t.Fatalf("got %+v; want a late counter lagging 2 inside the new window", s)
	}
}

func TestRelayOrderIgnoresAllButTransportMessages(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	hs := wgTransport(7, 1)
	hs[0] = 1
	tr.observe(hs, "A", now)
	tr.observe(wgTransport(7, 1)[:15], "A", now)
	tr.observe(wgTransport(7, 1), "", now)
	if s := tr.take(now); s.got != 0 {
		t.Fatalf("booked %+v", s)
	}
}

// A counter WireGuard never sends is not booked, whatever else the packet says:
// the top of uint64 used to send advanceLocked round for ever under the lock,
// with the counter's own packet unauthenticated yet (audit 2026-10-21).
func TestRelayOrderRejectsCountersWireGuardNeverSends(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.observe(wgTransport(7, math.MaxUint64), "A", now)
		tr.observe(wgTransport(7, device.RejectAfterMessages), "A", now)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("observe did not return: a counter at the top of uint64 spins advanceLocked for ever")
	}
	if s := tr.take(now); s.got != 0 {
		t.Fatalf("booked %+v; want nothing from counters past RejectAfterMessages", s)
	}
	// The last counter a peer may send is a counter like any other — and the
	// jump to it from a known book counts as holes that never came, saturated
	// rather than wrapped.
	tr.observe(wgTransport(7, 1000), "A", now)
	tr.observe(wgTransport(7, device.RejectAfterMessages-1), "A", now)
	if s := tr.take(now); s.got != 2 || s.neverCame <= 0 {
		t.Fatalf("got %+v; want both counters booked and a positive never-came count", s)
	}
}

func TestRelayOrderTakeStartsANewWindow(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	tr.observe(wgTransport(7, 1), "A", now)
	tr.observe(wgTransport(7, 0), "B", now)
	if s := tr.take(now.Add(time.Minute)); s.late != 1 || s.span != time.Minute {
		t.Fatalf("first window %+v", s)
	}
	tr.observe(wgTransport(7, 2), "A", now)
	s := tr.take(now.Add(2 * time.Minute))
	if s.got != 1 || s.late != 0 || len(s.pairs) != 0 || s.lag.n != 0 || orderRelay(s, "B").got != 0 {
		t.Fatalf("second window %+v", s)
	}
}

func TestRelayOrderLine(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	tr.observe(wgTransport(7, 4), "A", now)
	for ctr := uint64(0); ctr < 4; ctr++ {
		tr.observe(wgTransport(7, ctr), "B", now.Add(2*time.Millisecond))
	}
	got := tr.take(now.Add(10 * time.Second)).String()
	want := "last 10s: 5 packets, 80.00% late, 40.00% by 3+; lag p50 2 p95 4 p99 4 max 4; hole p50 2.0ms p95 2.0ms p99 2.0ms max 2.0ms; 0 duplicated, 0 never came, 0 after written off; late through A 0.00% of 1, B 100.00% of 4; overtaken: B by A 4"
	if got != want {
		t.Fatalf("line\n%s\nwant\n%s", got, want)
	}
	if line := tr.take(now.Add(20 * time.Second)).String(); strings.Contains(line, "lag") {
		t.Fatalf("empty window shows lag: %s", line)
	}
}

func TestRelayOrderHistQuantiles(t *testing.T) {
	var h relayOrderHist
	for v := uint64(1); v <= 1000; v++ {
		h.add(v)
	}
	for _, c := range []struct {
		q    float64
		want uint64
	}{{0.01, 10}, {0.5, 500}, {0.95, 950}, {0.99, 990}} {
		got := h.quantile(c.q)
		if d := float64(got) - float64(c.want); d > 0.0625*float64(c.want) || -d > 0.0625*float64(c.want) {
			t.Fatalf("q%.2f = %d, want within 6.25%% of %d", c.q, got, c.want)
		}
	}
	if h.max != 1000 || h.quantile(1) > 1000 {
		t.Fatalf("max %d, q1 %d", h.max, h.quantile(1))
	}
	for v := uint64(0); v < 1<<20; v = v*3 + 1 {
		i := histBucket(v)
		if f := histFloor(i); f > v || v >= f+histWidth(i) || histWidth(i) > max(1, f/8) {
			t.Fatalf("value %d in bucket [%d, %d)", v, f, f+histWidth(i))
		}
	}
}

// A counter that came off its socket first but took the lock second closes a
// hole of no age, not one of 2^64 microseconds.
func TestRelayOrderHoleOpenedAfterTheLateCounterCameIsNoAge(t *testing.T) {
	now := time.Now()
	tr := newRelayOrder(now)
	tr.observe(wgTransport(7, 1), "A", now.Add(time.Millisecond))
	tr.observe(wgTransport(7, 0), "B", now)
	if s := tr.take(now); s.late != 1 || s.hole.max != 0 {
		t.Fatalf("late %d, hole max %dµs; want 1, 0", s.late, s.hole.max)
	}
}

// The RX goroutines book a datagram in both books of the downlink — loss and
// order — under one lock, the header parsed once; what is no transport message
// reaches neither (review 2026-10-22).
func TestObserveDownlinkBooksBothUnderOneLock(t *testing.T) {
	if downlinkRelayLoss.mu != &downlinkMu || downlinkRelayOrder.mu != &downlinkMu {
		t.Fatal("the downlink's books are not under downlinkMu together")
	}
	now := time.Now()
	downlinkRelayLoss.reset()
	downlinkRelayOrder.reset(now)
	t.Cleanup(func() {
		downlinkRelayLoss.reset()
		downlinkRelayOrder.reset(time.Now())
	})
	for ctr := uint64(0); ctr < 10; ctr++ {
		observeDownlink(wgTransport(7, ctr), "A")
	}
	observeDownlink([]byte{1, 2, 3}, "A")
	observeDownlink(wgTransport(7, 10), "")
	samples, _ := downlinkRelayLoss.take(now.Add(time.Minute))
	if len(samples) != 1 || samples[0].relay != "A" || samples[0].rx != 10 || samples[0].lost != 0 {
		t.Fatalf("loss book: %+v, want 10 through A and nothing lost", samples)
	}
	if order := downlinkRelayOrder.take(now.Add(time.Minute)); order.got != 10 || order.late != 0 {
		t.Fatalf("order book: got %d late %d, want 10 in order", order.got, order.late)
	}
}

// A counter a peer never sends — RejectAfterMessages and up — books nothing in
// either book: in the loss book it moved the base so far that the ordinary
// counters after it went missing, and the loss judge's numbers with them
// (codex review of the iOS port, 22.10).
func TestACounterPastTheLimitBooksNothing(t *testing.T) {
	if _, _, ok := wgTransportHeader(wgTransport(7, ^uint64(0)), "relay-a:3478"); ok {
		t.Fatal("a counter at the top of uint64 was taken")
	}
	loss := newRelayLoss()
	now := time.Now()
	for _, ctr := range []uint64{0, ^uint64(0), 1} {
		loss.observe(wgTransport(7, ctr), "relay-a:3478", now)
	}
	samples, _ := loss.take(now.Add(time.Second))
	if len(samples) != 1 || samples[0].rx != 2 || samples[0].lost != 0 {
		t.Fatalf("samples %+v, want relay-a with the two ordinary packets and none lost", samples)
	}
}
