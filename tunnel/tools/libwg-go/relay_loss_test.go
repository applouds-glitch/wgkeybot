package main

import (
	"encoding/binary"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func wgTransport(receiver uint32, ctr uint64) []byte {
	b := make([]byte, 32)
	b[0] = 4
	binary.LittleEndian.PutUint32(b[4:8], receiver)
	binary.LittleEndian.PutUint64(b[8:16], ctr)
	return b
}

// samplesOf drops take's count of the losses placed on no relay, and its span.
func samplesOf(samples []relayLossSample, _ int, _ relayLossSpan) []relayLossSample { return samples }

func lossOf(samples []relayLossSample, relay string) relayLossSample {
	for _, s := range samples {
		if s.relay == relay {
			return s
		}
	}
	return relayLossSample{relay: relay}
}

// The server hands the downlink out in chunks of 8 consecutive counters, one
// stream at a time; a counter dropped inside a chunk is charged to that
// chunk's relay.
func TestRelayLossChargesGapsToTheChunksRelay(t *testing.T) {
	tr := newRelayLoss()
	now := time.Now()
	dropped := 0
	for ctr := uint64(0); ctr < 8000; ctr++ {
		relay := "A"
		if (ctr/8)%2 == 1 {
			relay = "B"
		}
		// Drop one counter in the middle of every B chunk: 1 in 8 of B.
		if relay == "B" && ctr%8 == 4 {
			dropped++
			continue
		}
		tr.observe(wgTransport(7, ctr), relay, now)
	}
	got := samplesOf(tr.take(now.Add(time.Second))) // idle flush settles the tail
	a, b := lossOf(got, "A"), lossOf(got, "B")
	if a.lost != 0 {
		t.Fatalf("A charged with %d losses", a.lost)
	}
	if b.lost != dropped || b.rx != 4000-dropped {
		t.Fatalf("B = %+v, want %d lost of 4000", b, dropped)
	}
}

// The book counts the gaps a relay's losses came in apart from the packets: a
// run of three is three lost in one hole, two single drops are two in two.
func TestRelayLossCountsHolesApartFromPackets(t *testing.T) {
	tr := newRelayLoss()
	now := time.Now()
	for ctr := uint64(0); ctr < 800; ctr++ {
		relay := "A"
		if (ctr/8)%2 == 1 {
			relay = "B"
		}
		switch {
		case relay == "A" && ctr%8 >= 2 && ctr%8 <= 4: // one run of three per A chunk
			continue
		case relay == "B" && (ctr%8 == 2 || ctr%8 == 5): // two single drops per B chunk
			continue
		}
		tr.observe(wgTransport(7, ctr), relay, now)
	}
	got := samplesOf(tr.take(now.Add(time.Second)))
	a, b := lossOf(got, "A"), lossOf(got, "B")
	if a.lost != 150 || a.holes != 50 {
		t.Fatalf("A = %+v, want 150 lost in 50 holes", a)
	}
	if b.lost != 100 || b.holes != 100 {
		t.Fatalf("B = %+v, want 100 lost in 100 holes", b)
	}
	if again := samplesOf(tr.take(now.Add(2 * time.Second))); len(again) != 0 {
		t.Fatalf("the next window starts with %+v", again)
	}
}

// An outage on the phone's own link loses a run of counters through every relay.
// The relay of the chunk before it says nothing about whose they were, so the
// run is placed on no relay — not charged whole to that relay, which made a
// clean relay look bad, nor shared out by what each delivered, which blamed the
// relay still delivering for one gone dark.
func TestRelayLossLeavesGapsItCannotPlaceUnplaced(t *testing.T) {
	tr := newRelayLoss()
	now := time.Now()
	outage, short := 0, 0
	for ctr := uint64(0); ctr < 8000; ctr++ {
		relay := "A"
		if (ctr/8)%2 == 1 {
			relay = "B"
		}
		// Forty counters in a row every 800, after a B chunk.
		if ctr%800 >= 400 && ctr%800 < 440 {
			outage++
			continue
		}
		// And B's own loss: one counter in the middle of each of its chunks.
		if relay == "B" && ctr%8 == 4 {
			short++
			continue
		}
		tr.observe(wgTransport(7, ctr), relay, now)
	}
	got, unplaced, _ := tr.take(now.Add(time.Second))
	if a := lossOf(got, "A"); a.lost != 0 {
		t.Fatalf("A charged with %d losses", a.lost)
	}
	if b := lossOf(got, "B"); b.lost != short {
		t.Fatalf("B lost %d, want its own %d", b.lost, short)
	}
	if unplaced != outage {
		t.Fatalf("unplaced %d, want the outage, %d", unplaced, outage)
	}
}

// A short gap between counters of two relays is a chunk's tail or the next
// chunk's head: placed on neither.
func TestRelayLossLeavesAChunkBoundaryUnplaced(t *testing.T) {
	tr := newRelayLoss()
	now := time.Now()
	for ctr := uint64(0); ctr < 16; ctr++ {
		relay := "A"
		if ctr >= 8 {
			relay = "B"
		}
		if ctr == 8 { // the head of B's chunk
			continue
		}
		tr.observe(wgTransport(7, ctr), relay, now)
	}
	got, unplaced, _ := tr.take(now.Add(time.Second))
	if a, b := lossOf(got, "A"), lossOf(got, "B"); a.lost != 0 || b.lost != 0 || unplaced != 1 {
		t.Fatalf("A lost %d, B lost %d, unplaced %d; want 0, 0, 1", a.lost, b.lost, unplaced)
	}
}

// Arrival shuffled within the horizon is not loss.
func TestRelayLossShuffledArrivalIsNotLoss(t *testing.T) {
	tr := newRelayLoss()
	now := time.Now()
	order := make([]uint64, 5000)
	for i := range order {
		order[i] = uint64(i)
	}
	rng := rand.New(rand.NewSource(1))
	// Shuffle within blocks of 300: no counter is displaced by 300 or more.
	for start := 0; start < len(order); start += 300 {
		block := order[start:min(start+300, len(order))]
		rng.Shuffle(len(block), func(i, j int) { block[i], block[j] = block[j], block[i] })
	}
	for _, ctr := range order {
		tr.observe(wgTransport(1, ctr), "A", now)
	}
	a := lossOf(samplesOf(tr.take(now.Add(time.Second))), "A")
	if a.lost != 0 || a.rx != 5000 {
		t.Fatalf("A = %+v, want 5000 received and nothing lost", a)
	}
}

// A rekey starts a new receiver index at counter 0; what the old keypair still
// owed is settled, its stragglers are ignored and nothing is charged twice.
func TestRelayLossNewKeypairStartsOver(t *testing.T) {
	tr := newRelayLoss()
	now := time.Now()
	for ctr := uint64(0); ctr < 3000; ctr++ {
		tr.observe(wgTransport(1, ctr), "A", now)
	}
	for ctr := uint64(0); ctr < 3000; ctr++ {
		tr.observe(wgTransport(2, ctr), "B", now)
		if ctr == 10 {
			tr.observe(wgTransport(1, 2999), "A", now) // straggler of the old keypair
		}
	}
	got := samplesOf(tr.take(now.Add(time.Second)))
	if a := lossOf(got, "A"); a.rx != 3000 || a.lost != 0 {
		t.Fatalf("A = %+v", a)
	}
	if b := lossOf(got, "B"); b.rx != 3000 || b.lost != 0 {
		t.Fatalf("B = %+v", b)
	}
}

// A keypair that carried only a few packets — an idle tunnel's — has
// stragglers with counters as low as a new keypair's. One arriving after the
// rekey must not switch the book back to the keypair left, or every packet of
// the current one reads as a straggler until the next rekey.
func TestRelayLossIgnoresALowStragglerOfTheKeypairLeft(t *testing.T) {
	tr := newRelayLoss()
	now := time.Now()
	for ctr := uint64(0); ctr < 32; ctr++ {
		tr.observe(wgTransport(1, ctr), "A", now)
	}
	for ctr := uint64(0); ctr < 3000; ctr++ {
		tr.observe(wgTransport(2, ctr), "B", now)
		if ctr == 2048 {
			tr.observe(wgTransport(1, 31), "A", now) // late, through the slower relay
		}
	}
	got := samplesOf(tr.take(now.Add(time.Second)))
	if b := lossOf(got, "B"); b.rx != 3000 || b.lost != 0 {
		t.Fatalf("B = %+v, want all 3000 of the current keypair and nothing lost", b)
	}
	if a := lossOf(got, "A"); a.rx != 32 || a.lost != 0 {
		t.Fatalf("A = %+v, want the 32 of the old keypair counted once", a)
	}
}

func TestRelayLossIgnoresAllButTransportMessages(t *testing.T) {
	tr := newRelayLoss()
	now := time.Now()
	init := make([]byte, 148)
	init[0] = 1
	tr.observe(init, "A", now)
	tr.observe(stunBindingIndication, "A", now)
	tr.observe(wgTransport(1, 0), "", now)
	if got := samplesOf(tr.take(now.Add(time.Second))); len(got) != 0 {
		t.Fatalf("counted %+v", got)
	}
}

// Windows do not overlap: what take returned is not returned again.
func TestRelayLossTakeStartsANewWindow(t *testing.T) {
	tr := newRelayLoss()
	now := time.Now()
	for ctr := uint64(0); ctr < 2000; ctr++ {
		tr.observe(wgTransport(1, ctr), "A", now)
	}
	first := lossOf(samplesOf(tr.take(now)), "A") // not idle: only what is past the horizon
	if first.rx != 2000-relayLossHorizon {
		t.Fatalf("first window rx = %d, want %d", first.rx, 2000-relayLossHorizon)
	}
	second := lossOf(samplesOf(tr.take(now.Add(time.Second))), "A")
	if second.rx != relayLossHorizon || second.lost != 0 {
		t.Fatalf("second window = %+v", second)
	}
}

func TestRelayLossResetStartsClean(t *testing.T) {
	tr := newRelayLoss()
	now := time.Now()
	for ctr := uint64(0); ctr < 2000; ctr += 2 { // every other counter lost
		tr.observe(wgTransport(1, ctr), "A", now)
	}
	tr.reset()
	if got := samplesOf(tr.take(now.Add(time.Second))); len(got) != 0 {
		t.Fatalf("after reset: %+v", got)
	}
	for ctr := uint64(0); ctr < 100; ctr++ {
		tr.observe(wgTransport(9, ctr), "B", now)
	}
	if b := lossOf(samplesOf(tr.take(now.Add(time.Second))), "B"); b.rx != 100 || b.lost != 0 {
		t.Fatalf("B after reset = %+v", b)
	}
}

// active counts the distinct seconds of the window with traffic through a relay.
func TestRelayLossCountsActiveSeconds(t *testing.T) {
	tr := newRelayLoss()
	t0 := time.Unix(1_700_000_000, 0)
	ctr := uint64(0)
	for sec := 0; sec < 10; sec++ {
		// A every second, B in seconds 0, 3, 6 and 9 only.
		for i := 0; i < 100; i++ {
			tr.observe(wgTransport(1, ctr), "A", t0.Add(time.Duration(sec)*time.Second+time.Duration(i)*time.Millisecond))
			ctr++
		}
		if sec%3 == 0 {
			tr.observe(wgTransport(1, ctr), "B", t0.Add(time.Duration(sec)*time.Second+500*time.Millisecond))
			ctr++
		}
	}
	got := samplesOf(tr.take(t0.Add(11 * time.Second)))
	if a, b := lossOf(got, "A"), lossOf(got, "B"); a.active != 10 || b.active != 4 {
		t.Fatalf("active seconds A=%d B=%d, want 10 and 4", a.active, b.active)
	}
	if got := samplesOf(tr.take(t0.Add(12 * time.Second))); len(got) != 0 {
		t.Fatalf("a new window carried the old one over: %+v", got)
	}
}

// What a take returns is what became final, and its span is the time that
// covers. The field log of 2026-11-09: a trickle that left no pause of
// relayLossIdleFlush before three takes in a row printed no loss line for
// them, and the fourth printed all four windows' packets as "last 10s".
func TestRelayLossTakeSaysWhatTimeItsNumbersCover(t *testing.T) {
	tr := newRelayLoss()
	t0 := time.Unix(1_700_000_000, 0)
	at := func(d time.Duration) time.Time { return t0.Add(d) }

	// A packet every 400 ms for 30 s, then nothing.
	ctr := uint64(0)
	feed := func(upTo time.Duration) {
		for d := time.Duration(ctr) * 400 * time.Millisecond; d <= upTo; d += 400 * time.Millisecond {
			tr.observe(wgTransport(1, ctr), "A", at(d))
			ctr++
		}
	}
	for _, sec := range []int{10, 20, 30} {
		now := time.Duration(sec) * time.Second
		feed(now)
		got, _, span := tr.take(at(now))
		if len(got) != 0 || span.over != 0 || span.ago != now {
			t.Fatalf("take at %v, the tail not final: %+v over %v ending %v ago; want nothing, 0 and %v", now, got, span.over, span.ago, now)
		}
	}
	got, _, span := tr.take(at(40 * time.Second))
	if a := lossOf(got, "A"); a.rx != int(ctr) || a.lost != 0 {
		t.Fatalf("after the pause: %+v, want all %d delivered", a, ctr)
	}
	if span.over != 40*time.Second || span.ago != 0 {
		t.Fatalf("after the pause: over %v ending %v ago, want 40s and 0", span.over, span.ago)
	}

	// An ordinary window after it covers itself.
	tr.observe(wgTransport(1, ctr), "A", at(43*time.Second))
	if _, _, span := tr.take(at(50 * time.Second)); span.over != 10*time.Second || span.ago != 0 {
		t.Fatalf("an ordinary window: over %v ending %v ago, want 10s and 0", span.over, span.ago)
	}
}

// Steady traffic too slow to pass the horizon within a window is booked a
// horizon late: each take covers one window's worth, ending that far back, and
// neither grows.
func TestRelayLossSpanOfSteadyTrafficBehindTheHorizon(t *testing.T) {
	tr := newRelayLoss()
	t0 := time.Unix(1_700_000_000, 0)
	const every = 20 * time.Millisecond // 50 packets a second: the horizon is 20.48 s
	lag := relayLossHorizon * every
	ctr := uint64(0)
	for sec := 10; sec <= 100; sec += 10 {
		now := time.Duration(sec) * time.Second
		for d := time.Duration(ctr) * every; d <= now; d += every {
			tr.observe(wgTransport(1, ctr), "A", t0.Add(d))
			ctr++
		}
		got, _, span := tr.take(t0.Add(now))
		if sec < 40 {
			continue // the first windows fill the horizon
		}
		if a := lossOf(got, "A"); a.rx != 500 || a.lost != 0 {
			t.Fatalf("take at %v: %+v, want 500 delivered", now, a)
		}
		if span.over != 10*time.Second || span.ago != lag {
			t.Fatalf("take at %v: over %v ending %v ago, want 10s and %v", now, span.over, span.ago, lag)
		}
	}
}

// The line says "last 10s" for a window that is one, and what its numbers
// cover when they are not the window's: the rates are over that time too.
func TestRelayLossLineSaysWhatItCovers(t *testing.T) {
	for _, c := range []struct {
		span     relayLossSpan
		want     string
		wantOver time.Duration
	}{
		{relayLossSpan{over: 10*time.Second + 2*time.Millisecond}, "10s", 10 * time.Second},
		// The horizon at speed: 0.7 s of a 16 Mbit/s download.
		{relayLossSpan{over: 9990 * time.Millisecond, ago: 700 * time.Millisecond}, "10s", 10 * time.Second},
		{relayLossSpan{over: 40 * time.Second}, "40s", 40 * time.Second},
		{relayLossSpan{over: 10 * time.Second, ago: 20480 * time.Millisecond}, "10s (ending 20s ago)", 10 * time.Second},
		{relayLossSpan{over: 300 * time.Millisecond}, "1s", time.Second},
	} {
		if got, over := relayLossLineSpan(c.span); got != c.want || over != c.wantOver {
			t.Errorf("%+v: %q over %v, want %q over %v", c.span, got, over, c.want, c.wantOver)
		}
	}
	samples := []relayLossSample{{relay: "A", rx: 240}}
	if got := formatRelayLoss(samples, map[string]int{"A": 3}, 40*time.Second); !strings.Contains(got, "(3 streams, 2/s each)") {
		t.Fatalf("240 packets over 40 s on 3 streams: %q", got)
	}
}
