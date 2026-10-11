package main

import (
	"encoding/binary"
	"math/rand"
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

// samplesOf drops take's count of the losses placed on no relay.
func samplesOf(samples []relayLossSample, _ int) []relayLossSample { return samples }

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
	got, unplaced := tr.take(now.Add(time.Second))
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
	got, unplaced := tr.take(now.Add(time.Second))
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
