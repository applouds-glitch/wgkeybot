/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"strings"
	"testing"
	"time"
)

// hear has s hear n packets, the last at at.
func hear(s *stream, n int, at time.Time) {
	a := s.activity.Load()
	for i := 0; i < n; i++ {
		a.noteRx(at)
	}
}

// judgeEvery takes the judge's turns every tick after from, up to and
// including to, as the runner does — a turn skipped reads as a freeze to the
// judge, which is the point of its clock — with what happens on the streams at
// each moment (hear; nil for nothing) applied before the turn there. It
// returns everything the turns gave.
func judgeEvery(j *silentUnderLoadJudge, streams []*stream, from, to time.Time, hear func(t time.Time)) (verdicts []silentUnderLoadVerdict, back []silentUnderLoadReturn) {
	for t := from.Add(silentUnderLoadTick); !t.After(to); t = t.Add(silentUnderLoadTick) {
		if hear != nil {
			hear(t)
		}
		v, b := j.judge(streams, t)
		verdicts, back = append(verdicts, v...), append(back, b...)
	}
	return verdicts, back
}

// packetsATick is the load the tests put on a witness: three chunks by the
// tick the silence reaches silentUnderLoadAfter, nothing before that would
// convict.
var packetsATick = silentUnderLoadPackets / int(silentUnderLoadAfter/silentUnderLoadTick)

// siblingsHear is a load on streams 1 and 2 — n1 and n2 packets a tick, up to
// and including until — while stream 0 hears nothing.
func siblingsHear(streams []*stream, n1, n2 int, until time.Time) func(time.Time) {
	return func(t time.Time) {
		if t.After(until) {
			return
		}
		hear(streams[1], n1, t)
		hear(streams[2], n2, t)
	}
}

// loadedStreams is the field case in miniature: three ready streams whose
// sessions began at start, and a judge that has taken its first turn over
// them there.
func loadedStreams(start time.Time) ([]*stream, *silentUnderLoadJudge) {
	streams := []*stream{dispatchStream(0, true, start, 8), dispatchStream(1, true, start, 8), dispatchStream(2, true, start, 8)}
	j := newSilentUnderLoadJudge(len(streams))
	j.judge(streams, start)
	return streams, j
}

// The point of it: a stream silent for four seconds while two siblings have
// each heard three chunks since is stale at once — to the dispatcher and to the
// WGH1 mask — thirty seconds before the age rule, and the verdict is given once.
func TestSilentUnderLoadSkipsTheStreamItsSiblingsOuthear(t *testing.T) {
	start := time.Now()
	streams, j := loadedStreams(start)
	loaded := start.Add(silentUnderLoadAfter)
	at := loaded.Add(silentUnderLoadTick)

	verdicts, back := judgeEvery(j, streams, start, at, siblingsHear(streams, packetsATick, packetsATick, loaded))
	if len(verdicts) != 1 || len(back) != 0 {
		t.Fatalf("verdicts = %+v, back = %+v, want one verdict", verdicts, back)
	}
	v := verdicts[0]
	if v.id != 0 || v.index != 0 || v.silent != silentUnderLoadAfter || len(v.witnesses) != 2 || v.witnesses[0] != 1 || v.witnesses[1] != 2 || v.packets != 2*silentUnderLoadPackets {
		t.Fatalf("verdict = %+v, want stream 0 silent %v with witnesses 1 and 2 and %d packets", v, silentUnderLoadAfter, 2*silentUnderLoadPackets)
	}
	if !streams[0].dispatchStale(at) || streams[1].dispatchStale(at) || streams[2].dispatchStale(at) {
		t.Fatal("the verdict did not make stream 0 alone stale")
	}
	for _, want := range []string{"stream 0 silent 4s while siblings [1 2] got 48 packets", "skipped 31s before the 35s rule"} {
		if line := v.line(); !strings.Contains(line, want) {
			t.Fatalf("no %q in %q", want, line)
		}
	}

	if sent, _ := dispatchPacket(streams, 0, at, []byte{1}); !sent || queued(streams[0]) != 0 || queued(streams[1]) != 1 {
		t.Fatalf("the dispatcher did not pass stream 0 over: sent=%v, queued %d/%d", sent, queued(streams[0]), queued(streams[1]))
	}
	if again, _ := judgeEvery(j, streams, at, at.Add(2*silentUnderLoadTick), siblingsHear(streams, 1, 1, at.Add(time.Minute))); len(again) != 0 {
		t.Fatalf("the verdict was given again: %+v", again)
	}
}

// The verdict is the stream's silence: the next packet it hears lifts it at
// once, without a turn of the judge; the judge reports the return on its next
// turn, and a new silence under load is judged anew — with the siblings'
// packets counted from that packet on, not from the episode before.
func TestSilentUnderLoadVerdictEndsWithTheNextPacket(t *testing.T) {
	start := time.Now()
	streams, j := loadedStreams(start)
	loaded := start.Add(silentUnderLoadAfter)
	at := loaded.Add(silentUnderLoadTick)
	if v, _ := judgeEvery(j, streams, start, at, siblingsHear(streams, packetsATick, packetsATick, loaded)); len(v) != 1 {
		t.Fatal("setup: no verdict")
	}

	heard := at.Add(silentUnderLoadTick)
	hear(streams[0], 1, heard)
	if streams[0].dispatchStale(heard) {
		t.Fatal("a packet did not lift the verdict")
	}
	if streams[0].activity.Load().foundSilentUnderLoad() {
		t.Fatal("the verdict still stands after the packet")
	}
	v, back := judgeEvery(j, streams, at, heard, nil)
	if len(v) != 0 || len(back) != 1 || back[0].id != 0 || back[0].silent != heard.Sub(start) {
		t.Fatalf("verdicts = %+v, back = %+v, want the return of stream 0 after %v", v, back, heard.Sub(start))
	}

	// A new silence, under a lighter load from the packet on: two chunks a
	// witness by the time the silence is four seconds old would be three with
	// the first episode's chunks — and must not be.
	lighter := packetsATick - 1
	ticksToThree := (silentUnderLoadPackets + lighter - 1) / lighter
	convicted := heard.Add(time.Duration(ticksToThree) * silentUnderLoadTick)
	load := siblingsHear(streams, lighter, lighter, convicted)
	if _, back := judgeEvery(j, streams, heard, heard.Add(silentUnderLoadTick), load); len(back) != 0 {
		t.Fatalf("the return was reported again: %+v", back)
	}
	v, _ = judgeEvery(j, streams, heard.Add(silentUnderLoadTick), convicted.Add(-silentUnderLoadTick), load)
	if len(v) != 0 {
		t.Fatalf("judged on the first episode's chunks: %+v", v)
	}
	v, _ = judgeEvery(j, streams, convicted.Add(-silentUnderLoadTick), convicted, load)
	if len(v) != 1 || v[0].silent != convicted.Sub(heard) || !streams[0].dispatchStale(convicted) {
		t.Fatalf("verdicts = %+v, want one at %v of silence", v, convicted.Sub(heard))
	}
}

// A verdict ends with its session: a stream found silent and then replaced
// (the dead-stream detector, a move to another relay) has no return to report,
// and the new session starts clean.
func TestSilentUnderLoadVerdictEndsWithTheSession(t *testing.T) {
	start := time.Now()
	streams, j := loadedStreams(start)
	loaded := start.Add(silentUnderLoadAfter)
	at := loaded.Add(silentUnderLoadTick)
	if v, _ := judgeEvery(j, streams, start, at, siblingsHear(streams, packetsATick, packetsATick, loaded)); len(v) != 1 {
		t.Fatal("setup: no verdict")
	}
	next := at.Add(silentUnderLoadTick)
	streams[0].activity.Store(newStreamActivity(next, 0))
	if streams[0].dispatchStale(next) {
		t.Fatal("the verdict outlived the session")
	}
	if v, back := judgeEvery(j, streams, at, next.Add(silentUnderLoadTick), nil); len(v) != 0 || len(back) != 0 {
		t.Fatalf("verdicts = %+v, back = %+v, want nothing for a new session", v, back)
	}
}

// Each thing the verdict rests on, taken away: the load runs as in the field
// case but for the one thing.
func TestSilentUnderLoadNeedsTheSilenceTheWitnessesAndTheirPackets(t *testing.T) {
	type scene struct {
		to   time.Duration // after start
		hear func(streams []*stream, start time.Time) func(time.Time)
		// spoil, if any, is done to the streams before the first turn.
		spoil func(streams []*stream, start time.Time)
	}
	field := func(streams []*stream, start time.Time) func(time.Time) {
		return siblingsHear(streams, packetsATick, packetsATick, start.Add(silentUnderLoadAfter))
	}
	cases := map[string]scene{
		"silence short of the threshold": {
			to: silentUnderLoadAfter - silentUnderLoadTick,
			// Three chunks each well within the silence; only the silence is short.
			hear: func(streams []*stream, start time.Time) func(time.Time) {
				return siblingsHear(streams, silentUnderLoadPackets, silentUnderLoadPackets, start.Add(silentUnderLoadAfter))
			},
		},
		// A stream stale by age is the age rule's.
		"silent past the age rule": {
			to: silentUnderLoadAfter + silentUnderLoadTick, hear: field,
			spoil: func(streams []*stream, start time.Time) {
				streams[0].activity.Store(newStreamActivity(start.Add(-dispatchStaleAfter-time.Second), 0))
			},
		},
		"one witness only": {
			to: silentUnderLoadAfter + silentUnderLoadTick,
			hear: func(streams []*stream, start time.Time) func(time.Time) {
				return siblingsHear(streams, packetsATick, 0, start.Add(silentUnderLoadAfter))
			},
		},
		"a chunk short on one witness": {
			to: silentUnderLoadAfter + silentUnderLoadTick,
			hear: func(streams []*stream, start time.Time) func(time.Time) {
				return siblingsHear(streams, packetsATick, packetsATick-1, start.Add(silentUnderLoadAfter))
			},
		},
		// Packets alone are not a witness: the path must be alive now.
		"a witness not heard lately": {
			to: silentUnderLoadAfter + silentUnderLoadTick,
			hear: func(streams []*stream, start time.Time) func(time.Time) {
				return func(t time.Time) {
					if t.Equal(start.Add(silentUnderLoadTick)) {
						hear(streams[2], silentUnderLoadPackets, t) // and nothing since
					}
					if !t.After(start.Add(silentUnderLoadAfter)) {
						hear(streams[1], packetsATick, t)
					}
				}
			},
		},
		"a witness not ready": {
			to: silentUnderLoadAfter + silentUnderLoadTick, hear: field,
			spoil: func(streams []*stream, _ time.Time) { streams[2].ready.Store(false) },
		},
		"the silent one not ready": {
			to: silentUnderLoadAfter + silentUnderLoadTick, hear: field,
			spoil: func(streams []*stream, _ time.Time) { streams[0].ready.Store(false) },
		},
		// After a thaw every stream is equally silent; the post-wake probe asks.
		"a freeze in the silence": {
			to: silentUnderLoadAfter + silentUnderLoadTick, hear: field,
			spoil: func(streams []*stream, start time.Time) {
				streams[0].activity.Load().resetLiveness(start.Add(time.Second))
			},
		},
	}
	for name, c := range cases {
		start := time.Now()
		streams := []*stream{dispatchStream(0, true, start, 8), dispatchStream(1, true, start, 8), dispatchStream(2, true, start, 8)}
		if c.spoil != nil {
			c.spoil(streams, start)
		}
		j := newSilentUnderLoadJudge(len(streams))
		j.judge(streams, start)
		if v, _ := judgeEvery(j, streams, start, start.Add(c.to), c.hear(streams, start)); len(v) != 0 {
			t.Errorf("%s: judged anyway: %+v", name, v)
		}
		if a := streams[0].activity.Load(); a.foundSilentUnderLoad() {
			t.Errorf("%s: the stream was marked", name)
		}
	}
}

// Only what the siblings heard since the stream's last packet counts: what
// they had before it is no evidence, and a sibling in a new session since has
// heard everything since.
func TestSilentUnderLoadCountsFromTheStreamsLastPacket(t *testing.T) {
	start := time.Now()
	streams := []*stream{dispatchStream(0, true, start, 8), dispatchStream(1, true, start, 8), dispatchStream(2, true, start, 8)}
	hear(streams[1], 100, start)
	hear(streams[2], 100, start)
	j := newSilentUnderLoadJudge(len(streams))
	j.judge(streams, start)

	// Stream 1 hears two packets a tick: three chunks since the silence began
	// take twelve ticks, far past the four seconds — and a hundred were there
	// before. Stream 2 begins a new session at the second tick and hears four
	// a tick from then on: its count starts over, and nothing in it is from
	// before stream 0's silence.
	renewed := start.Add(2 * silentUnderLoadTick)
	load := func(t time.Time) {
		if t.Equal(renewed) {
			streams[2].activity.Store(newStreamActivity(t, 0))
		}
		hear(streams[1], 2, t)
		if t.After(renewed) {
			hear(streams[2], 4, t)
		}
	}
	convicted := start.Add(time.Duration(silentUnderLoadPackets/2) * silentUnderLoadTick)
	if v, _ := judgeEvery(j, streams, start, convicted.Add(-silentUnderLoadTick), load); len(v) != 0 {
		t.Fatalf("the hundred packets from before the silence counted: %+v", v)
	}
	v, _ := judgeEvery(j, streams, convicted.Add(-silentUnderLoadTick), convicted, load)
	ticksRenewed := int(convicted.Sub(renewed) / silentUnderLoadTick)
	if want := silentUnderLoadPackets + 4*ticksRenewed; len(v) != 1 || v[0].silent != convicted.Sub(start) || v[0].packets != want {
		t.Fatalf("verdict = %+v, want one at %v of silence with %d packets", v, convicted.Sub(start), want)
	}
}

// A turn that comes long after its tick is a freeze the loop never saw: the
// siblings' packets from before it are forgotten, and only chunks heard after
// the thaw can convict a stream still silent.
func TestSilentUnderLoadForgetsWhatCameBeforeAFreeze(t *testing.T) {
	start := time.Now()
	streams, j := loadedStreams(start)
	// Three chunks each before the silence is four seconds old, then the
	// freeze: nothing at the turn after it, although the silence is long.
	frozen := start.Add(silentUnderLoadAfter - silentUnderLoadTick)
	if v, _ := judgeEvery(j, streams, start, frozen, siblingsHear(streams, packetsATick+1, packetsATick+1, frozen)); len(v) != 0 {
		t.Fatalf("judged before the silence was long enough: %+v", v)
	}
	thaw := frozen.Add(10 * time.Second)
	if v, _ := j.judge(streams, thaw); len(v) != 0 {
		t.Fatalf("judged on the turn after a freeze: %+v", v)
	}
	// Three chunks each after the thaw convict; the verdict names the whole
	// silence and only the chunks since the thaw.
	loaded := thaw.Add(silentUnderLoadAfter)
	v, _ := judgeEvery(j, streams, thaw, loaded.Add(silentUnderLoadTick), siblingsHear(streams, packetsATick, packetsATick, loaded))
	if len(v) != 1 || v[0].silent != loaded.Sub(start) || v[0].packets != 2*silentUnderLoadPackets {
		t.Fatalf("verdicts = %+v, want one at %v of silence with %d packets", v, loaded.Sub(start), 2*silentUnderLoadPackets)
	}
}

// The watch of stale transitions leaves both lines of an early verdict to the
// judge — it has the witnesses and their packets, and sees the return on its
// own turn — while still counting the stream as stale; a stream stale by age
// keeps its lines here.
func TestStaleWatchLeavesTheEarlyVerdictLinesToTheJudge(t *testing.T) {
	start := time.Now()
	streams, j := loadedStreams(start)
	w := newStaleWatch(len(streams))
	w.observe(streams, start)
	loaded := start.Add(silentUnderLoadAfter)
	at := loaded.Add(silentUnderLoadTick)
	if v, _ := judgeEvery(j, streams, start, at, siblingsHear(streams, packetsATick, packetsATick, loaded)); len(v) != 1 {
		t.Fatal("setup: no verdict")
	}
	if lines := w.observe(streams, at); len(lines) != 0 {
		t.Fatalf("the watch spoke on the judge's verdict: %q", lines)
	}
	if !w.stale[0] {
		t.Fatal("the watch did not take the verdict as stale")
	}
	heard := at.Add(staleWatchInterval)
	hear(streams[0], 1, heard)
	if lines := w.observe(streams, heard); len(lines) != 0 {
		t.Fatalf("the watch spoke on the return the judge reports: %q", lines)
	}

	// Stale by age, as before: the watch's own lines, in and out.
	aged := heard.Add(dispatchStaleAfter + time.Second)
	hear(streams[1], 1, aged)
	hear(streams[2], 1, aged)
	lines := w.observe(streams, aged)
	if len(lines) != 1 || !strings.Contains(lines[0], "stream 0 silent for") {
		t.Fatalf("stale by age: got %q", lines)
	}
	hear(streams[0], 1, aged.Add(staleWatchInterval))
	lines = w.observe(streams, aged.Add(staleWatchInterval))
	if len(lines) != 1 || !strings.Contains(lines[0], "stream 0 heard its relay again") {
		t.Fatalf("return from age: got %q", lines)
	}
}

// The WGH1 report tells the server to skip the stream from the verdict on.
func TestFeedbackMaskDropsTheStreamFoundSilentUnderLoad(t *testing.T) {
	now := time.Now()
	deaf, good := feedbackTestStream(0, now), feedbackTestStream(1, now)
	a := deaf.activity.Load()
	a.markSilentUnderLoad(a.lastHeard.Load())
	var r downlinkReporter
	r.update([]*stream{deaf, good}, now)
	_, mask := readFeedbackReport(t, good)
	if mask.contains(0) || !mask.contains(1) || len(deaf.in) != 0 {
		t.Fatal("the report did not drop the stream found silent under load")
	}
}

// The measures against each other: the early rule sits well below the age
// rule and above a stream's way back into the rotation (the reporter's
// second, a round trip, a turn of the server's rotation); three chunks a
// witness are the server's chunk size; a verdict comes within a tick, and the
// tests' load of three chunks by the tick the silence is long enough divides.
func TestSilentUnderLoadThresholds(t *testing.T) {
	if silentUnderLoadAfter >= dispatchStaleAfter/4 {
		t.Fatalf("silentUnderLoadAfter %v gains too little on %v", silentUnderLoadAfter, dispatchStaleAfter)
	}
	if silentUnderLoadAfter < 3*time.Second {
		t.Fatalf("silentUnderLoadAfter %v is inside a readmitted stream's way back", silentUnderLoadAfter)
	}
	if silentUnderLoadPackets != 3*relayLossChunk || silentUnderLoadWitnesses < 2 {
		t.Fatalf("%d packets on %d witnesses: want three chunks of %d on at least two", silentUnderLoadPackets, silentUnderLoadWitnesses, relayLossChunk)
	}
	if silentUnderLoadEcho >= silentUnderLoadAfter || silentUnderLoadTick > time.Second {
		t.Fatalf("echo %v, tick %v: want the echo inside the silence and a turn at least every second", silentUnderLoadEcho, silentUnderLoadTick)
	}
	if ticks := int(silentUnderLoadAfter / silentUnderLoadTick); packetsATick*ticks != silentUnderLoadPackets {
		t.Fatalf("%d packets a tick over %d ticks is not %d", packetsATick, ticks, silentUnderLoadPackets)
	}
}
