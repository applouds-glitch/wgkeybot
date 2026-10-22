/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
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

// The judge is idle while no stream has heard three chunks since a take
// dispatchStaleAfter or more ago, which no witness of a turn could do without.
// A tunnel at rest hears keepalive echoes, one a stream per keepaliveInterval:
// idle on those; busy from a stream's three chunks for dispatchStaleAfter at
// the least after them, idle again within twice that; and a session begun
// since the take has heard all of its packets since — its own count, not a
// wrapped one.
func TestSilentUnderLoadJudgeIdlesOnKeepaliveEchoes(t *testing.T) {
	start := time.Now()
	streams, j := loadedStreams(start)
	if !j.idle {
		t.Fatal("busy on the first turn, with nothing heard")
	}
	at := start
	turn := func(d time.Duration, hear func(time.Time)) {
		at = at.Add(d)
		if hear != nil {
			hear(at)
		}
		j.judge(streams, at)
	}
	echoes := func(now time.Time) {
		for _, s := range streams {
			hear(s, 1, now)
		}
	}
	// Three minutes of echoes, a turn on each as the runner takes them.
	for at.Sub(start) < 3*time.Minute {
		turn(keepaliveInterval, echoes)
		if !j.idle {
			t.Fatalf("busy on keepalive echoes %v in", at.Sub(start))
		}
	}

	turn(time.Second, func(now time.Time) { hear(streams[1], silentUnderLoadPackets, now) })
	if j.idle {
		t.Fatal("idle with three chunks just heard")
	}
	chunks := at
	for !j.idle {
		turn(silentUnderLoadTick, nil)
		if at.Sub(chunks) > 2*dispatchStaleAfter+silentUnderLoadTick {
			t.Fatalf("still busy %v after the chunks", at.Sub(chunks))
		}
	}
	if since := at.Sub(chunks); since < dispatchStaleAfter {
		t.Fatalf("idle %v after the chunks, want %v at the least", since, dispatchStaleAfter)
	}

	// A new session on stream 1, with fewer packets than the take holds for
	// the old one.
	streams[1].activity.Store(newStreamActivity(at, 0))
	turn(time.Second, func(now time.Time) { hear(streams[1], silentUnderLoadPackets-1, now) })
	if !j.idle {
		t.Fatal("busy on a new session short of three chunks")
	}
	turn(time.Second, func(now time.Time) { hear(streams[1], 1, now) })
	if j.idle {
		t.Fatal("idle with a new session's three chunks")
	}
}

// A gap between idle turns is no freeze: idle, the judge turns on the packets
// heard, so none fell inside the gap, and what the siblings heard before it
// counts — the turn that finds their third chunk convicts with the two before.
func TestSilentUnderLoadIdleGapIsNoFreeze(t *testing.T) {
	start := time.Now()
	streams, j := loadedStreams(start)

	at := start.Add(silentUnderLoadAfter)
	hear(streams[1], 2*relayLossChunk, at)
	hear(streams[2], 2*relayLossChunk, at)
	if v, _ := j.judge(streams, at); len(v) != 0 || !j.idle {
		t.Fatalf("two chunks a witness: verdicts %+v, idle %v; want none and idle", v, j.idle)
	}

	at = at.Add(silentUnderLoadAfter)
	hear(streams[1], relayLossChunk, at)
	hear(streams[2], relayLossChunk, at)
	v, _ := j.judge(streams, at)
	if len(v) != 1 || v[0].id != 0 || v[0].silent != at.Sub(start) || v[0].packets != 2*silentUnderLoadPackets || j.idle {
		t.Fatalf("the third chunk %v later: verdicts %+v, idle %v; want stream 0 silent %v on %d packets, and busy",
			silentUnderLoadAfter, v, j.idle, at.Sub(start), 2*silentUnderLoadPackets)
	}
}

// A burst while idle — three chunks on two witnesses, then nothing — wakes the
// judge, which convicts on that turn: at a rarer tick instead the witnesses
// were out of the echo by the turn after (codex review 2026-10-22).
func TestSilentUnderLoadBurstWhileIdleConvictsAtOnce(t *testing.T) {
	start := time.Now()
	streams, j := loadedStreams(start)
	at := start.Add(silentUnderLoadAfter + silentUnderLoadTick/2)
	hear(streams[1], silentUnderLoadPackets, at)
	hear(streams[2], silentUnderLoadPackets, at)
	v, _ := j.judge(streams, at)
	if len(v) != 1 || v[0].id != 0 || v[0].silent != at.Sub(start) || j.idle {
		t.Fatalf("the turn on the burst: verdicts %+v, idle %v; want stream 0 silent %v and busy", v, j.idle, at.Sub(start))
	}
}

// The row of a stream heard while idle is taken on that packet — the judge
// turns on it — not at a later tick with the siblings' chunks since already in
// it (codex review 2026-10-22: a 2 s tick took the row with the whole burst
// inside, and the episode went without a verdict).
func TestSilentUnderLoadRowIsTakenOnTheStreamsOwnPacket(t *testing.T) {
	start := time.Now()
	streams, j := loadedStreams(start)
	heard := start.Add(100 * time.Millisecond)
	hear(streams[0], 1, heard)
	j.judge(streams, heard)
	burst := start.Add(750 * time.Millisecond)
	hear(streams[1], silentUnderLoadPackets, burst)
	hear(streams[2], silentUnderLoadPackets, burst)
	if v, _ := j.judge(streams, burst); len(v) != 0 || j.idle {
		t.Fatalf("on the burst: verdicts %+v, idle %v; want none yet, and busy", v, j.idle)
	}

	// Ticking from the burst: one packet more a witness, and the silence
	// reaching four seconds — the verdict counts the burst.
	more := burst.Add(6 * silentUnderLoadTick)
	v, _ := judgeEvery(j, streams, burst, burst.Add(7*silentUnderLoadTick), func(now time.Time) {
		if now.Equal(more) {
			hear(streams[1], 1, now)
			hear(streams[2], 1, now)
		}
	})
	convicted := burst.Add(7 * silentUnderLoadTick)
	if len(v) != 1 || v[0].id != 0 || v[0].silent != convicted.Sub(heard) || v[0].packets != 2*(silentUnderLoadPackets+1) {
		t.Fatalf("verdicts %+v; want stream 0 silent %v on %d packets", v, convicted.Sub(heard), 2*(silentUnderLoadPackets+1))
	}
}

// The runner, in real time: a first turn at once, none while the tunnel
// rests, one on a packet heard while idle, one on a stream come ready, and
// ticks once a stream has three chunks since the take — with room for the
// scheduler.
func TestSilentUnderLoadRunnerRestsWithTheTunnel(t *testing.T) {
	select {
	case <-silentUnderLoadWake: // a token left by another test's packets
	default:
	}
	start := time.Now()
	streams := []*stream{dispatchStream(0, true, start, 8), dispatchStream(1, true, start, 8), dispatchStream(2, false, start, 8)}
	j := newSilentUnderLoadJudge(len(streams))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		j.run(ctx, streams)
	}()
	defer func() {
		cancel()
		<-done
	}()
	turnsReach := func(n uint64) bool {
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if j.turns.Load() >= n {
				return true
			}
		}
		return false
	}

	if !turnsReach(1) {
		t.Fatal("no first turn")
	}
	time.Sleep(4 * silentUnderLoadTick)
	if n := j.turns.Load(); n != 1 {
		t.Fatalf("%d turns with nothing heard, want the first alone", n)
	}
	hear(streams[1], 1, time.Now())
	if !turnsReach(2) {
		t.Fatal("a packet heard while idle did not wake the judge")
	}
	time.Sleep(4 * silentUnderLoadTick)
	if n := j.turns.Load(); n != 2 {
		t.Fatalf("%d turns after one packet, want two: no tick while idle", n)
	}
	// A stream's proof is heard before it is ready (NoDTLS): the turn on the
	// packet finds it not ready, and coming ready wakes the judge again.
	hear(streams[2], 1, time.Now())
	if !turnsReach(3) {
		t.Fatal("a packet on a stream not ready did not wake the judge")
	}
	streams[2].ready.Store(true)
	wakeSilentUnderLoadJudge()
	if !turnsReach(4) {
		t.Fatal("a stream come ready did not wake the judge")
	}
	hear(streams[1], silentUnderLoadPackets, time.Now())
	if !turnsReach(5) {
		t.Fatal("three chunks did not wake the judge")
	}
	time.Sleep(4 * silentUnderLoadTick)
	if n := j.turns.Load(); n < 7 {
		t.Fatalf("%d turns in %v of three chunks since the take, want ticks", n, 4*silentUnderLoadTick)
	}
}

// A freeze while the judge is idle — no tick of its own to come late — is told
// by the WGH1 reporter's second: a turn of the reporter's that came late since
// the judge's last turn, or none at all for that long, resets the rows as a
// late tick does, so what the witnesses had before the freeze counts for
// nothing (codex review 2026-10-22). The reporter's clock quiet, a gap is a
// quiet spell, and what came before it counts. Under the tick the judge's own
// clock rules: a reporter late on its own resets nothing.
func TestSilentUnderLoadIdleFreezeIsToldByTheReportersClock(t *testing.T) {
	seconds := func(from, to time.Time) {
		for at := from; !at.After(to); at = at.Add(time.Second) {
			noteReporterTurn(at)
		}
	}
	// The witnesses a packet short of three chunks at last, the judge idle on
	// them; the gap; the packet more a witness at now, and the judge's turn on
	// it — with the reporter's turns in between as each case has them.
	cases := map[string]struct {
		reporter func(start, last, now time.Time)
		froze    bool
	}{
		"the reporter has not turned since the judge's last turn": {func(start, last, now time.Time) {
			startReporterClock(start)
		}, true},
		"the reporter's first second came after the thaw": {func(start, last, now time.Time) {
			startReporterClock(start)
			noteReporterTurn(now.Add(-50 * time.Millisecond))
		}, true},
		"the reporter turned on time throughout": {func(start, last, now time.Time) {
			startReporterClock(start)
			seconds(start.Add(time.Second), now)
		}, false},
		"the reporter was late once, before the judge's last turn": {func(start, last, now time.Time) {
			startReporterClock(start.Add(-3 * time.Second))
			noteReporterTurn(start) // two seconds late: a freeze, before last
			seconds(start.Add(time.Second), now)
		}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { silentUnderLoadClock.Store(nil) })
			start := time.Now()
			streams, j := loadedStreams(start)
			last := start.Add(500 * time.Millisecond)
			hear(streams[1], silentUnderLoadPackets-1, last)
			hear(streams[2], silentUnderLoadPackets-1, last)
			if v, _ := j.judge(streams, last); len(v) != 0 || !j.idle {
				t.Fatalf("setup: verdicts %+v, idle %v", v, j.idle)
			}
			now := last.Add(silentUnderLoadAfter + 100*time.Millisecond)
			c.reporter(start, last, now)
			hear(streams[1], 1, now)
			hear(streams[2], 1, now)
			v, _ := j.judge(streams, now)
			if got := len(v) == 0; got != c.froze {
				t.Fatalf("verdicts %+v; want a freeze %v", v, c.froze)
			}
			if !c.froze {
				return
			}
			// The rows taken afresh at the thaw: three chunks a witness from
			// there convict, with those alone.
			later := now.Add(silentUnderLoadTick)
			noteReporterTurn(later)
			hear(streams[1], silentUnderLoadPackets, later)
			hear(streams[2], silentUnderLoadPackets, later)
			v, _ = j.judge(streams, later)
			if len(v) != 1 || v[0].id != 0 || v[0].packets != 2*silentUnderLoadPackets {
				t.Fatalf("after the thaw: verdicts %+v; want stream 0 on %d packets", v, 2*silentUnderLoadPackets)
			}
		})
	}

	t.Run("under the tick the judge's own clock rules", func(t *testing.T) {
		t.Cleanup(func() { silentUnderLoadClock.Store(nil) })
		start := time.Now()
		streams, j := loadedStreams(start)
		startReporterClock(start)
		noteReporterTurn(start.Add(time.Second))
		// Three chunks a witness on the first tick and a packet more on each
		// after, the judge ticking all along; the reporter stalled on its own
		// from its second on. The verdict comes as the silence reaches four
		// seconds, on everything the witnesses heard.
		loaded := start.Add(silentUnderLoadAfter)
		v, _ := judgeEvery(j, streams, start, loaded, func(now time.Time) {
			n := 1
			if now.Equal(start.Add(silentUnderLoadTick)) {
				n = silentUnderLoadPackets
			}
			hear(streams[1], n, now)
			hear(streams[2], n, now)
		})
		ticks := int(silentUnderLoadAfter / silentUnderLoadTick)
		if len(v) != 1 || v[0].silent != silentUnderLoadAfter || v[0].packets != 2*(silentUnderLoadPackets+ticks-1) {
			t.Fatalf("verdicts %+v; want stream 0 silent %v on %d packets", v, silentUnderLoadAfter, 2*(silentUnderLoadPackets+ticks-1))
		}
	})
}

// One freeze is one freeze: seen stale on the judge's turn before the
// reporter's, the reporter's late turn that marks it afterwards resets nothing
// again — the witnesses' chunks since the first reset convict (codex review
// 2026-10-22). And the next freeze is the next: seen again.
func TestSilentUnderLoadTakesAGapForAFreezeOnce(t *testing.T) {
	t.Cleanup(func() { silentUnderLoadClock.Store(nil) })
	start := time.Now()
	streams, j := loadedStreams(start)
	startReporterClock(start)

	// The freeze, the judge first after it on a packet a witness, the reporter
	// marking it a moment later, then the witnesses' three chunks.
	thaw := start.Add(silentUnderLoadAfter + 600*time.Millisecond)
	hear(streams[1], 1, thaw)
	hear(streams[2], 1, thaw)
	if v, _ := j.judge(streams, thaw); len(v) != 0 || !j.idle {
		t.Fatalf("at the thaw: verdicts %+v, idle %v", v, j.idle)
	}
	noteReporterTurn(thaw.Add(50 * time.Millisecond))
	chunks := thaw.Add(100 * time.Millisecond)
	hear(streams[1], silentUnderLoadPackets, chunks)
	hear(streams[2], silentUnderLoadPackets, chunks)
	// (The packet a witness at the thaw went into the rows taken afresh there.)
	v, _ := j.judge(streams, chunks)
	if len(v) != 1 || v[0].id != 0 || v[0].packets != 2*silentUnderLoadPackets {
		t.Fatalf("after the mark of the freeze already taken: verdicts %+v; want stream 0 on %d packets", v, 2*silentUnderLoadPackets)
	}

	// Heard again, silent again, and a second freeze with chunks before it:
	// that one resets.
	heard := chunks.Add(time.Second)
	hear(streams[0], 1, heard)
	noteReporterTurn(heard)
	j.judge(streams, heard)
	before := heard.Add(500 * time.Millisecond)
	hear(streams[1], silentUnderLoadPackets-1, before)
	hear(streams[2], silentUnderLoadPackets-1, before)
	if v, _ := j.judge(streams, before); len(v) != 0 {
		t.Fatalf("before the second freeze: verdicts %+v", v)
	}
	again := before.Add(silentUnderLoadAfter + 100*time.Millisecond)
	hear(streams[1], 1, again)
	hear(streams[2], 1, again)
	if v, _ := j.judge(streams, again); len(v) != 0 {
		t.Fatalf("the second freeze, the reporter not turned since: verdicts %+v; want none", v)
	}
}

// A reporter left running by a Stop that timed out publishes nothing over the
// clock the next proxy started: its turn, read before that start, is dropped.
func TestAStoppedProxysReporterLeavesTheNextOnesClockAlone(t *testing.T) {
	t.Cleanup(func() { silentUnderLoadClock.Store(nil) })
	start := time.Now()
	startReporterClock(start)
	old := silentUnderLoadClock.Load()
	restarted := start.Add(10 * time.Second)
	startReporterClock(restarted)
	if reporterTurn(old, restarted.Add(time.Second)) {
		t.Fatal("the old reporter's turn was published over the new clock")
	}
	if c := silentUnderLoadClock.Load(); !c.turn.Equal(restarted) || !c.froze.IsZero() {
		t.Fatalf("clock %+v; want the new proxy's start untouched", c)
	}
	if !reporterTurn(silentUnderLoadClock.Load(), restarted.Add(time.Second)) {
		t.Fatal("the new reporter's own turn was not published")
	}
}
