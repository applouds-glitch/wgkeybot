/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"slices"
	"sync"
	"time"
)

// The dark that outlives its lookout, and the one worker at a time that dials
// it.
//
// Periodic-download runs on 18.10 (Rostelecom on Tele2's 3G, TCP): the radio
// path went dark for about two minutes at a time, three times an hour, with
// Android none the wiser. The workers parked on the lookout (path_revival.go) —
// but the lookout is the stalled sockets, and relayTCPUserTimeout gives the
// last of them up 30s in. With no socket stalled any more the path no longer
// looked dark, every parked worker was let go into it, and for the next ninety
// seconds ten workers redialed, each attempt racing all six relays: sixty SYNs a
// round, streaks running up to 23s backoffs, and every Allocate that got
// through in a flicker of light a ghost on its relay once the next dark took it
// (17.10: six). Over UDP nothing stalls, so nothing ever parked.
//
// So a dark, once found, holds until a relay is heard over its transport
// (relayHeardMark: a connect accepted or refused, anything read from a relay's
// socket), a stream over it hears its relay, a session's proof
// (notePathProven), a move to another network or transport, or a proxy start.
// It is found by the lookout as before, or by an attempt of a worker's own that
// failed the dark's way (parksInTheDark) after darkEvidenceMin at least, no
// relay heard over its transport while it ran and no stream over it heard its
// relay for darkUpQuiet: its race had dialed its relays and none answered, nor
// anything else. An attempt that fails at once — the phone's own network
// refusing it — is no evidence of a dark, and joins one only if it is found.
//
// While it holds, the workers that fail into it wait in line, and the one at
// its head dials it — the scout — no sooner than darkScoutPeriod after the last
// scout attempt began and darkScoutGap after it ended, its streak not growing.
// Then it goes to the back of the line: the turns pass through every parked
// worker, so a link whose relays are dead cannot keep the others' from being
// dialed. The first relay to answer ends the dark, but the waiting workers stay
// until the scout's attempt has had its say — a proof wakes them all, one at a
// time as always (awaitRevivalSlot); a flicker of light that does not carry the
// scout through leaves the dark found again by its verdict, and nobody else
// dialed into it. A scout that is not back with its credential within
// darkScoutLease — stuck on it, say — loses its turn; once it dials, the turn is
// its own until the attempt has had its say, however long that takes: the lease
// ran out mid-attempt on a slow connect and Allocate, and the whole line was let
// go before the scout could tell whether the light it had seen would carry
// (Codex review, 19.10). There is no cap on that: the attempt ends by its own
// stages' limits, a stop or a move. While the dark holds, the park's
// limit (pathDarkParkMax) no longer lets the others go: a relay set that has
// really died is still dialed, by the scouts.
//
// A dark belongs to one path, and only to the transport in use: an attempt
// begun before a reset — a move, a transport changed, a proxy start — does not
// find it again on the path after (darkEpoch), and the screen asks only about
// the transport the dials go over now (pathSilence).
//
// The turns do not back off however long the dark lasts. In a dark the radio is
// awake anyway, hunting for a cell; a few SYNs every darkScoutPeriod cost next
// to nothing beside that, and how soon the tunnel is back once the cell is is
// what the user feels — a turn every 24s would leave it down that long.

var (
	darkScoutGap    = 500 * time.Millisecond // from one scout attempt's end to the next; vars for the tests
	darkScoutPeriod = 6 * time.Second        // from one scout attempt's start to the next: an attempt refused at once does not loop
	darkScoutLease  = 20 * time.Second       // a scout not back by then has lost its turn
	darkEvidenceMin = 3 * time.Second        // an attempt shorter than this tells nothing about the path
	darkUpQuiet     = 30 * time.Second       // a stream that heard its relay this recently says the path is there
)

// darkPath is the state of the path over one transport.
type darkPath struct {
	found     bool
	since     time.Time
	mark      uint64 // relayHeardMark when found: a relay heard since ends it
	scout     *stream
	dialing   bool // the scout has dialed: its turn lasts until its verdict
	lastScout *stream
	leaseTill time.Time // the scout's turn ends then, until it dials
	nextScout time.Time
	waiting   []*stream // the parked workers, in the order of their turns
}

var darkPaths struct {
	sync.Mutex
	t     [2]darkPath // UDP, TCP (proofTransport)
	epoch uint64      // the path's number: every reset starts another
}

// darkEpoch is the number of the path the darks belong to now; an attempt takes
// it as it begins.
func darkEpoch() uint64 {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	return darkPaths.epoch
}

// noteDarkPath records the path over the transport found dark, with no relay
// heard since mark, by an attempt that began at attemptStart on path epoch; a
// dark already found and still holding stays as it is. It reports whether the
// dark holds now — not for an attempt begun on another path, whose finding a
// reset since has made about a path that is gone: checked under the same lock
// as the reset, as a check of the attempt's move before this would leave a
// window for the reset to fall in (Codex review, 19.10).
func noteDarkPath(overTCP bool, mark, epoch uint64, attemptStart, now time.Time) bool {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	if epoch != darkPaths.epoch {
		return false
	}
	d := &darkPaths.t[proofTransport(overTCP)]
	d.noteLocked(overTCP, mark, attemptStart, now)
	return d.found
}

func (d *darkPath) noteLocked(overTCP bool, mark uint64, attemptStart, now time.Time) {
	if d.holdsLocked(overTCP) || relayHeardMark(overTCP) != mark {
		return
	}
	d.found, d.since, d.mark = true, now, mark
	if next := scoutNext(attemptStart, now); next.After(d.nextScout) {
		d.nextScout = next
	}
	turnLog("[PATH] no relay heard over %s — the path is dark: the workers that fail into it wait, and take turns dialing it alone",
		relayTransportLabel(overTCP))
}

// scoutNext is when the next scout attempt may begin after one that began at
// start and ended at end.
func scoutNext(start, end time.Time) time.Time {
	next := end.Add(darkScoutGap)
	if p := start.Add(darkScoutPeriod); p.After(next) {
		next = p
	}
	return next
}

// holdsLocked reports whether the dark is found and no relay heard since, and
// ends it once one is.
func (d *darkPath) holdsLocked(overTCP bool) bool {
	if !d.found {
		return false
	}
	if relayHeardMark(overTCP) == d.mark {
		return true
	}
	turnLog("[PATH] a relay heard over %s after %v dark", relayTransportLabel(overTCP), time.Since(d.since).Round(100*time.Millisecond))
	d.found = false
	return false
}

// pathStillDark reports whether the dark over the transport holds.
func pathStillDark(overTCP bool) bool {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	return darkPaths.t[proofTransport(overTCP)].holdsLocked(overTCP)
}

// liveScoutLocked reports whether a scout holds its turn: dialing, or not yet
// past its lease.
func (d *darkPath) liveScoutLocked(now time.Time) bool {
	return d.scout != nil && (d.dialing || now.Before(d.leaseTill))
}

// darkReleases reports whether the workers parked over the transport may go:
// no dark holds, and no scout attempt is under way whose outcome is still to
// tell whether the light it saw is back for good.
func darkReleases(overTCP bool, now time.Time) bool {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.t[proofTransport(overTCP)]
	return !d.holdsLocked(overTCP) && !d.liveScoutLocked(now)
}

// litPath ends the dark over the transport and any scout attempt's say in it:
// a session's proof, or a stream over it hearing its relay.
func litPath(overTCP bool) {
	darkPaths.Lock()
	d := &darkPaths.t[proofTransport(overTCP)]
	d.found, d.scout, d.dialing = false, nil, false
	darkPaths.Unlock()
}

// resetDarkPaths forgets both and starts another path: another network,
// another transport, another proxy. Workers parked on it are woken by the move
// itself.
func resetDarkPaths() {
	darkPaths.Lock()
	darkPaths.t = [2]darkPath{}
	darkPaths.epoch++
	darkPaths.Unlock()
}

// waitInTheDark puts s at the back of the line over the transport.
func waitInTheDark(s *stream, overTCP bool) {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.t[proofTransport(overTCP)]
	if !slices.Contains(d.waiting, s) {
		d.waiting = append(d.waiting, s)
	}
}

// stopWaitingInTheDark takes s out of the line over the transport.
func stopWaitingInTheDark(s *stream, overTCP bool) {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.t[proofTransport(overTCP)]
	d.waiting = slices.DeleteFunc(d.waiting, func(w *stream) bool { return w == s })
}

// leaveTheDark takes s out of the line, and its scout turn if it holds one, on
// both transports: a worker that stops.
func leaveTheDark(s *stream) {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	for i := range darkPaths.t {
		d := &darkPaths.t[i]
		d.waiting = slices.DeleteFunc(d.waiting, func(w *stream) bool { return w == s })
		if d.scout == s {
			d.scout, d.dialing = nil, false
		}
	}
}

// takeDarkScout gives s the next scout turn over the transport if the dark
// holds, s is at the head of the line, the turn is due and no scout holds a
// live one; changed reports a scout other than the last.
func takeDarkScout(s *stream, overTCP bool, now time.Time) (taken, changed bool) {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.t[proofTransport(overTCP)]
	if !d.holdsLocked(overTCP) || now.Before(d.nextScout) || len(d.waiting) == 0 || d.waiting[0] != s {
		return false, false
	}
	if d.liveScoutLocked(now) {
		return false, false
	}
	d.waiting = d.waiting[1:]
	changed = d.lastScout != s
	d.scout, d.dialing, d.lastScout, d.leaseTill = s, false, s, now.Add(darkScoutLease)
	return true, changed
}

// darkScoutDials reports whether s, back from a scout turn over the transport
// with its credential, is to dial: it still holds the turn, which is then its
// own until its verdict (darkScoutDone) — or no dark holds and no other scout's
// turn is live. A scout back past its lease has lost the turn even if nobody
// has taken it yet.
func darkScoutDials(s *stream, overTCP bool, now time.Time) bool {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.t[proofTransport(overTCP)]
	if d.scout == s && (d.dialing || now.Before(d.leaseTill)) {
		d.dialing = true
		return true
	}
	return !d.holdsLocked(overTCP) && !d.liveScoutLocked(now)
}

// darkScoutDone ends s's scout turn over the transport, if it dialed in it and
// still holds it, for an attempt that began at start: the next is due by
// scoutNext. dark is the scout's verdict: its attempt failed the dark's way and
// never got through, so whatever was heard while it dialed — a flicker of light
// — did not carry, and the dark is found again before anybody else is let into
// it. A scout whose turn has passed — its lease run out before it dialed, a
// proof, a move — has no say (Codex review, 18.10).
func darkScoutDone(s *stream, overTCP bool, start, now time.Time, dark bool) {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.t[proofTransport(overTCP)]
	if d.scout != s || !d.dialing {
		return
	}
	if dark {
		d.noteLocked(overTCP, relayHeardMark(overTCP), start, now)
	}
	d.scout, d.dialing = nil, false
	if next := scoutNext(start, now); next.After(d.nextScout) {
		d.nextScout = next
	}
}

// darkScouted reports whether a worker other than s holds a live scout turn
// over the transport.
func darkScouted(s *stream, overTCP bool, now time.Time) bool {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.t[proofTransport(overTCP)]
	return d.scout != s && d.liveScoutLocked(now)
}

// heardWithin reports whether a stream that is up over the transport has heard
// its relay within quiet.
func heardWithin(overTCP bool, streams []*stream, now time.Time, quiet time.Duration) bool {
	for _, s := range streams {
		if !s.ready.Load() || s.overTCP.Load() != overTCP {
			continue
		}
		if a := s.activity.Load(); a != nil && a.heardAge(now) < quiet {
			return true
		}
	}
	return false
}

// findsTheDark reports, for a worker whose attempt over the transport has just
// failed the dark's way, whether the path is dark, and records it so; why says
// how it was told. The attempt began at start on path epoch, the count of
// relays heard over the transport then standing at mark.
func findsTheDark(overTCP bool, mark, epoch uint64, start time.Time, err error, now time.Time) (dark bool, why string) {
	set := activeStreamSet()
	switch {
	case heardWithin(overTCP, set, now, pathDarkQuiet):
		litPath(overTCP)
		return false, ""
	case overTCP && pathLooksDark(set, now):
		if !noteDarkPath(overTCP, relayHeardMark(overTCP), epoch, start, now) {
			return false, ""
		}
		return true, "a socket stalled, no relay heard for " + pathDarkQuiet.String()
	case relayHeardMark(overTCP) == mark && now.Sub(start) >= darkEvidenceMin &&
		!localNetworkError(err) && !heardWithin(overTCP, set, now, darkUpQuiet):
		if !noteDarkPath(overTCP, mark, epoch, start, now) {
			return false, ""
		}
		return true, "no relay heard while the attempt ran"
	case pathStillDark(overTCP):
		return true, "no relay heard since it went dark"
	}
	return false, ""
}

// pathSilence is how long the path to the relays over the transport in use has
// been silent, when the streams know it to be: a dark found and holding, or the
// lookout's stalled sockets with no relay heard for pathDarkQuiet; zero
// otherwise — a tunnel that is idle hears nothing for a while and is not silent.
// Counted from the relay last heard over it, or, over a transport no relay ever
// answered on, from when the dark was found: a switch to TCP whose every SYN
// went unanswered read as no silence at all (Codex review, 19.10). The other
// transport's dark is not asked about: left behind by a switch, it said a path
// that works was silent.
//
// For the screen (wgTurnPathSilentSeconds). In the dark spells of 18.10 Android
// kept the network CONNECTED and VALIDATED for two minutes while nothing came
// over it, and the screen said "Connected" for the first 30s of each, then
// "Reconnecting…" — as if the tunnel were at fault, while it was the relays the
// network no longer reached.
func pathSilence(streams []*stream, overTCP bool, now time.Time) time.Duration {
	darkPaths.Lock()
	d := &darkPaths.t[proofTransport(overTCP)]
	found := d.holdsLocked(overTCP)
	since := d.since
	darkPaths.Unlock()
	if !found && !(overTCP && pathLooksDark(streams, now)) {
		return 0
	}
	if heard := sinceRelayHeard(overTCP, now); heard > 0 {
		return heard
	}
	if found {
		return max(now.Sub(since), 0)
	}
	return 0
}

// relayTransportLabel names a relay transport in the log.
func relayTransportLabel(overTCP bool) string {
	if overTCP {
		return "TCP"
	}
	return "UDP"
}
