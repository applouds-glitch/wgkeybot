/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A session the relay ended with "no allocation for this socket" is graded by
// how long the relay was heard, as the post-wake probe's verdict on the same
// fact is — never as a failure of the relay.
func TestOutOfReachIsGradedByTheTimeTheRelayWasHeard(t *testing.T) {
	closed := errors.New("relay RX: read udp: use of closed network connection")
	for _, c := range []struct {
		name        string
		dur, silent time.Duration
		err         error
		want        sessionVerdict
	}{
		{"an hour carried, cut at a thaw", time.Hour, 2 * time.Minute, closed, verdictSuccess},
		{"just long enough once the silence is off", healthySessionDuration + time.Minute, time.Minute, closed, verdictSuccess},
		{"just short of it", healthySessionDuration + time.Minute - time.Second, time.Minute, closed, verdictNone},
		{"young", 10 * time.Second, 0, closed, verdictNone},
		{"heard nothing", 5 * time.Minute, 5 * time.Minute, nil, verdictNone},
		// A deaf error's own silence is the one taken off, not both.
		{"deaf as well", healthySessionDuration + deadStreamTimeout, deadStreamTimeout, &deadStreamError{silent: deadStreamTimeout}, verdictSuccess},
	} {
		if got := sessionOutcome(false, blackholeOutOfReach, c.dur, c.silent, c.err); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if got := sessionOutcome(true, blackholeOutOfReach, time.Hour, 0, closed); got != verdictNone {
		t.Errorf("a teardown read as %v", got)
	}
	// The relay going silent on the session is still the failure it was.
	if got := sessionOutcome(false, blackholeRelay, time.Hour, 0, closed); got != verdictFailure {
		t.Errorf("a silent relay read as %v", got)
	}
}

// A session whose transport never published a clock of its own carried
// nothing, whatever it left behind — no clock at all on a stream's first
// session, the last session's on any other. Its silence is its whole length,
// and a 400 that cut it is no success: a first DTLS handshake frozen past
// healthySessionDuration and cut at the thaw used to wipe the relay's strikes
// (Codex review of the iOS port, 23.10).
func TestASessionWithNoClockOfItsOwnCarriedNothing(t *testing.T) {
	now := time.Now()
	started := now.Add(-5 * time.Minute)
	handshake := fmt.Errorf("%w: DTLS handshake failed: %w", errDataPlaneHandshake, context.DeadlineExceeded)
	earlier := newStreamActivity(started.Add(-time.Hour), 0)
	earlier.noteRx(started.Add(-10 * time.Minute))
	for _, c := range []struct {
		name string
		a    *streamActivity
	}{
		{"a stream's first session", nil},
		{"the last session's clock", earlier},
	} {
		silent := sessionSilence(c.a, started, now)
		if silent < now.Sub(started) {
			t.Errorf("%s: silent %v of a %v session", c.name, silent, now.Sub(started))
		}
		if got := sessionOutcome(false, blackholeOutOfReach, now.Sub(started), silent, handshake); got != verdictNone {
			t.Errorf("%s: a 400 at the thaw graded %v", c.name, got)
		}
	}
	// Its own clock, heard until a minute ago: carried four minutes.
	own := newStreamActivity(started, 0)
	own.noteRx(now.Add(-time.Minute))
	if got := sessionSilence(own, started, now); got != time.Minute {
		t.Fatalf("its own clock: silent %v, want 1m", got)
	}
	if got := sessionOutcome(false, blackholeOutOfReach, now.Sub(started), sessionSilence(own, started, now), nil); got != verdictSuccess {
		t.Errorf("four minutes carried, then a 400: %v", got)
	}
}

// What the watchdog fired on decides the kind; its first verdict, as for its
// reason.
func TestBlackholeKindFollowsTheFirstVerdict(t *testing.T) {
	watch := func(lines ...string) *permWatch {
		w := newPermWatch(1)
		for _, l := range lines {
			w.note(l)
		}
		return w
	}
	checked := newPermWatch(1)
	checked.markOutOfReach("allocation check after wake: CreatePermission error response (error 400: Bad Request)")
	for name, c := range map[string]struct {
		perm *permWatch
		want blackholeKind
	}{
		"none":             {nil, noBlackhole},
		"live":             {watch(logBindOK, logPermOK), noBlackhole},
		"permission 400":   {watch(logPermFail400), blackholeOutOfReach},
		"allocation check": {checked, blackholeOutOfReach},
		// pion closes the allocation itself after a first ChannelBind 400: not
		// the out-of-reach case, and still the relay's failure.
		"first ChannelBind 400": {watch(logAllocClose), blackholeRelay},
		"ChannelBind silence":   {watch(logBindFail, logBindFail), blackholeRelay},
		// A refresh pion reports as failed was not answered (see note).
		"allocation refresh":  {watch(logAllocFail), blackholeRelay},
		"permission refusals": {watch(logPermFail, logPermFail), blackholeRelay},
		"400 after silence":   {watch(logAllocFail, logPermFail400), blackholeRelay},
	} {
		if got := sessionBlackhole(c.perm); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// Which out-of-reach ends leave a seat at the relay: the probe's over either
// transport, a 400 only over UDP.
func TestOutOfReachSeatsOnlyWhereTheOld5TupleCanHoldOne(t *testing.T) {
	probe := &deadStreamError{silent: time.Minute, probe: true}
	for _, c := range []struct {
		name    string
		hole    blackholeKind
		overTCP bool
		err     error
		want    bool
	}{
		{"400 over UDP", blackholeOutOfReach, false, nil, true},
		{"400 over TCP", blackholeOutOfReach, true, nil, false},
		{"probe over UDP", noBlackhole, false, probe, true},
		{"probe over TCP", noBlackhole, true, probe, true},
		{"silent relay", blackholeRelay, false, nil, false},
		{"detector", noBlackhole, false, &deadStreamError{silent: deadStreamTimeout}, false},
		{"nothing", noBlackhole, false, nil, false},
	} {
		if got := outOfReachSeated(c.hole, c.overTCP, c.err); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// The whole path, on a live session: the relay answering 400 to the allocation
// check ends the session and costs the relay nothing; the relay going silent on
// it still costs a strike.
func TestARelayAnsweringOutOfReachTakesNoStrike(t *testing.T) {
	for _, c := range []struct {
		name    string
		end     func(*permWatch)
		strikes int
		ghosts  int // the seat the session leaves at the relay, over UDP
	}{
		{"out of reach", func(p *permWatch) {
			p.markOutOfReach("allocation check after thaw: CreatePermission error response (error 400: Bad Request)")
		}, 0, 1},
		{"silent", func(p *permWatch) { p.markDead("Failed to bind channel 16384: all retransmissions failed") }, 1, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			resetAllocationBook(t)
			resetNetworkSwitch(t)
			resetNetworkAvailabilityForTest()
			resetServerHealth()
			t.Cleanup(resetServerHealth)
			relay := startTestRelay(t, listenFakeRelay(t), 0)
			answer := make(chan struct{})
			close(answer)
			cfg := WorkerGroupConfig{GroupID: 140, Link: "test", UseUDP: true, PeerType: "wireguard", PeerAddr: fakeRelay(t, answer)}

			s, _ := newNoDTLSTestStream(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client, raw, relayConn, rtt, perm, err := dialAndAllocate(ctx, s, t.Name(), "pass", relay.addr, cfg, dialOpts{})
			if err != nil {
				t.Fatal(err)
			}
			ended := make(chan error, 1)
			go func() {
				ended <- s.runSession(ctx, winner{client: client, raw: raw, relay: relayConn, addr: relay.addr, rtt: rtt, perm: perm, user: t.Name()}, cfg)
			}()
			waitFor(t, "a stream over UDP", 5*time.Second, func() bool { return s.ready.Load() })

			c.end(perm)
			select {
			case err := <-ended:
				if err == nil || !strings.Contains(err.Error(), "TURN blackhole") {
					t.Fatalf("the session ended with %v, want the watchdog's reason", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the session is still running 3s after the watchdog closed its relay")
			}
			if got := relayStrikes(relay.addr); got != c.strikes {
				t.Fatalf("the relay took %d strike(s), want %d", got, c.strikes)
			}
			if got := ghosts(t.Name(), relay.addr, time.Now()); got != c.ghosts {
				t.Fatalf("the session left %d ghost(s) at the relay, want %d", got, c.ghosts)
			}
		})
	}
}
