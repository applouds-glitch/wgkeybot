/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// conflictLog collects the watch's own lines.
type conflictLog []string

func (l *conflictLog) logf(format string, args ...any) { *l = append(*l, fmt.Sprintf(format, args...)) }

// retryAnswered is one retry for silence and its response after rtt.
func retryAnswered(c *peerConflict, at time.Time, rtt time.Duration) {
	c.note(wgFormatRetrySilence, at)
	c.note(wgFormatResponse, at.Add(rtt))
}

// The Pixel's journal of 2026-11-14 02:31:34-02:40:34, a second phone up on the
// same config: the retries for silence, in seconds from the first, each
// answered within 0.11-0.45 s.
var conflict20261114 = []float64{0, 22.1, 38.0, 123.1, 144.6, 173.7, 203.4, 219.2, 235.0, 250.8, 266.5, 382.3, 413.6, 443.6, 479.3, 510.6, 540.0}

func TestSecondDeviceOnTheConfigIsFoundAndItsEndToo(t *testing.T) {
	var log conflictLog
	c := newPeerConflict(log.logf)
	start := time.Unix(1_800_000_000, 0)
	at := func(s float64) time.Time { return start.Add(time.Duration(s * float64(time.Second))) }

	for i, s := range conflict20261114 {
		retryAnswered(c, at(s), 250*time.Millisecond)
		got := c.seconds(at(s + 1))
		if i < peerConflictRetries-1 && got != 0 {
			t.Fatalf("a conflict after %d answered retries", i+1)
		}
		if i >= peerConflictRetries-1 && got == 0 {
			t.Fatalf("no conflict after %d answered retries in %v", i+1, at(s).Sub(start))
		}
	}
	found := conflict20261114[peerConflictRetries-1]
	if got := c.seconds(at(300)); got < int(300-found)-1 || got > int(300-found)+1 {
		t.Fatalf("at 300 s the conflict has lasted %d s, want ~%d", got, int(300-found))
	}
	if len(log) != 1 || !strings.Contains(log[0], "another device") {
		t.Fatalf("log = %q, want one line naming another device", log)
	}

	last := conflict20261114[len(conflict20261114)-1]
	if c.seconds(at(last+170)) == 0 {
		t.Fatal("the conflict ended within its window of the last taken-over handshake")
	}
	if c.seconds(at(last+0.25+peerConflictWindow.Seconds()+1)) != 0 {
		t.Fatalf("the conflict did not end %v after the last taken-over handshake", peerConflictWindow)
	}
	if len(log) != 2 || !strings.Contains(log[1], "is over") {
		t.Fatalf("log = %q, want the end said once", log)
	}
}

// The same journal on its quiet evening: one packet lost now and then. A retry
// for silence answered at once, hours apart, and a handshake that took two
// tries, are no second device.
func TestALostPacketNowAndThenIsNoConflict(t *testing.T) {
	c := newPeerConflict(nil)
	start := time.Unix(1_800_000_000, 0)
	// 20:04:10: the initiation went unanswered for 5 s, the second try answered.
	c.note(wgFormatHandshakeTimeout, start)
	c.note(wgFormatResponse, start.Add(200*time.Millisecond))
	// 22:04:14: one retry for silence, answered; and another two hours later.
	retryAnswered(c, start.Add(2*time.Hour), 300*time.Millisecond)
	retryAnswered(c, start.Add(4*time.Hour), 300*time.Millisecond)
	// Two close together are still not three.
	retryAnswered(c, start.Add(5*time.Hour), 300*time.Millisecond)
	retryAnswered(c, start.Add(5*time.Hour+40*time.Second), 300*time.Millisecond)
	if got := c.seconds(start.Add(5*time.Hour + time.Minute)); got != 0 {
		t.Fatalf("a conflict (%d s) from packets lost now and then", got)
	}
}

// A path that is down answers no handshake, however often WireGuard retries:
// that is the dark the relay layer already tells, not another device.
func TestUnansweredRetriesAreNoConflict(t *testing.T) {
	c := newPeerConflict(nil)
	start := time.Unix(1_800_000_000, 0)
	for i := 0; i < 10; i++ {
		at := start.Add(time.Duration(i) * 20 * time.Second)
		c.note(wgFormatRetrySilence, at)
		c.note(wgFormatHandshakeTimeout, at.Add(5*time.Second))
		c.note(wgFormatHandshakeTimeout, at.Add(10*time.Second))
	}
	// A response that comes only after a later try does not answer the retry.
	c.note(wgFormatResponse, start.Add(4*time.Minute))
	// Nor does one that took longer than peerConflictAnswerWithin.
	for i := 0; i < 5; i++ {
		at := start.Add(5*time.Minute + time.Duration(i)*20*time.Second)
		retryAnswered(c, at, 3*time.Second)
	}
	if got := c.seconds(start.Add(7 * time.Minute)); got != 0 {
		t.Fatalf("a conflict (%d s) from a path that did not answer", got)
	}
}

// Every WireGuard line passes the log thinner, and so the watch: the formats
// are read before the thinner drops or collapses anything.
func TestTheDeviceLogFeedsTheWatch(t *testing.T) {
	var out []string
	l := newWGLogThinner(func(s string) { out = append(out, s) }, func(s string) { out = append(out, s) })
	now := time.Unix(1_800_000_000, 0)
	l.now = func() time.Time { return now }
	l.watch = newPeerConflict(nil)
	peer := "peer(CnIG…8SDo)"
	for i := 0; i < peerConflictRetries; i++ {
		l.Verbosef(wgFormatRetrySilence, peer, 15)
		now = now.Add(250 * time.Millisecond)
		l.Verbosef(wgFormatResponse, peer)
		now = now.Add(20 * time.Second)
	}
	if l.watch.seconds(now) == 0 {
		t.Fatal("the lines that passed the thinner did not reach the watch")
	}
	if len(out) != 2*peerConflictRetries || !strings.Contains(out[0], "Retrying handshake because we stopped hearing back after 15 seconds") {
		t.Fatalf("the thinner's own output changed: %q", out)
	}
	// No watch: the thinner works as before.
	l2 := newWGLogThinner(func(string) {}, func(string) {})
	l2.Verbosef(wgFormatResponse, peer)
}

// The device that goes down takes its watch with it, and only its own.
func TestTheActiveWatchFollowsTheDevice(t *testing.T) {
	a, b := newPeerConflict(nil), newPeerConflict(nil)
	setActivePeerConflict(a)
	setActivePeerConflict(b) // the next device came up before the first went down
	clearActivePeerConflict(a)
	activePeerConflict.Lock()
	still := activePeerConflict.w
	activePeerConflict.Unlock()
	if still != b {
		t.Fatal("the old device's going down removed the new device's watch")
	}
	clearActivePeerConflict(b)
	if peerConflictSeconds(time.Now()) != 0 {
		t.Fatal("a conflict with no device up")
	}
}
