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

// An idle interval writes nothing: the summary exists to show activity, and a
// line every ten seconds saying "0 of everything" would be the noise it is
// meant to replace.
func TestActivityLineStaysSilentWhenNothingMoved(t *testing.T) {
	a := newTetherActivity()
	a.noteOpened(routeTunnel)
	s := a.snapshot(10, 20)
	if line, ok := activityLine(s, s, 3, tetherActivityLogInterval); ok {
		t.Fatalf("got a line for an idle interval: %q", line)
	}
}

// The line carries deltas since the previous snapshot, not running totals, and
// names only the routes that were actually used.
func TestActivityLineReportsDeltasByRoute(t *testing.T) {
	a := newTetherActivity()
	prev := a.snapshot(100, 200)
	a.noteOpened(routeTunnel)
	a.noteOpened(routeTunnel)
	a.noteOpened(routeDirect)
	a.noteFailed()
	cur := a.snapshot(100+1536, 200+2*1024*1024)

	line, ok := activityLine(prev, cur, 7, 10*time.Second)
	if !ok {
		t.Fatal("no line for an interval with three upstreams")
	}
	want := "[TETHER] last 10s: 3 upstreams (tunnel 2, direct 1), 0 blocked, 1 failed; 7 live; up 1.5 KB, down 2.0 MB"
	if line != want {
		t.Fatalf("line = %q\nwant  %q", line, want)
	}

	// Bytes alone are movement too: a page that opened no new connection but
	// kept streaming over old ones is the case where "is anything flowing" is
	// the whole question.
	next := cur
	next.down += 4096
	if _, ok := activityLine(cur, next, 7, 10*time.Second); !ok {
		t.Fatal("no line for an interval in which only bytes moved")
	}
}

// Blocked destinations get their own line up to the budget, then one line
// saying the budget is spent, then nothing but the counter.
func TestActivityBlockLinesAreBudgeted(t *testing.T) {
	var lines []string
	a := newTetherActivity()
	a.logf = func(format string, args ...interface{}) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	for i := 0; i < tetherBlockLogBudget+5; i++ {
		a.noteBlocked(fmt.Sprintf("ads%d.example", i), 443)
	}
	if got := a.blocked.Load(); got != int64(tetherBlockLogBudget+5) {
		t.Fatalf("blocked counter = %d, want every refusal counted", got)
	}
	if len(lines) != tetherBlockLogBudget+1 {
		t.Fatalf("%d lines, want %d per-host lines plus the budget notice", len(lines), tetherBlockLogBudget+1)
	}
	if !strings.Contains(lines[0], "blocked ads0.example:443") {
		t.Fatalf("first line = %q, want the host and port", lines[0])
	}
	if !strings.Contains(lines[tetherBlockLogBudget], "only counted") {
		t.Fatalf("last line = %q, want the budget notice", lines[tetherBlockLogBudget])
	}
}

// A dialer built without an activity (every hand-made one in the tests) must
// keep working: the counters are observability, not behaviour.
func TestActivityNilIsSafe(t *testing.T) {
	var a *tetherActivity
	a.noteOpened(routeDirect)
	a.noteFailed()
	a.noteBlocked("x.example", 80)
	if s := a.snapshot(1, 2); s.up != 1 || s.down != 2 || s.opened[routeDirect] != 0 {
		t.Fatalf("nil snapshot = %+v", s)
	}
}

func TestFmtBytes(t *testing.T) {
	cases := map[int64]string{
		0:                      "0 B",
		999:                    "999 B",
		1024:                   "1.0 KB",
		1536:                   "1.5 KB",
		5 * 1024 * 1024:        "5.0 MB",
		3 * 1024 * 1024 * 1024: "3.0 GB",
	}
	for n, want := range cases {
		if got := fmtBytes(n); got != want {
			t.Errorf("fmtBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// The dialer is where the route is known, so it is what feeds the counters:
// one opened per route actually taken, one blocked per refusal, one failed per
// dial that produced nothing.
func TestRoutedDialFeedsActivityCounters(t *testing.T) {
	rd := newRoutedDialer(t)
	rd.d.activity = newTetherActivity()
	rd.d.activity.logf = func(string, ...interface{}) {}

	if err := rd.dial(t, "mail.yandex.ru"); err != nil {
		t.Fatalf("dial yandex: %v", err)
	}
	if err := rd.dial(t, "example.com"); err != nil {
		t.Fatalf("dial example.com: %v", err)
	}
	if err := rd.dial(t, "ad.mail.ru"); err == nil {
		t.Fatal("dial ad.mail.ru succeeded, want the profile's refusal")
	}
	rd.tunnel.err = fmt.Errorf("resolver down")
	if err := rd.dial(t, "nowhere.example"); err == nil {
		t.Fatal("dial nowhere.example succeeded, want a resolve failure")
	}

	s := rd.d.activity.snapshot(0, 0)
	if s.opened[routeDirect] != 1 || s.opened[routeTunnel] != 1 || s.blocked != 1 || s.failed != 1 {
		t.Fatalf("counters = %+v, want direct 1, tunnel 1, blocked 1, failed 1", s)
	}
}
