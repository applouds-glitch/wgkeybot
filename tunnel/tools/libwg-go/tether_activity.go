/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// What the sharing proxy says about itself while it runs.
//
// The per-connection paths are quiet on purpose: a page load opens dozens of
// connections, and a line for each would bury everything else in the log. But
// a proxy that logs only its failures is unreadable in the one situation that
// matters — "the client says nothing loads, and the log says nothing at all".
// That silence has two very different causes, and the log has to tell them
// apart: either the client's requests never reached the proxy (a proxy setting
// on the client, a PAC it did not fetch), or they did and every dial succeeded
// — which is not a line anywhere — and the bytes stopped afterwards.
//
// So the proxy keeps counters and speaks in summaries: one line per
// tetherActivityLogInterval, and only when something moved since the last one.
// An idle session stays silent; a busy one costs six lines a minute, with the
// route split (tunnel / direct / blocked / failed), the live connection count
// and the byte totals — enough to see requests arriving, which road they took,
// and whether anything came back.
//
// A blocked destination is the one decision that also gets its own line, up to
// tetherBlockLogBudget of them per session. A refusal is a verdict the profile
// reached, not a failure, and a client sees it as a site that will not open;
// with nothing in the log it is indistinguishable from an outage. The budget
// keeps an ad-heavy page from turning that into a wall.

const (
	tetherActivityLogInterval = 10 * time.Second
	tetherBlockLogBudget      = 20
)

// tetherActivity is the counters behind the summary line. Shared by the dialer
// (which knows the route each upstream took) and the proxy (which owns the
// byte counters and the live count); the proxy allocates it.
type tetherActivity struct {
	opened  [routeKinds]atomic.Int64
	blocked atomic.Int64
	failed  atomic.Int64
	// blockLines is how many blocked destinations have had their own line.
	blockLines atomic.Int64
	// logf is turnLog on device; a field so the host tests can read the lines.
	logf func(format string, args ...interface{})
}

func newTetherActivity() *tetherActivity {
	return &tetherActivity{logf: turnLog}
}

// noteOpened records an upstream that connected over route k.
func (a *tetherActivity) noteOpened(k routeKind) {
	if a == nil || k >= routeKinds {
		return
	}
	a.opened[k].Add(1)
}

// noteFailed records a dial that produced no upstream: resolution, the dial
// itself, or the egress check.
func (a *tetherActivity) noteFailed() {
	if a == nil {
		return
	}
	a.failed.Add(1)
}

// noteBlocked records a destination the routing profile refused, and says
// which one while the budget lasts.
func (a *tetherActivity) noteBlocked(host string, port int) {
	if a == nil {
		return
	}
	a.blocked.Add(1)
	n := a.blockLines.Add(1)
	switch {
	case n <= tetherBlockLogBudget:
		a.logf("[TETHER] blocked %s:%d by the routing profile", host, port)
	case n == tetherBlockLogBudget+1:
		a.logf("[TETHER] further blocked destinations are only counted; see the activity summary")
	}
}

// activitySnapshot is every counter the summary line is built from, read at
// one instant. up and down come from the proxy, the rest from here.
type activitySnapshot struct {
	opened   [routeKinds]int64
	blocked  int64
	failed   int64
	up, down int64
}

func (a *tetherActivity) snapshot(up, down int64) activitySnapshot {
	s := activitySnapshot{up: up, down: down}
	if a == nil {
		return s
	}
	for k := range s.opened {
		s.opened[k] = a.opened[k].Load()
	}
	s.blocked = a.blocked.Load()
	s.failed = a.failed.Load()
	return s
}

// activityLine renders what moved between prev and cur. ok is false when
// nothing did, which is what keeps an idle session out of the log.
func activityLine(prev, cur activitySnapshot, live int64, interval time.Duration) (line string, ok bool) {
	if prev == cur {
		return "", false
	}
	var opened int64
	var split []string
	for k := routeKind(0); k < routeKinds; k++ {
		n := cur.opened[k] - prev.opened[k]
		opened += n
		if n > 0 {
			split = append(split, fmt.Sprintf("%s %d", k, n))
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[TETHER] last %s: %d upstreams", interval, opened)
	if len(split) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(split, ", "))
	}
	fmt.Fprintf(&b, ", %d blocked, %d failed; %d live; up %s, down %s",
		cur.blocked-prev.blocked, cur.failed-prev.failed, live,
		fmtBytes(cur.up-prev.up), fmtBytes(cur.down-prev.down))
	return b.String(), true
}

// reportActivity logs the summary line every tetherActivityLogInterval for as
// long as the proxy runs, skipping intervals in which nothing happened.
func (p *tetherProxy) reportActivity(ctx context.Context) {
	t := time.NewTicker(tetherActivityLogInterval)
	defer t.Stop()
	prev := p.activity.snapshot(p.bytesUp.Load(), p.bytesDown.Load())
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur := p.activity.snapshot(p.bytesUp.Load(), p.bytesDown.Load())
		if line, ok := activityLine(prev, cur, p.conns.Load(), tetherActivityLogInterval); ok {
			p.activity.logf("%s", line)
		}
		prev = cur
	}
}

// fmtBytes renders a byte count the way the sharing sheet does: one decimal
// past kilobytes, so "1.5 MB" rather than 1572864.
func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 3; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
