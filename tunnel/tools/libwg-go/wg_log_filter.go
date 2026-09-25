/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// wgLogThinner sits between wireguard-go's logger and logcat, and so between it
// and every exported journal (PersistentLog keeps each WireGuard/… line). The
// device's verbose log is written for someone watching it live: on a tunnel
// that sits idle for a day, one keepalive line every 25s came to over a quarter
// of a pulled log, and every connect added a line per CPU core for each of
// three worker pools. Two things are done about it, both keyed on wireguard-go's
// format string, so a reworded upstream line simply passes through unchanged:
//
//   - wgDroppedFormats are not written at all;
//   - wgCollapsedFormats are counted instead of written, and a run of them
//     becomes one line — the original text plus how many, over how long and how
//     long ago the last one was — written just before the next line of any
//     other kind, or once the oldest pending run is wgLogCollapseWindow old.
//
// The collapsed lines still tell a reader what they came for: that keepalives
// were leaving and arriving, and when the last one did. On a live tunnel the
// next other line is never far off — WireGuard re-handshakes every two minutes
// — and a dead one logs its handshake retries every five seconds.
type wgLogThinner struct {
	mu      sync.Mutex
	verbose func(string)
	errorf  func(string)
	now     func() time.Time
	runs    []wgLogRun
}

type wgLogRun struct {
	msg         string
	n           int
	first, last time.Time
}

// One line per CPU core for each pool, on every device up and down: 24 per
// connect on an eight-core phone, saying nothing a failure is ever traced by.
var wgDroppedFormats = map[string]bool{
	"Routine: encryption worker %d - started": true,
	"Routine: encryption worker %d - stopped": true,
	"Routine: decryption worker %d - started": true,
	"Routine: decryption worker %d - stopped": true,
	"Routine: handshake worker %d - started":  true,
	"Routine: handshake worker %d - stopped":  true,
}

// Worth knowing as a rate and a last time, not one line each. allowedip is
// here for split-tunnel configs: one line per prefix, hundreds of them, on
// every start.
var wgCollapsedFormats = map[string]bool{
	"%v - Sending keepalive packet":   true,
	"%v - Receiving keepalive packet": true,
	"%v - UAPI: %s allowedip":         true,
}

// The longest a collapsed run waits for another line to be written ahead of.
const wgLogCollapseWindow = 5 * time.Minute

func newWGLogThinner(verbose, errorf func(string)) *wgLogThinner {
	return &wgLogThinner{verbose: verbose, errorf: errorf, now: time.Now}
}

func (l *wgLogThinner) Verbosef(format string, args ...any) {
	if wgDroppedFormats[format] {
		return
	}
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if wgCollapsedFormats[format] {
		l.count(msg, now)
		if now.Sub(l.runs[0].first) >= wgLogCollapseWindow {
			l.flush(now)
		}
		return
	}
	l.flush(now)
	l.verbose(msg)
}

// Errorf is never thinned; it only lets the pending runs out first, so the
// error lands after the keepalives that preceded it, not before.
func (l *wgLogThinner) Errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flush(l.now())
	l.errorf(msg)
}

func (l *wgLogThinner) count(msg string, now time.Time) {
	for i := range l.runs {
		if l.runs[i].msg == msg {
			l.runs[i].n++
			l.runs[i].last = now
			return
		}
	}
	l.runs = append(l.runs, wgLogRun{msg: msg, n: 1, first: now, last: now})
}

func (l *wgLogThinner) flush(now time.Time) {
	for _, r := range l.runs {
		l.verbose(r.line(now))
	}
	l.runs = l.runs[:0]
}

// "peer(…) - Sending keepalive packet ×6 over 2m5s, the last 20s ago"; a
// single line flushed on the spot reads exactly as wireguard-go wrote it.
func (r wgLogRun) line(now time.Time) string {
	var b strings.Builder
	b.WriteString(r.msg)
	if r.n > 1 {
		fmt.Fprintf(&b, " ×%d", r.n)
		if span := r.last.Sub(r.first).Round(time.Second); span > 0 {
			fmt.Fprintf(&b, " over %v", span)
		}
	}
	if age := now.Sub(r.last).Round(time.Second); age > 0 {
		if r.n > 1 {
			fmt.Fprintf(&b, ", the last %v ago", age)
		} else {
			fmt.Fprintf(&b, " (%v ago)", age)
		}
	}
	return b.String()
}
