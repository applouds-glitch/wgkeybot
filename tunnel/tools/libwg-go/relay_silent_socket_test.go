/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// The line a silent stream gets over TCP: both clocks, what of ours is
// outstanding, the segment sizes — and nothing at all for a UDP stream.
func TestSilentStreamOverTCPGetsItsSocketDescribed(t *testing.T) {
	w := newRelaySocketWatch()
	conn := &net.TCPConn{}
	cur := relaySocketSample{
		received: 300 * 1024, sinceData: 36200 * time.Millisecond, sinceAck: 900 * time.Millisecond,
		sndMSS: 1228, rcvMSS: 1228, pathMTU: 1460,
	}
	w.sample = func(*net.TCPConn) (relaySocketSample, bool) { return cur, true }
	four := &stream{id: 4}
	w.register(four, "193.203.43.23:19302", conn)

	line := w.silentSocketLine(four)
	for _, want := range []string{
		"[TCP] stream 4 (193.203.43.23:19302)", "last data from the relay 36.2s ago", "last ACK 900ms ago",
		"nothing of ours unacknowledged", "300 KB received", "mss 1228 out / 1228 in", "path mtu 1460",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("no %q in %q", want, line)
		}
	}

	cur.backlog, cur.timeouts = 84*1024, 5
	line = w.silentSocketLine(four)
	if !strings.Contains(line, "up to 84 KB of ours unacknowledged after 5 timeout(s) in a row") {
		t.Fatalf("the outstanding data is not in %q", line)
	}

	if got := w.silentSocketLine(&stream{id: 7}); got != "" {
		t.Fatalf("a stream with no TCP socket got %q", got)
	}
	w.sample = func(*net.TCPConn) (relaySocketSample, bool) { return relaySocketSample{}, false }
	if got := w.silentSocketLine(four); got != "" {
		t.Fatalf("an unreadable socket got %q", got)
	}
}

// And it reaches the log next to the dispatcher's own line, once per silence.
func TestStaleWatchAddsTheSocketLine(t *testing.T) {
	prev := relaySockets
	relaySockets = newRelaySocketWatch()
	t.Cleanup(func() { relaySockets = prev })
	relaySockets.sample = func(*net.TCPConn) (relaySocketSample, bool) {
		return relaySocketSample{sndMSS: 1228}, true
	}

	now := time.Now()
	quiet := dispatchStream(0, true, now, 8)
	fresh := dispatchStream(1, true, now, 8)
	streams := []*stream{quiet, fresh}
	relaySockets.register(quiet, "relay:19302", &net.TCPConn{})
	w := newStaleWatch(len(streams))

	later := now.Add(dispatchStaleAfter + time.Second)
	fresh.activity.Load().noteRx(later)
	lines := w.observe(streams, later)
	if len(lines) != 2 || !strings.Contains(lines[0], "silent for") || !strings.HasPrefix(lines[1], "[TCP] stream 0 ") {
		t.Fatalf("lines: %q", lines)
	}
	if again := w.observe(streams, later.Add(staleWatchInterval)); len(again) != 0 {
		t.Fatalf("the same silence was reported again: %q", again)
	}
}
