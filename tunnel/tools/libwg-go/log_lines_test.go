/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// The device, 11:38:18: the validated hint and the lost path arrived on two
// JNI threads at once, and the hint's line — snapshotted while the path was
// still up — was written after the path's. The log ended on
// "PhysicalPath=true … effectiveAvailable=true" with the gate closed. Here the
// hint's thread is held between its snapshot and its line while the path goes;
// the last line must still describe the gate as it is.
func TestGateLinesEndOnTheCurrentState(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	var mu sync.Mutex
	var lines []string
	calls := 0
	held := make(chan struct{})
	release := make(chan struct{})
	prev := networkLogf
	networkLogf = func(format string, args ...interface{}) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			close(held)
			<-release
		}
		mu.Lock()
		lines = append(lines, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	defer func() { networkLogf = prev }()

	setNetworkAvailable(false)
	hintDone := make(chan struct{})
	go func() { defer close(hintDone); logNetworkAvailability() }()
	<-held

	setPhysicalPath(false)
	pathDone := make(chan struct{})
	go func() { defer close(pathDone); logNetworkAvailability() }()
	time.Sleep(50 * time.Millisecond) // the path's line, if nothing stops it, is written by now
	close(release)
	<-hintDone
	<-pathDone

	mu.Lock()
	defer mu.Unlock()
	if last := lines[len(lines)-1]; !strings.Contains(last, "PhysicalPath=false") {
		t.Fatalf("the last gate line describes a state already gone: %q\nall: %q", last, lines)
	}
}

// A slot is also missed when its group's link has changed; the credential in it
// has then not expired, and its expiry is no reason to report.
func TestCacheMissReason(t *testing.T) {
	now := time.Now()
	prev := TurnCredentials{Link: "old", FetchedAt: now.Add(-40 * time.Second), ExpiresAt: now.Add(58 * time.Minute)}

	got := cacheMissReason(prev, "new", now)
	if want := "cached creds are for another link (lived 40s)"; got != want {
		t.Fatalf("link changed: %q, want %q", got, want)
	}

	prev.Link = "new"
	prev.ExpiresAt = now.Add(-5 * time.Second)
	if got, want := cacheMissReason(prev, "new", now), "previous creds lived 40s (expired 5s ago)"; got != want {
		t.Fatalf("expired: %q, want %q", got, want)
	}
}
