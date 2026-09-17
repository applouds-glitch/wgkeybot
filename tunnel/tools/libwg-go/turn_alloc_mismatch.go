/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"sync"
	"time"
)

// allocationMismatchPause is how long a relay that refused three different
// local addresses with 437 is left alone (RFC 8656 section 7.4). It is the only
// thing this client remembers about a relay: a 437 is the relay's own explicit
// answer, not an inference from silence, so an uplink outage cannot arm it.
const allocationMismatchPause = 2 * time.Minute

var allocationMismatch = struct {
	sync.Mutex
	until map[string]time.Time
}{until: make(map[string]time.Time)}

func noteServerAllocationMismatch(addr string, now time.Time) {
	allocationMismatch.Lock()
	defer allocationMismatch.Unlock()
	allocationMismatch.until[addr] = now.Add(allocationMismatchPause)
}

func serverAllocationMismatchPaused(addr string, now time.Time) bool {
	allocationMismatch.Lock()
	defer allocationMismatch.Unlock()
	until, ok := allocationMismatch.until[addr]
	if !ok {
		return false
	}
	if now.Before(until) {
		return true
	}
	delete(allocationMismatch.until, addr)
	return false
}

// resetAllocationMismatchPauses is called when a proxy starts: the credentials,
// and usually the relay list itself, are new.
func resetAllocationMismatchPauses() {
	allocationMismatch.Lock()
	allocationMismatch.until = make(map[string]time.Time)
	allocationMismatch.Unlock()
}
