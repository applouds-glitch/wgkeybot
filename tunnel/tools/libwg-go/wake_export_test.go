/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import "testing"

// The unlock of the device reaches the keepalive loops only while a proxy is
// running: with none, nothing listens, and the epoch must not move — a wake
// that happened before a session starts would otherwise read as this session's.
func TestUnlockWakesTheStreamsOnlyWhileAProxyRuns(t *testing.T) {
	t.Cleanup(func() { activeStreams.Store(nil) })
	activeStreams.Store(nil)

	before := hostWakeEpoch()
	wgTurnProxyWake()
	if got := hostWakeEpoch(); got != before {
		t.Fatalf("epoch moved %d → %d with no proxy running", before, got)
	}

	set := []*stream{}
	activeStreams.Store(&set)
	wgTurnProxyWake()
	if got := hostWakeEpoch(); got != before+1 {
		t.Fatalf("epoch %d after an unlock with a proxy running, want %d", got, before+1)
	}
}
