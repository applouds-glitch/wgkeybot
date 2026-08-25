/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <stdlib.h>
extern void notifyTurnFatal(const char* reason);
*/
import "C"

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// Terminal-failure accounting for the worker pool.
//
// A worker used to retry a credential failure forever on a fixed cadence: an
// unsolvable captcha or a call that no longer exists produced the same 30s sleep
// as a lost packet, so a stream that could never come back kept re-running the
// solve ladder — dialog included — for as long as the tunnel was up, and nothing
// ever told the user why the connection was not working.
//
// Workers now give up on failures that retrying cannot fix (see runWorker). A
// group that loses every worker is dead, but the tunnel may still be carried by
// the other groups, so a single give-up is not fatal. Only when every worker in
// the session has given up does the tunnel have no transport left at all — that
// is the terminal state, reported once to the Android layer so it can tell the
// user and tear the tunnel down instead of leaving a connected-looking VPN with
// a dead route.
var (
	fatalWorkersTotal atomic.Int64
	fatalWorkersDead  atomic.Int64
	fatalOnce         atomic.Pointer[sync.Once]
)

// resetWorkerFatalState re-arms the accounting for a fresh session. total is the
// number of workers about to be launched.
func resetWorkerFatalState(total int) {
	fatalWorkersTotal.Store(int64(total))
	fatalWorkersDead.Store(0)
	fatalOnce.Store(&sync.Once{})
}

// reportWorkerGaveUp records that one worker stopped retrying for good. When the
// last one goes, the session is reported as terminally failed — once.
func reportWorkerGaveUp(streamID int, reason string) {
	dead := fatalWorkersDead.Add(1)
	total := fatalWorkersTotal.Load()
	turnLog("[WORKER %d] Gave up permanently (%s) — %d/%d workers dead", streamID, reason, dead, total)
	if total <= 0 || dead < total {
		return
	}
	once := fatalOnce.Load()
	if once == nil {
		return
	}
	once.Do(func() {
		// Hands the reason to the Android layer (TurnBackend.onTurnFatal), which
		// tells the user and takes the tunnel down. Fire-and-forget on the JNI side,
		// so this does not block the worker that lost last.
		turnLog("[PROXY] Every worker gave up — reporting terminal failure: %s", reason)
		cReason := C.CString(reason)
		defer C.free(unsafe.Pointer(cReason))
		C.notifyTurnFatal(cReason)
	})
}
