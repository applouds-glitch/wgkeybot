/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import "C"

import "sync/atomic"

// The app's private files directory, where native keeps what has to outlive the
// process: Android kills it between sessions, on some devices within a minute of
// every disconnect. Empty until the app names it, and then nothing is kept.
var stateDir atomic.Pointer[string]

// wgSetStateDir names that directory. TurnProxyManager calls it once, before
// any proxy start.
//
//export wgSetStateDir
func wgSetStateDir(dirC *C.char) {
	setStateDir(C.GoString(dirC))
}

func setStateDir(dir string) { stateDir.Store(&dir) }

func stateDirPath() string {
	if dir := stateDir.Load(); dir != nil {
		return *dir
	}
	return ""
}
