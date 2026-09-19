//go:build !linux

/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import "net"

// readRelaySocket has nothing to read off Linux: the package is built there only
// to run its tests, and the watcher skips a socket it cannot sample.
func readRelaySocket(*net.TCPConn) (relaySocketSample, bool) {
	return relaySocketSample{}, false
}
