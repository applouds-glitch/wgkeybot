/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"syscall"
	"time"
)

// A failure of the phone's own network is not held against a relay.
//
// The health accounting reads a young session's error, a failed connect or a
// failed Allocate as the relay's doing. When the network under the socket goes
// away they all fail at once, on every relay in use, and it read those too:
// Android aborts the TCP sockets of a lost network (ECONNABORTED), UDP writes
// get ENETUNREACH, Allocates in flight time out — three strikes each within the
// coalescing window's reach, and both relays stood down for five minutes at the
// very moment the path returned. Field log 19.09 (a cellular network that
// re-created its data call eight times in 23 minutes): twenty stand-downs of a
// relay with live streams on it, several of both at once; and "all servers
// failed" is what takes the head-start race away, the one thing that network
// rewards. A move to ANOTHER network already wipes server health; a loss and
// return of the same one does not, and should not — what the relays did before
// it still holds.
//
// Two tests, because neither sees everything. The error: the kernel refuses the
// write ~100-300ms before Android reports the loss (orphaned_allocations.go saw
// the same lead), so at that moment the network still looks present — but these
// errnos are the local stack speaking about its own interface or route, never a
// relay's answer. The network: a timeout carries no errno at all, and a session
// that went quiet because the path left under it proves nothing either —
// whatever ended while there was no network, or after the network it began on
// was left, says nothing about the far end.
//
// What stays the relay's: a refusal (ECONNREFUSED), silence on a network that
// stayed (timeouts), a reset, any TURN error. An unblamed relay costs an attempt
// that fails fast; a blamed healthy one cost five minutes.
func localNetworkError(err error) bool {
	for _, errno := range []syscall.Errno{
		syscall.ECONNABORTED,  // the socket's network was torn down under it
		syscall.ENETUNREACH,   // no route: the interface is gone
		syscall.ENETDOWN,      //
		syscall.EADDRNOTAVAIL, // the source address left with the lease
		syscall.EPERM,         // the platform's firewall cut the socket off
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// networkLeftSince reports whether there is no physical network now, or the one
// bound at since has been left — lost or exchanged for another — after it.
//
// "None now" is the gate's word, not a zero handle: the gate is what starts out
// open, so a proxy that has not been told of any network yet still holds its
// relays to account.
func networkLeftSince(since time.Time) bool {
	if !isNetworkAvailable() {
		return true
	}
	networkSwitch.Lock()
	defer networkSwitch.Unlock()
	return networkSwitch.leftAt.After(since)
}

// relayNotToBlame: the failure of an attempt begun at started, ending in err,
// belongs to the phone's network rather than to the relay.
func relayNotToBlame(err error, started time.Time) bool {
	return localNetworkError(err) || networkLeftSince(started)
}
