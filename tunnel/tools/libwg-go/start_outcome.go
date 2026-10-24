/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import "sync/atomic"

// What a start that ran out of time tells the caller.
//
// The plain -1 after the startup timeout says nothing about why, and the app
// answers it by trying another stream count — 30 more seconds — and then with
// "failed to establish TURN connection". Field log 12.10 (Xiaomi, Tele2): the
// user had no internet at all, the cached credentials had expired, and every VK
// address reset the connection before a byte came back. About ten taps over
// 2.5 hours, each 60-70s, the app killed several times, a new build installed and
// extra relays added, none of which could help — and the screen never said what
// was wrong.
//
// startVKUnreachable is that case named: no credential reached this start, and
// not one VK connection carried a byte back while it ran. Then nothing VK said
// stood between us and credentials; the network in between did — no internet,
// no balance, or a filter in front of VK — and a different stream count is the
// same wait over again. One byte back (a TLS hello, an error page, a captcha) is
// VK answering, and the start keeps the plain -1: a refusal VK gave has its own
// paths. Whether Android validated the network is not asked: behind a whitelist
// it never does and the relays still answer (see PhysicalNetworkChoice).
const startVKUnreachable int32 = -5

// vkConnsHeard counts VK API connections that carried at least one byte back
// (heardConn). Only ever compared with a snapshot taken at the start of the
// attempt, so its absolute value means nothing.
var vkConnsHeard atomic.Uint64

// startTimeoutCode is the code for a start whose window closed without a
// stream proving its data plane.
func startTimeoutCode(credsObtained, vkHeard bool) int32 {
	if !credsObtained && !vkHeard {
		return startVKUnreachable
	}
	return -1
}

// prefetchOutcomeCode is the start's answer as soon as the credential prefetch
// is over, or 0 to go on and launch the groups.
//
// Field log 23.10 (Pixel, Wi-Fi): not one resolver answered over plain DNS, DoH
// or DoT for the whole 36s of the prefetch, and the start then had the startup
// timeout's 30s more to run before it could say -5 — the workers spending them
// on the same fetch over the same silent network. The user disconnected at 41s.
// A group's own-network failure (errVKCallsOwnNetwork) is a fetch that has
// already spent its retry budget on our side of the network and found the
// legacy host unresolvable too; with no credential in any group no relay can be
// asked anything, so the verdict startTimeoutCode would give later is known now.
// Every group must have failed that way: one that failed otherwise — VK
// refused, a captcha — keeps the start going, and so does a byte from VK
// heard anywhere since the start began, as for startTimeoutCode. So does any
// network event during the prefetch (networkMoved): the failures are then the
// old network's — lookups already running when a working network arrived end
// on the path they started on — and the workers would fetch over the new one
// (Codex review, 23.10).
func prefetchOutcomeCode(groups, ownNetworkFails int, credsObtained, vkHeard, networkMoved bool) int32 {
	if groups > 0 && ownNetworkFails == groups && !credsObtained && !vkHeard && !networkMoved {
		return startVKUnreachable
	}
	return 0
}
