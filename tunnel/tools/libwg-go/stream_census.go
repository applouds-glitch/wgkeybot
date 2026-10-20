/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import "sync/atomic"

// How many streams are carrying the tunnel right now, for the screen.
//
// The UI used to learn that anything was wrong from WireGuard alone: its last
// handshake going stale, three minutes on. A network drop therefore read
// "Connected" all the way through — the streams died, the workers redialed, the
// streams came back, and nothing on the screen ever said so; and when they did
// not come back, the first sign of it was minutes late. The proxy knows at once:
// a stream is ready or it is not.

// activeStreams is the stream set of the proxy that is running, nil when none is.
var activeStreams atomic.Pointer[[]*stream]

// activeUseUDP is the running proxy's config transport (#@wgt:UseUDP): with the
// choice in force it says which transport the dials go over (relayTransportInUse).
var activeUseUDP atomic.Bool

// publishStreams makes streams the set readyStreamCount counts, over a config
// that says useUDP, and returns the call that withdraws it — only if it is still
// the one published: a stop that drains slowly must not take the next start's
// set down with it.
func publishStreams(streams []*stream, useUDP bool) (withdraw func()) {
	set := &streams
	activeUseUDP.Store(useUDP)
	activeStreams.Store(set)
	return func() { activeStreams.CompareAndSwap(set, nil) }
}

// relayTransportInUse reports whether the running proxy's dials go over TCP now.
// Not what a stream last ran over: a worker fetching its credential has no
// attempt, and its last session may be on the transport just left.
func relayTransportInUse() bool {
	return transportOverTCP(relayTransportChoice.Load(), activeUseUDP.Load())
}

// readyStreamCount is the number of streams handed to the dispatcher, or -1 when
// no proxy is running — which is not the same as a proxy with none.
func readyStreamCount() int {
	set := activeStreams.Load()
	if set == nil {
		return -1
	}
	n := 0
	for _, s := range *set {
		if s.ready.Load() {
			n++
		}
	}
	return n
}
