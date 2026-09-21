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

// publishStreams makes streams the set readyStreamCount counts, and returns the
// call that withdraws it — only if it is still the one published: a stop that
// drains slowly must not take the next start's set down with it.
func publishStreams(streams []*stream) (withdraw func()) {
	set := &streams
	activeStreams.Store(set)
	return func() { activeStreams.CompareAndSwap(set, nil) }
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
