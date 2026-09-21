/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import "testing"

// No proxy is not the same as a proxy with no stream up: the screen says
// "reconnecting" for the second and nothing for the first.
func TestReadyStreamCount(t *testing.T) {
	t.Cleanup(func() { activeStreams.Store(nil) })
	activeStreams.Store(nil)
	if got := readyStreamCount(); got != -1 {
		t.Fatalf("no proxy running: %d, want -1", got)
	}

	streams := []*stream{{id: 0}, {id: 1}, {id: 2}}
	withdraw := publishStreams(streams)
	if got := readyStreamCount(); got != 0 {
		t.Fatalf("a proxy with no stream up: %d, want 0", got)
	}
	streams[0].ready.Store(true)
	streams[2].ready.Store(true)
	if got := readyStreamCount(); got != 2 {
		t.Fatalf("two of three ready: %d", got)
	}

	// A stop that drains slowly withdraws its set after the next start has
	// published another: it must not take that one down.
	next := []*stream{{id: 0}}
	next[0].ready.Store(true)
	withdrawNext := publishStreams(next)
	withdraw()
	if got := readyStreamCount(); got != 1 {
		t.Fatalf("the old proxy's withdrawal took the new proxy's streams down: %d", got)
	}
	withdrawNext()
	if got := readyStreamCount(); got != -1 {
		t.Fatalf("after the last withdrawal: %d, want -1", got)
	}
}
