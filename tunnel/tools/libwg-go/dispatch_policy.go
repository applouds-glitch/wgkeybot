/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"time"
)

const (
	// chunkSize is how many consecutive packets the dispatcher sends through
	// one stream before rotating. Chunking keeps order inside a burst without
	// per-packet path accounting.
	chunkSize = 8

	// chunkMaxAge caps how long a chunk may stay open. The count alone rotates
	// only under load: with the screen off the tunnel carries a keepalive every
	// 25s and the odd handshake, so one chunk lasted minutes and every
	// WireGuard handshake retry (5s apart) landed on the same stream. A stream
	// that was merely flaky — not yet stale, so not skipped — then ate the whole
	// retry series while eight siblings sat idle; one rekey took 10s that way.
	// Packets a second apart have no ordering to protect, so an idle chunk is
	// closed and the next packet starts its search on the next stream.
	chunkMaxAge = time.Second

	// staleWatchInterval bounds how often the dispatcher re-scans every stream
	// for stale transitions. Transitions are logged, not the scans, so this only
	// caps the atomic loads per packet under load; at idle every packet scans.
	staleWatchInterval = time.Second
)

// chunkRotor chooses the stream a packet starts its round-robin search from:
// the same stream for chunkSize consecutive packets, or until the chunk has
// been open for chunkMaxAge, whichever comes first.
type chunkRotor struct {
	n          int
	cur        int
	inChunk    int
	chunkStart time.Time
}

func newChunkRotor(n int) *chunkRotor {
	return &chunkRotor{n: n}
}

// start returns the stream index to dispatch from, closing an idle chunk first.
func (r *chunkRotor) start(now time.Time) int {
	if r.inChunk > 0 && now.Sub(r.chunkStart) >= chunkMaxAge {
		r.advance()
	}
	return r.cur
}

// sent records a packet placed on the current chunk.
func (r *chunkRotor) sent(now time.Time) {
	if r.inChunk == 0 {
		r.chunkStart = now
	}
	r.inChunk++
	if r.inChunk >= chunkSize {
		r.advance()
	}
}

func (r *chunkRotor) advance() {
	r.cur = (r.cur + 1) % r.n
	r.inChunk = 0
}

// staleWatch turns the dispatcher's silent stale decisions into log lines, one
// per transition. Skipping a stream is deliberately quiet (it is reversible and
// costs nothing), but without a trace the first sign of a relay that went quiet
// was the dead-stream detector 90s later — and a relay outage looked exactly
// like an uplink outage until then. The per-stream lines tell one dead
// allocation from the rest: it stales one stream while its siblings keep
// hearing echoes. The "every stream" line says only that all of them went
// quiet, not where: all streams share one relay (assignServers), so a dead
// uplink and a relay whose path went dark look the same from here — field log
// 18.09 had that line while the other relay was answering Allocates in 200ms.
type staleWatch struct {
	stale    []bool
	allStale bool
	lastScan time.Time
}

func newStaleWatch(n int) *staleWatch {
	return &staleWatch{stale: make([]bool, n)}
}

// observe re-evaluates every stream at most once per staleWatchInterval and
// returns the log lines for whatever changed since the previous scan.
func (w *staleWatch) observe(streams []*stream, now time.Time) []string {
	if !w.lastScan.IsZero() && now.Sub(w.lastScan) < staleWatchInterval {
		return nil
	}
	w.lastScan = now

	var lines []string
	ready, stale := 0, 0
	for i, st := range streams {
		if !st.ready.Load() {
			// A torn-down stream leaves the picture without a line of its own:
			// the dead-stream detector or the worker already said why.
			w.stale[i] = false
			continue
		}
		ready++
		isStale := st.dispatchStale(now)
		if isStale {
			stale++
		}
		if isStale == w.stale[i] {
			continue
		}
		w.stale[i] = isStale
		if isStale {
			lines = append(lines, fmt.Sprintf("[DISPATCH] stream %d silent for %v — skipped while siblings hear echoes",
				st.id, st.activity.Load().rxAge(now).Round(time.Second)))
		} else {
			lines = append(lines, fmt.Sprintf("[DISPATCH] stream %d heard its relay again — back in rotation", st.id))
		}
	}

	allStale := ready > 0 && stale == ready
	if allStale != w.allStale {
		w.allStale = allStale
		if allStale {
			lines = append(lines, fmt.Sprintf("[DISPATCH] every ready stream (%d) is silent — the uplink or the relay they share is dark; dispatching to all of them", ready))
		} else if ready > 0 {
			lines = append(lines, fmt.Sprintf("[DISPATCH] relay echoes are back on %d of %d streams", ready-stale, ready))
		}
	}
	return lines
}
