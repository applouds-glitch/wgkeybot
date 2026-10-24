/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync"
)

// sessionReadiness owns one transport session's claim on s.ready. It withdraws
// that claim as soon as teardown begins, before waiting for the other goroutines
// or closing the TURN allocation. Dispatch and WGH1 must stop using it then.
//
// Invariant: end never clears a ready flag this session did not set. runDTLS
// returns after a failed handshake without waiting for its two relay-pipe
// goroutines; their late end calls must not clear the NEXT session's ready flag.
// A session that published waits for all its goroutines (wg.Wait) before its
// transport returns, so their end calls precede the next session. end is
// idempotent, including late context callbacks after the first end.
type sessionReadiness struct {
	mu        sync.Mutex
	s         *stream
	ctx       context.Context
	cancel    context.CancelFunc
	ending    bool
	published bool
}

func newSessionReadiness(ctx context.Context, cancel context.CancelFunc, s *stream) *sessionReadiness {
	return &sessionReadiness{s: s, ctx: ctx, cancel: cancel}
}

func (r *sessionReadiness) publish() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ending || r.ctx.Err() != nil {
		return false
	}
	r.published = true
	r.s.ready.Store(true)
	return true
}

func (r *sessionReadiness) end() {
	r.mu.Lock()
	if r.ending {
		r.mu.Unlock()
		return
	}
	r.ending = true
	if r.published {
		r.s.ready.Store(false)
	}
	r.mu.Unlock()
	r.cancel()
}
