/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"testing"
)

func TestSessionReadiness(t *testing.T) {
	t.Run("publish_then_end", func(t *testing.T) {
		s := &stream{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ready := newSessionReadiness(ctx, cancel, s)
		if !ready.publish() || !s.ready.Load() {
			t.Fatal("publish did not make the stream ready")
		}
		ready.end()
		if s.ready.Load() || ctx.Err() == nil {
			t.Fatalf("end left ready=%v, ctx.Err()=%v", s.ready.Load(), ctx.Err())
		}
		// Late repeats must not withdraw the following session's claim.
		nextCtx, nextCancel := context.WithCancel(context.Background())
		defer nextCancel()
		next := newSessionReadiness(nextCtx, nextCancel, s)
		defer next.end()
		if !next.publish() {
			t.Fatal("next session did not publish")
		}
		ready.end()
		if !s.ready.Load() {
			t.Fatal("repeated end cleared the next session's ready flag")
		}
	})
	t.Run("end_before_publish", func(t *testing.T) {
		s := &stream{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ready := newSessionReadiness(ctx, cancel, s)
		ready.end()
		if s.ready.Load() || ready.publish() || s.ready.Load() {
			t.Fatal("an ended session published ready")
		}
		if ctx.Err() == nil {
			t.Fatal("end did not cancel the session")
		}
	})
	t.Run("cancel_before_publish", func(t *testing.T) {
		s := &stream{}
		ctx, cancel := context.WithCancel(context.Background())
		ready := newSessionReadiness(ctx, cancel, s)
		defer ready.end()
		cancel()
		if ready.publish() || s.ready.Load() {
			t.Fatal("a cancelled session published ready")
		}
	})
	t.Run("unpublished_end_preserves_next_session", func(t *testing.T) {
		s := &stream{}
		oldCtx, oldCancel := context.WithCancel(context.Background())
		defer oldCancel()
		old := newSessionReadiness(oldCtx, oldCancel, s)
		nextCtx, nextCancel := context.WithCancel(context.Background())
		defer nextCancel()
		next := newSessionReadiness(nextCtx, nextCancel, s)
		defer next.end()
		if !next.publish() {
			t.Fatal("next session did not publish")
		}
		// A late relay-pipe exit after the old DTLS handshake failed.
		old.end()
		if !s.ready.Load() {
			t.Fatal("unpublished session end cleared the next session's ready flag")
		}
	})
}
