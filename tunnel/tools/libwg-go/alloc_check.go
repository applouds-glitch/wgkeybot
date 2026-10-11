/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"net"
	"sync/atomic"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// The allocation check. At a thaw, and at a wake() the probe is due for, the
// relay itself is asked whether this session's allocation still exists: one
// CreatePermission for the peer every transport sends to. The relay answers
// within a round trip — a success installs the permission the session would
// refresh anyway; a 400 says this socket HAS NO allocation (anton48
// vk-turn-proxy-ios build 432, stand-measured: expired, given back, or out of
// reach behind a mapping the translator forgot in the silence) — and the
// session is dead now, not after thirty seconds of listening for an echo.
//
// Field 2026-09-28, build 10, Wi-Fi: every stream died in freezes of 1m18s and
// 2m43s. The probe found them dead at 30 s of listening and the tunnel stood
// 35 s; where the refresh timers happened to be due at the thaw, the same 400
// recycled them within 6 s and the tunnel stood 5. This asks for that answer
// on purpose, every time.
//
// No answer (a timeout, a network still coming up) is no verdict: the probe
// and the periodic detector go on. Any other refusal is logged and left to
// permWatch's own accounting. The verdict travels the blackhole path
// (permWatch.markDead → the session's watchdog closes the relay → runWithCreds
// re-dials), whose reason classifyCredError never reads as the credential's
// fault: a 400 names no quota and no auth.

// permissionAsker is the one call the check makes; *turn.Client is the
// production one, tests hand in a fake relay's answer.
type permissionAsker interface {
	CreatePermission(addrs ...net.Addr) error
}

var _ permissionAsker = (*turn.Client)(nil)

type allocCheck struct {
	streamID int
	client   permissionAsker
	peer     net.Addr
	perm     *permWatch
	inFlight atomic.Bool
}

// newAllocCheck: nil for a nil peer or client — a check that never asks.
func newAllocCheck(streamID int, client *turn.Client, peer net.Addr, perm *permWatch) *allocCheck {
	if client == nil || peer == nil || perm == nil {
		return nil
	}
	return &allocCheck{streamID: streamID, client: client, peer: peer, perm: perm}
}

// pionTryAgain is how pion reports a stale nonce it has already renewed
// (internal/client/errors.go errTryAgain): the same request goes out again.
const pionTryAgain = "try again"

// run asks once, off the caller's goroutine (pion's transaction waits for the
// answer); a check already in flight is not doubled.
func (c *allocCheck) run(why string) {
	if c == nil || !c.inFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer c.inFlight.Store(false)
		var err error
		for tries := 0; tries < 3; tries++ {
			err = c.client.CreatePermission(c.peer)
			if err == nil || err.Error() != pionTryAgain {
				break
			}
		}
		if err == nil {
			return
		}
		if code, ok := turnErrorCode(err); ok && code == stun.CodeBadRequest {
			turnLog("[STREAM %d] allocation check (%s): CreatePermission answered 400 — the relay has no allocation for this socket", c.streamID, why)
			c.perm.markDead(fmt.Sprintf("allocation check after %s: %v", why, err))
			return
		}
		turnLog("[STREAM %d] allocation check (%s): no verdict (%v)", c.streamID, why, err)
	}()
}

// runAllocCheck is the keepalive loop's call: the session installs its check
// on the stream for as long as it runs (runSession).
func (s *stream) runAllocCheck(why string) {
	if c := s.allocCheck.Load(); c != nil {
		c.run(why)
	}
}
