/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// fakeAsker answers CreatePermission with a scripted sequence of errors. With
// entered/release set, a call announces itself and then stays inside until
// released — a check in flight for as long as the test wants.
type fakeAsker struct {
	mu      sync.Mutex
	answers []error
	asked   int
	entered chan struct{}
	release chan struct{}
}

func (f *fakeAsker) CreatePermission(...net.Addr) error {
	if f.entered != nil {
		f.entered <- struct{}{}
	}
	if f.release != nil {
		<-f.release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.asked
	f.asked++
	if i < len(f.answers) {
		return f.answers[i]
	}
	return nil
}

func (f *fakeAsker) times() int { f.mu.Lock(); defer f.mu.Unlock(); return f.asked }

func refused(code stun.ErrorCode, reason string) error {
	return &stun.TurnError{
		StunMessageType: stun.NewType(stun.MethodCreatePermission, stun.ClassErrorResponse),
		ErrorCodeAttr:   stun.ErrorCodeAttribute{Code: code, Reason: []byte(reason)},
	}
}

func testAllocCheck(asker permissionAsker) (*allocCheck, *permWatch) {
	w := newPermWatch(4)
	peer := &net.UDPAddr{IP: net.IPv4(31, 70, 79, 228), Port: 56000}
	return &allocCheck{streamID: 4, client: asker, peer: peer, perm: w}, w
}

func waitAsked(t *testing.T, f *fakeAsker, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.times() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("asked %d times, want %d", f.times(), n)
}

func waitFired(t *testing.T, w *permWatch) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !w.fired() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !w.fired() {
		t.Fatal("the stream was not ended")
	}
}

// The relay's 400 is the verdict: the stream is ended through the blackhole
// path with a reason no classifier reads as the credential's fault.
func TestAllocationCheckEndsTheStreamOnBadRequest(t *testing.T) {
	f := &fakeAsker{answers: []error{refused(stun.CodeBadRequest, "Bad Request")}}
	c, w := testAllocCheck(f)
	c.run("thaw")
	waitAsked(t, f, 1)
	waitFired(t, w)
	if !strings.Contains(w.why(), "400") {
		t.Errorf("reason %q does not carry the relay's answer", w.why())
	}
	sessionErr := fmt.Errorf("TURN blackhole: %s", w.why())
	if classifyCredError(sessionErr) || isTransportError(sessionErr) {
		t.Errorf("%q was read as a credential or transport error", sessionErr)
	}
}

// A success, a timeout or another refusal is no verdict.
func TestAllocationCheckHasNoVerdictWithoutA400(t *testing.T) {
	for name, answer := range map[string]error{
		"alive":   nil,
		"timeout": errors.New("all retransmissions failed for x"),
		"other":   refused(stun.CodeForbidden, "Forbidden"),
	} {
		f := &fakeAsker{answers: []error{answer}}
		c, w := testAllocCheck(f)
		c.run("wake")
		waitAsked(t, f, 1)
		time.Sleep(20 * time.Millisecond)
		if w.fired() {
			t.Errorf("%s: the stream was ended on %v", name, answer)
		}
	}
}

// A stale nonce pion has already renewed ("try again") is asked once more.
func TestAllocationCheckRetriesAStaleNonce(t *testing.T) {
	f := &fakeAsker{answers: []error{errors.New(pionTryAgain), errors.New(pionTryAgain), refused(stun.CodeBadRequest, "Bad Request")}}
	c, w := testAllocCheck(f)
	c.run("thaw")
	waitAsked(t, f, 3)
	waitFired(t, w)
}

// One check at a time: a run while one is in flight asks nothing more; a nil
// check (no session) asks nothing at all.
func TestAllocationCheckIsNotDoubledAndNilIsInert(t *testing.T) {
	f := &fakeAsker{entered: make(chan struct{}), release: make(chan struct{})}
	c, _ := testAllocCheck(f)
	c.run("thaw")
	<-f.entered // the first ask is inside CreatePermission now, and stays there
	c.run("wake")
	c.run("wake")
	close(f.release)
	waitAsked(t, f, 1)
	time.Sleep(20 * time.Millisecond)
	if n := f.times(); n != 1 {
		t.Fatalf("asked %d times with one in flight, want 1", n)
	}
	s := &stream{id: 1}
	s.runAllocCheck("thaw") // nil pointer: nothing to ask
	var none *allocCheck
	none.run("thaw")
}
