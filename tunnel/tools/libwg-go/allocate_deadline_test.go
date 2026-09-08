/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// blockingAllocate stands in for a pion Allocate on a blackholed socket: it
// returns only once abort has been called, the way Client.Close fails the
// pending transaction.
func blockingAllocate() (allocate func() (net.PacketConn, error), abort func(), aborted *atomic.Bool) {
	release := make(chan struct{})
	aborted = &atomic.Bool{}
	allocate = func() (net.PacketConn, error) {
		<-release
		return nil, errors.New("transaction closed")
	}
	abort = func() {
		if aborted.CompareAndSwap(false, true) {
			close(release)
		}
	}
	return allocate, abort, aborted
}

// A silent Allocate is abandoned at the deadline, not at pion's 7.8s.
func TestAllocateWithDeadlineAbortsSilentAllocate(t *testing.T) {
	allocate, abort, aborted := blockingAllocate()
	start := time.Now()
	relay, err := allocateWithDeadline(context.Background(), 50*time.Millisecond, allocate, abort)
	if relay != nil || !errors.Is(err, errAllocateSilent) {
		t.Fatalf("relay=%v err=%v, want errAllocateSilent", relay, err)
	}
	if !aborted.Load() {
		t.Fatal("abort was not called")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("took %v, want about the deadline", took)
	}
}

// Cancelling the race (a sibling won, or a teardown) aborts the same way but
// reports the context, which dialAndAllocate treats as "no strike".
func TestAllocateWithDeadlineHonoursContext(t *testing.T) {
	allocate, abort, _ := blockingAllocate()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := allocateWithDeadline(ctx, time.Minute, allocate, abort)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
}

// A prompt answer passes straight through, error or relay alike, and abort is
// never called on it.
func TestAllocateWithDeadlinePassesPromptResult(t *testing.T) {
	want := errors.New("error 486: allocation quota reached")
	var aborted atomic.Bool
	_, err := allocateWithDeadline(context.Background(), time.Minute,
		func() (net.PacketConn, error) { return nil, want },
		func() { aborted.Store(true) })
	if !errors.Is(err, want) || aborted.Load() {
		t.Fatalf("err=%v aborted=%v, want the allocate error and no abort", err, aborted.Load())
	}

	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	relay, err := allocateWithDeadline(context.Background(), time.Minute,
		func() (net.PacketConn, error) { return pc, nil },
		func() { aborted.Store(true) })
	if relay != pc || err != nil || aborted.Load() {
		t.Fatalf("relay=%v err=%v aborted=%v", relay, err, aborted.Load())
	}
	pc.Close()
}

// An allocation that lands after the deadline is released, not leaked.
func TestAllocateWithDeadlineClosesLateRelay(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	release := make(chan struct{})
	_, err := allocateWithDeadline(context.Background(), 20*time.Millisecond,
		func() (net.PacketConn, error) { <-release; return pc, nil },
		func() { close(release) })
	if !errors.Is(err, errAllocateSilent) {
		t.Fatalf("err=%v", err)
	}
	if _, werr := pc.WriteTo([]byte{0}, pc.LocalAddr()); werr == nil {
		t.Fatal("late relay was left open")
	}
}
