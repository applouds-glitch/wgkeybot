/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"testing"
	"time"
)

func wgInitiation() []byte {
	b := packetPool.Get().([]byte)[:148]
	for i := range b {
		b[i] = 0
	}
	b[0] = 1
	return b
}

func TestIsWireGuardInitiation(t *testing.T) {
	if !isWireGuardInitiation(wgInitiation()) {
		t.Fatal("a 148-byte type-1 message is not read as an initiation")
	}
	if isWireGuardInitiation(wgInitiation()[:100]) {
		t.Fatal("a short packet read as an initiation")
	}
	transport := wgInitiation()
	transport[0] = 4
	if isWireGuardInitiation(transport) {
		t.Fatal("a transport packet read as an initiation")
	}
}

// While every stream is silent, the initiation waits; the moment one stream
// hears its relay, the newest one goes out.
func TestInitiationIsHeldUntilAStreamIsProven(t *testing.T) {
	now := time.Now()
	streams := []*stream{dispatchStream(0, true, now.Add(-time.Minute), 8), dispatchStream(1, true, now.Add(-time.Minute), 8)}
	h := &thawHold{}
	sent := make(chan []byte, 1)
	send := func(p []byte, _ time.Time) bool { sent <- p; return true }

	if h.offer(wgInitiation()[:100], true, now, streams, send) {
		t.Fatal("a data packet was held")
	}
	if h.offer(wgInitiation(), false, now, streams, send) {
		t.Fatal("an initiation was held while a stream was proven")
	}
	if !h.offer(wgInitiation(), true, now, streams, send) {
		t.Fatal("an initiation was not held while every stream was silent")
	}
	select {
	case <-sent:
		t.Fatal("the held initiation went out before any stream was proven")
	case <-time.After(150 * time.Millisecond):
	}
	second := wgInitiation()
	second[5] = 0x7f
	if !h.offer(second, true, time.Now(), streams, send) {
		t.Fatal("a newer initiation was not taken")
	}
	streams[1].activity.Load().noteRx(time.Now()) // stream 1 hears its relay
	select {
	case p := <-sent:
		if p[5] != 0x7f {
			t.Fatal("the older initiation went out, want the newest")
		}
	case <-time.After(time.Second):
		t.Fatal("the initiation was not released once a stream was proven")
	}
}

// Nobody proves themselves: the initiation goes out anyway at thawHoldMax.
func TestHeldInitiationIsReleasedOnTimeout(t *testing.T) {
	old := thawHoldMax
	thawHoldMax = 120 * time.Millisecond
	t.Cleanup(func() { thawHoldMax = old })
	now := time.Now()
	streams := []*stream{dispatchStream(0, true, now.Add(-time.Minute), 8)}
	h := &thawHold{}
	sent := make(chan []byte, 1)
	t0 := time.Now()
	if !h.offer(wgInitiation(), true, now, streams, func(p []byte, _ time.Time) bool { sent <- p; return true }) {
		t.Fatal("not held")
	}
	select {
	case <-sent:
		if el := time.Since(t0); el < 100*time.Millisecond {
			t.Errorf("released after %s, before the window", el)
		}
	case <-time.After(time.Second):
		t.Fatal("the initiation was never released")
	}
}
