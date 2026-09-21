/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"context"
	"testing"
	"time"
)

func TestTCPPriorityBypassesBulkWithoutStarvingIt(t *testing.T) {
	s := dispatchStream(0, true, time.Now(), 2)
	s.priority = make(chan []byte, tcpPriorityQueueSize)
	s.overTCP.Store(true)
	bulk := make([]byte, 1200)
	if sent, _ := dispatchPacket([]*stream{s}, 0, time.Now(), bulk); !sent {
		t.Fatal("bulk packet was not queued")
	}
	for i := 0; i < tcpPriorityQueueSize; i++ {
		if sent, _ := dispatchPacket([]*stream{s}, 0, time.Now(), make([]byte, 96)); !sent {
			t.Fatal("small packet was not queued")
		}
	}
	reader := outboundReader{s: s}
	for i := 0; i < priorityBurstLimit; i++ {
		if pkt, ok := reader.next(context.Background()); !ok || len(pkt) != 96 {
			t.Fatalf("small packet %d waited behind bulk", i)
		}
	}
	if pkt, ok := reader.next(context.Background()); !ok || len(pkt) != len(bulk) {
		t.Fatal("continuous priority traffic starved bulk data")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := len(s.priority)
	if _, ok := reader.next(ctx); ok || len(s.priority) != before {
		t.Fatal("cancelled writer consumed another queued packet")
	}
}

func TestTCPPriorityRespectsLivenessAndQueueFallback(t *testing.T) {
	now := time.Now()
	stale := dispatchStream(0, true, now.Add(-2*dispatchStaleAfter), 1)
	fresh := dispatchStream(1, true, now, 1)
	for _, s := range []*stream{stale, fresh} {
		s.priority = make(chan []byte, 1)
		s.overTCP.Store(true)
	}
	fresh.priority <- []byte{0}
	if sent, _ := dispatchPacket([]*stream{stale, fresh}, 0, now, []byte{1}); !sent {
		t.Fatal("small packet dropped despite a fresh ordinary queue")
	}
	if len(stale.priority) != 0 || len(fresh.in) != 1 {
		t.Fatal("stale priority queue outranked fresh ordinary traffic")
	}
	// No space in either queue: retain the normal drop decision.
	if sent, ready := dispatchPacket([]*stream{fresh}, 0, now, []byte{2}); sent || !ready {
		t.Fatalf("full queues: sent=%v ready=%v", sent, ready)
	}

	udp := dispatchStream(2, true, now, 2)
	udp.priority = make(chan []byte, 1)
	dispatchPacket([]*stream{udp}, 0, now, make([]byte, 1200))
	dispatchPacket([]*stream{udp}, 0, now, []byte{3})
	reader := outboundReader{s: udp}
	if pkt, ok := reader.next(context.Background()); !ok || len(pkt) != 1200 || len(udp.priority) != 0 {
		t.Fatal("UDP no longer preserves ordinary FIFO ordering")
	}
}

func TestTCPChunkSchedulingKeepsBulkAffinityAndBoundsDwell(t *testing.T) {
	now := time.Now()
	for _, size := range []int{200, 600, 900, 1200} {
		r := newChunkRotor(2)
		limit := map[int]int{200: 3, 600: 8, 900: 24, 1200: 64}[size]
		for i := 0; i < limit; i++ {
			if got := r.startPacket(now, size, true); got != 0 {
				t.Fatalf("%d-byte bulk switched paths at packet %d", size, i)
			}
			r.sentPacket(now, size, true)
			// ACK-sized packets must not split the bulk batch.
			r.startPacket(now, 96, true)
			r.sentPacket(now, 96, true)
		}
		if got := r.startPacket(now, size, true); got != 1 {
			t.Fatalf("%d-byte batch never rotated", size)
		}
	}
	r := newChunkRotor(2)
	r.startPacket(now, 1200, true)
	r.sentPacket(now, 1200, true)
	if got := r.startPacket(now.Add(tcpChunkMaxAge), 1200, true); got != 1 {
		t.Fatal("TCP retained a batch beyond its dwell limit")
	}

	r = newChunkRotor(2)
	for i := 0; i < 4; i++ {
		if got := r.startPacket(now, 96, true); got != i%2 {
			t.Fatal("small packets did not rotate independently")
		}
		r.sentPacket(now, 96, true)
	}
	for i := 0; i < chunkSize; i++ {
		if got := r.startPacket(now, 1200, false); got != 0 {
			t.Fatal("UDP batch size changed")
		}
		r.sentPacket(now, 1200, false)
	}
	if got := r.startPacket(now, 1200, false); got != 1 {
		t.Fatal("UDP did not rotate after its original eight packets")
	}
}
