/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import "context"

const (
	tcpPriorityPacketSize = 128
	tcpPriorityQueueSize  = 32
	priorityBurstLimit    = 8
)

// enqueuePriority only transfers ownership on success. A nil/full priority
// queue leaves the caller free to try another stream or the ordinary queue.
func (s *stream) enqueuePriority(pkt []byte) bool {
	if !s.overTCP.Load() {
		return false
	}
	select {
	case s.priority <- pkt:
		return true
	default:
		return false
	}
}

// drainOutbound empties both of the stream's queues and says how many packets it
// dropped; called between sessions, never while a TX goroutine is reading them.
//
// The queues belong to the stream, not to a session, and outlive every session
// on it. That is harmless while sessions end because something failed at once —
// but a stream whose writer is stuck stays ready and "fresh" for up to
// dispatchStaleAfter, and the dispatcher goes on filling it: over TCP a hung
// flow blocks the writer in the socket until the kernel gives the flow up
// (relayTCPUserTimeout), with the queue full behind it. The worker then redials
// — seconds, more with the connects paced — and the first thing the new session
// did was pour what had been queued before all that into the relay, up to the
// queues' 512+32: data the inner TCP has long retransmitted another way,
// handshakes that were answered or given up. Dropped instead; WireGuard treats
// it as the loss it already was.
//
// It is called twice per reconnect (runWithCreds on the way out, runSession on
// the way in) because neither sender is atomic with the ready flag: the
// dispatcher may still be placing a packet it chose this stream for just before
// ready went false, and so may the feedback reporter. What slips in after the
// second call is a packet or two from the last instant, not a backlog; a hard
// boundary would take per-session queues. A WGH1 REPORT dropped here is no loss
// either: reports are repeated, and the capability they rest on is per attempt
// anyway.
func (s *stream) drainOutbound() int {
	dropped := 0
	for _, q := range []chan []byte{s.priority, s.in} {
		for drained := false; !drained && q != nil; {
			select {
			case pkt, ok := <-q:
				if !ok {
					drained = true
					break
				}
				packetPool.Put(pkt[:cap(pkt)])
				dropped++
			default:
				drained = true
			}
		}
	}
	return dropped
}

// outboundReader belongs to one session's TX goroutine. Prefer small packets
// already queued, but admit ordinary data after a bounded priority burst. This
// cannot overtake bytes that have already been written into the TCP socket.
type outboundReader struct {
	s           *stream
	priorityRun int
}

func (r *outboundReader) next(ctx context.Context) ([]byte, bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	if r.priorityRun >= priorityBurstLimit {
		select {
		case pkt, ok := <-r.s.in:
			r.priorityRun = 0
			return pkt, ok
		default:
		}
	}
	select {
	case pkt, ok := <-r.s.priority:
		r.priorityRun = min(r.priorityRun+1, priorityBurstLimit)
		return pkt, ok
	default:
	}
	select {
	case <-ctx.Done():
		return nil, false
	case pkt, ok := <-r.s.priority:
		r.priorityRun = min(r.priorityRun+1, priorityBurstLimit)
		return pkt, ok
	case pkt, ok := <-r.s.in:
		r.priorityRun = 0
		return pkt, ok
	}
}
