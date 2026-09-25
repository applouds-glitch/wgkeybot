/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// groupLaunchStagger is the pause between consecutive WorkerGroup launches.
	// It used to be ~2s "so TURN allocations and VK credential fetches are
	// staggered across groups", but both reasons have since moved elsewhere:
	// wgTurnProxyStart pre-fetches every group's credential before this runs,
	// so a group's first fetch is a cache hit, and Allocate is paced by the
	// per-relay Allocate slots (allocSlots) and workerStagger regardless of
	// which group a stream belongs to. What is left is only to keep the first streams of adjacent
	// groups from dialing in the same instant — a few hundred milliseconds do
	// that, and the last of three groups no longer starts 4-5s late for
	// nothing.
	groupLaunchStagger       = 300 * time.Millisecond
	groupLaunchStaggerJitter = 200 * time.Millisecond
)

// dispatchDropCount counts WireGuard packets the dispatcher could not hand to
// any stream because every ready stream's queue was full. Dropping here is
// indistinguishable from loss on the far side, so it is logged — sparsely,
// since a saturated pool would otherwise flood the log at line rate.
var dispatchDropCount atomic.Uint64

// What the dispatcher did about streams whose sockets had stopped sending
// (stream.sendStalled), for the TCP summary (relay_tcp_watch.go): packets it
// took past such a stream to a sibling, and packets it had to put into one
// because no other ready stream could take them.
var (
	dispatchSteeredCount     atomic.Uint64
	dispatchIntoStalledCount atomic.Uint64
)

// anyReady separates the two causes: a saturated pool (every ready stream's
// queue full) from a pool with nothing ready at all, which is the normal state
// for the first moments after start.
func noteDispatchDrop(anyReady bool) {
	n := dispatchDropCount.Add(1)
	if n != 1 && n%1000 != 0 {
		return
	}
	if anyReady {
		turnLog("[DISPATCH] Every ready stream's queue was full — %d packets dropped this session", n)
	} else {
		turnLog("[DISPATCH] No stream ready yet — %d packets dropped this session", n)
	}
}

// TunnelGroupsConfig — configuration for launching multiple WorkerGroups.
type TunnelGroupsConfig struct {
	Links           []string
	PeerAddr        *net.UDPAddr
	PeerType        string
	UseUDP          bool
	TurnIP          string
	TurnPort        int
	StreamsPerGroup int
	// TotalStreams is the stream count to spread over Links. It may be less
	// than len(Links)*StreamsPerGroup, in which case the last group is short —
	// StreamsPerGroup is a group's capacity, not its guaranteed size. Zero
	// means "fill every group", the old behaviour.
	TotalStreams    int
	Cert            *tls.Certificate
	SessionID       []byte
	WatchdogTimeout int
	WrapKey         []byte // ← добавить: 32 байта = WRAP включён, nil = выключен
}

// StartTunnelGroups launches N WorkerGroups concurrently.
// Credential fetches are serialised per cache slot by the slot's cache.mutex
// (single-flight) and globally throttled by vkSemaphore, but TURN/DTLS
// connections are established in parallel across groups.
// Returns cancel, okChan (first ready stream signal), done (closed once every
// WorkerGroup has fully exited), error.
func StartTunnelGroups(ctx context.Context, lc net.PacketConn, cfg TunnelGroupsConfig) (context.CancelFunc, <-chan struct{}, <-chan struct{}, error) {
	if len(cfg.Links) == 0 {
		return nil, nil, nil, fmt.Errorf("no links provided")
	}
	n := cfg.StreamsPerGroup
	if n <= 0 {
		n = streamsPerCredValue()
	}
	wd := cfg.WatchdogTimeout
	dispatchDropCount.Store(0)

	gCtx, gCancel := context.WithCancel(ctx)

	// okChan signals the first ready stream; okFunc is stored on each stream and
	// called from runDTLS/runNoDTLS directly — no polling goroutines needed.
	okChan := make(chan struct{}, 1)
	var okOnce sync.Once
	okFunc := func() {
		okOnce.Do(func() {
			select {
			case okChan <- struct{}{}:
			default:
			}
		})
	}

	totalStreams := cfg.TotalStreams
	if totalStreams <= 0 || totalStreams > len(cfg.Links)*n {
		totalStreams = len(cfg.Links) * n
	}
	// Terminal-failure accounting: the session is only reported as dead once every
	// one of these workers has given up for good (see turn_fatal.go).
	resetWorkerFatalState(totalStreams)

	allStreams := make([]*stream, totalStreams)
	for i := range allStreams {
		allStreams[i] = &stream{
			ctx:             gCtx,
			id:              i,
			in:              make(chan []byte, 512),
			priority:        make(chan []byte, tcpPriorityQueueSize),
			out:             lc,
			sessionID:       cfg.SessionID,
			cert:            cfg.Cert,
			watchdogTimeout: wd,
			okFunc:          okFunc,
			wrapKey:         cfg.WrapKey, // ← добавить
			// Slice the keepalive window by the actual stream count, so every
			// stream gets its own slot whatever the configured fan-out.
			kaPhase: keepalivePhase(i, totalStreams),
			wrapTx:  newWrapTxState(), // per-stream RTP SSRC + counter → distinct ChaCha nonce
			// Every peer type that ends at vk-turn-proxy: its WRAP, DTLS and SRTP
			// paths all answer WGH1. A server that predates it echoes HELLO as a
			// plain STUN keepalive, never ACKs, and so is never sent a report.
			feedbackEnabled: cfg.PeerType == "proxy_v2" || cfg.PeerType == "wireguard" || cfg.PeerType == "srtp",
		}
	}

	// One reporter for the whole session UUID, across every credential group:
	// the server keeps a single downstream-health mask per session.
	feedbackCtx, feedbackCancel := context.WithCancel(gCtx)
	feedbackDone := make(chan struct{})
	go func() {
		defer close(feedbackDone)
		runDownlinkFeedback(feedbackCtx, allStreams)
	}()

	// What the relay connections are doing, for the streams that run over TCP;
	// asleep while none does (relay_tcp_watch.go).
	go relaySockets.run(gCtx, allStreams)
	withdrawStreams := publishStreams(allStreams)

	var groupsWg sync.WaitGroup
	// The cascade below sleeps between groups, so it is launched in its own
	// goroutine: run inline it delayed everything after it — including the packet
	// dispatcher — by the whole cascade (2s per group back then, ~7s at four
	// groups) during which 127.0.0.1:9000 was bound but nobody drained it.
	// Stream 0 is typically ready within a second, so those were WireGuard
	// handshakes sitting in the socket buffer (or dropped) while a working path
	// was already available.
	//
	// The extra Add(1) is held by the launcher itself: without it groupsWg could
	// reach zero — and close done — before the first group had been added.
	groupsWg.Add(1)
	go func() {
		defer groupsWg.Done()
		for gi, link := range cfg.Links {
			// The last group is short whenever TotalStreams isn't a multiple of n.
			// Checked before the cascade sleep so a group with nothing to run
			// doesn't cost 2s on startup.
			start := gi * n
			if start >= totalStreams {
				break
			}
			end := start + n
			if end > totalStreams {
				end = totalStreams
			}

			if gi > 0 {
				// Cascading group launch (see groupLaunchStagger). Abandoned on
				// cancellation so a stop during startup doesn't keep launching
				// groups for a proxy that is already gone.
				jitter := time.Duration(rand.Int63n(int64(groupLaunchStaggerJitter)))
				select {
				case <-time.After(groupLaunchStagger + jitter):
				case <-gCtx.Done():
					return
				}
			}

			groupStreams := allStreams[start:end]

			groupCfg := WorkerGroupConfig{
				GroupID:  gi,
				Link:     link,
				PeerAddr: cfg.PeerAddr,
				UseUDP:   cfg.UseUDP,
				PeerType: cfg.PeerType,
				TurnIP:   cfg.TurnIP,
				TurnPort: cfg.TurnPort,
			}

			groupsWg.Add(1)
			go func() {
				defer groupsWg.Done()
				WorkerGroup(gCtx, groupCfg, groupStreams)
			}()
			turnLog("[INIT] Group %d started (streams %d-%d)", gi, start, end-1)
		}
	}()

	// done closes once every WorkerGroup has fully exited. Each WorkerGroup waits
	// (via its WaitGroup) for its workers, whose runWithCreds defers
	// relayConn.Close() → TURN Refresh(lifetime=0). Waiting on done therefore
	// means every server-side allocation has been told to release.
	done := make(chan struct{})
	go func() {
		groupsWg.Wait()
		withdrawStreams()
		feedbackCancel()
		<-feedbackDone
		close(done)
	}()

	// UDP uses eight-packet chunks. TCP adapts bulk chunks to packet size and
	// rotates small priority packets independently (see chunkRotor).
	go func() {
		rotor := newChunkRotor(totalStreams)
		stale := newStaleWatch(totalStreams)
		// Broadcast the WG source addr to every stream so each stream's RX
		// can forward responses back to WG even if the dispatcher never
		// picked it for TX. (The server's backendLoop round-robins peer
		// responses across all registered streams, so a stream the client
		// never TX'd through still receives RX packets; without an addr
		// stored those packets hit s.peer.Load() == nil and are dropped.)
		// WG's UDP source port is stable for the tunnel's lifetime, so we
		// only re-broadcast when the address actually changes. The comparison
		// avoids addr.String() — that formatted a fresh string on every single
		// packet just to detect a change that happens once per tunnel. lc is a
		// *net.UDPConn, so ReadFrom always yields *net.UDPAddr; lastAddrStr
		// keeps the old behaviour for any other net.Addr implementation.
		var lastAddr *net.UDPAddr
		var lastAddrStr string
		for {
			b := packetPool.Get().([]byte)[:iPacketBuffMaxSize]
			nRead, addr, err := lc.ReadFrom(b)
			if err != nil {
				packetPool.Put(b[:cap(b)])
				return
			}

			changed := false
			if ua, ok := addr.(*net.UDPAddr); ok {
				changed = lastAddr == nil || ua.Port != lastAddr.Port || !ua.IP.Equal(lastAddr.IP)
				if changed {
					lastAddr = ua
				}
			} else if curStr := addr.String(); curStr != lastAddrStr {
				changed = true
				lastAddrStr = curStr
			}
			if changed {
				returnAddr := addr
				for _, st := range allStreams {
					st.peer.Store(&returnAddr)
				}
			}

			now := time.Now()
			for _, line := range stale.observe(allStreams, now) {
				turnLog("%s", line)
			}
			overTCP := relayOverTCP(WorkerGroupConfig{UseUDP: cfg.UseUDP})
			sent, anyReady := dispatchPacket(allStreams, rotor.startPacket(now, nRead, overTCP), now, b[:nRead])
			if !sent {
				packetPool.Put(b[:cap(b)])
				noteDispatchDrop(anyReady)
				continue
			}
			rotor.sentPacket(now, nRead, overTCP)
		}
	}()

	return gCancel, okChan, done, nil
}

// dispatchPacket hands pkt to one ready stream, searching from start and
// wrapping around, and reports whether it was accepted and whether any stream
// was ready at all — the two dispatch-drop causes noteDispatchDrop tells apart.
//
// Up to three passes, each run only when the one before placed nothing.
//
// The first skips streams whose relay has gone quiet (dispatchStale): a stream
// stays ready until its dead-stream detector fires 90s after the last echo,
// and the plain round-robin used to keep feeding it every Nth chunk for that
// whole time — a steady 1/N loss that TCP inside the tunnel reads as
// congestion. The second pass admits stale streams: with every stream silent
// it is the uplink that is down, not a relay, and placing nothing would only
// add a drop of our own to whatever the network is already losing.
//
// Both skip a stream whose TCP socket has stopped moving what we send
// (sendStalled). Silence does not catch that one: on the network the TCP path
// exists for, the direction up dies on its own while the relay stays audible
// (field log of 22.09: 45 flows dead in sixteen minutes, not one stream ever
// judged silent), and each such flow was fed its 1/N until a reset or the
// kernel's 30s limit ended it. Only the third pass, run when a stalled socket
// was passed over and nothing else took the packet, admits one: there is
// nowhere better, and the packet waits in a socket that may yet move rather
// than being dropped here.
//
// Within a pass a full queue is not a drop either: the packet spills to the
// next candidate, so one stream whose TX goroutine has stalled (a slow relay, a
// reconnect in progress) cannot eat its whole 8-packet chunk while siblings sit
// idle. Spilling costs nothing when the queues are empty — the first candidate
// accepts — and keeps the loss confined to a genuinely saturated pool.
func dispatchPacket(streams []*stream, start int, now time.Time, pkt []byte) (sent, anyReady bool) {
	n := len(streams)
	// skip is each pass's test. It notes a stalled socket passed over: a
	// placement after one counts as steered, and without one the last pass
	// would only repeat the second.
	passedStalled := false
	skip := func(st *stream, pass int) bool {
		if pass < 2 && st.sendStalled.Load() {
			passedStalled = true
			return true
		}
		return pass == 0 && st.dispatchStale(now)
	}
	placed := func(st *stream, pass int) (bool, bool) {
		switch {
		case pass < 2 && passedStalled:
			dispatchSteeredCount.Add(1)
		case pass == 2 && st.sendStalled.Load():
			dispatchIntoStalledCount.Add(1)
		}
		return true, true
	}
	for pass := 0; pass < 3; pass++ {
		if pass == 2 && !passedStalled {
			break
		}
		// Prefer available priority queues across fresh TCP streams before
		// falling back to their normal queues. Stale priority queues must not
		// outrank a fresh stream's ordinary queue.
		if len(pkt) <= tcpPriorityPacketSize {
			for i := 0; i < n; i++ {
				st := streams[(start+i)%n]
				if !st.ready.Load() || skip(st, pass) {
					continue
				}
				if st.enqueuePriority(pkt) {
					return placed(st, pass)
				}
			}
		}
		for i := 0; i < n; i++ {
			st := streams[(start+i)%n]
			if !st.ready.Load() {
				continue
			}
			anyReady = true
			if skip(st, pass) {
				continue
			}
			select {
			case st.in <- pkt:
				return placed(st, pass)
			default:
			}
		}
		if !anyReady {
			return false, false
		}
	}
	return false, true
}
