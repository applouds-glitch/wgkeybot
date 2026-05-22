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
	"time"
)

// TunnelGroupsConfig — configuration for launching multiple WorkerGroups.
type TunnelGroupsConfig struct {
	Links           []string
	PeerAddr        *net.UDPAddr
	PeerType        string
	UseUDP          bool
	TurnIP          string
	TurnPort        int
	StreamsPerGroup int
	Cert            *tls.Certificate
	SessionID       []byte
	PauseFlag       *int32
	WatchdogTimeout int
	WrapKey         []byte // ← добавить: 32 байта = WRAP включён, nil = выключен
}

// StartTunnelGroups launches N WorkerGroups concurrently.
// Credential fetches are still serialised by groupFetchMu inside WorkerGroup,
// but TURN/DTLS connections are established in parallel across groups.
// Returns cancel, okChan (first ready stream signal), done (closed once every
// WorkerGroup has fully exited), error.
func StartTunnelGroups(ctx context.Context, lc net.PacketConn, cfg TunnelGroupsConfig) (context.CancelFunc, <-chan struct{}, <-chan struct{}, error) {
	if len(cfg.Links) == 0 {
		return nil, nil, nil, fmt.Errorf("no links provided")
	}
	n := cfg.StreamsPerGroup
	if n <= 0 {
		n = streamsPerCred
	}
	wd := cfg.WatchdogTimeout

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

	totalStreams := len(cfg.Links) * n
	allStreams := make([]*stream, totalStreams)
	for i := range allStreams {
		allStreams[i] = &stream{
			ctx:             gCtx,
			id:              i,
			in:              make(chan []byte, 512),
			out:             lc,
			sessionID:       cfg.SessionID,
			cert:            cfg.Cert,
			watchdogTimeout: wd,
			okFunc:          okFunc,
			wrapKey:         cfg.WrapKey, // ← добавить
		}
	}

	var pauseFlag int32
	if cfg.PauseFlag == nil {
		cfg.PauseFlag = &pauseFlag
	}

	var groupsWg sync.WaitGroup
	for gi, link := range cfg.Links {
		if gi > 0 {
			// Jittered gap between group launches so multi-stream setups from
			// a single IP don't hit the TURN server at exactly the same time.
			baseDelay := 150 * time.Millisecond
			jitter := time.Duration(rand.Intn(100)) * time.Millisecond
			time.Sleep(baseDelay + jitter)
		}

		groupStreams := allStreams[gi*n : gi*n+n]

		groupCfg := WorkerGroupConfig{
			GroupID:   gi,
			Link:      link,
			PeerAddr:  cfg.PeerAddr,
			UseUDP:    cfg.UseUDP,
			PeerType:  cfg.PeerType,
			TurnIP:    cfg.TurnIP,
			TurnPort:  cfg.TurnPort,
			PauseFlag: cfg.PauseFlag,
		}

		groupsWg.Add(1)
		go func() {
			defer groupsWg.Done()
			WorkerGroup(gCtx, groupCfg, groupStreams)
		}()
		turnLog("[INIT] Group %d started (link=%.12s, streams %d-%d)", gi, link, gi*n, gi*n+n-1)
	}

	// done closes once every WorkerGroup has fully exited. Each WorkerGroup's
	// deferred killBatch waits for its workers, whose runWithCreds defers run
	// relayConn.Close() → TURN Refresh(lifetime=0). Waiting on done therefore
	// means every server-side allocation has been told to release.
	done := make(chan struct{})
	go func() {
		groupsWg.Wait()
		close(done)
	}()

	// Chunked dispatcher: sends chunkSize consecutive packets through the
	// same stream before rotating, preserving packet order within a chunk.
	// Reduces WireGuard-level reordering caused by per-stream latency variance
	// across independent DTLS/TURN paths.
	go func() {
		nStreams := totalStreams
		const chunkSize = 8
		lastUsed := 0
		packetsInChunk := 0
		for {
			b := packetPool.Get().([]byte)[:iPacketBuffMaxSize]
			nRead, addr, err := lc.ReadFrom(b)
			if err != nil {
				packetPool.Put(b[:cap(b)])
				return
			}

			var s *stream
			for i := 0; i < nStreams; i++ {
				st := allStreams[(lastUsed+i)%nStreams]
				if st.ready.Load() {
					s = st
					break
				}
			}
			if s == nil {
				packetPool.Put(b[:cap(b)])
				continue
			}

			packetsInChunk++
			returnAddr := addr
			s.peer.Store(&returnAddr)
			select {
			case s.in <- b[:nRead]:
			default:
				packetPool.Put(b[:cap(b)])
			}

			if packetsInChunk >= chunkSize {
				lastUsed = (lastUsed + 1) % nStreams
				packetsInChunk = 0
			}
		}
	}()

	return gCancel, okChan, done, nil
}
