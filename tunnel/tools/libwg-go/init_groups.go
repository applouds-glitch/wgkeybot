/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
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
}

// StartTunnelGroups launches N WorkerGroups concurrently.
// Credential fetches are still serialised by groupFetchMu inside WorkerGroup,
// but TURN/DTLS connections are established in parallel across groups.
// Returns cancel, okChan (first ready stream signal), error.
func StartTunnelGroups(ctx context.Context, lc net.PacketConn, cfg TunnelGroupsConfig) (context.CancelFunc, <-chan struct{}, error) {
	if len(cfg.Links) == 0 {
		return nil, nil, fmt.Errorf("no links provided")
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
		}
	}

	var pauseFlag int32
	if cfg.PauseFlag == nil {
		cfg.PauseFlag = &pauseFlag
	}

	for gi, link := range cfg.Links {
		groupStreams := allStreams[gi*n : gi*n+n]

		groupCfg := WorkerGroupConfig{
			GroupID:  gi,
			Link:     link,
			PeerAddr: cfg.PeerAddr,
			UseUDP:   cfg.UseUDP,
			PeerType: cfg.PeerType,
			TurnIP:   cfg.TurnIP,
			TurnPort: cfg.TurnPort,
			PauseFlag: cfg.PauseFlag,
		}

		go WorkerGroup(gCtx, groupCfg, groupStreams)
		turnLog("[INIT] Group %d started (link=%.12s, streams %d-%d)", gi, link, gi*n, gi*n+n-1)
	}

	// Round-robin dispatcher: routes incoming UDP packets to ready streams
	go func() {
		nStreams := totalStreams
		lastUsed := 0
		for {
			b := packetPool.Get().([]byte)[:iPacketBuffMaxSize]
			nRead, addr, err := lc.ReadFrom(b)
			if err != nil {
				packetPool.Put(b[:cap(b)])
				return
			}

			lastUsed = (lastUsed + 1) % nStreams
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

			returnAddr := addr
			s.peer.Store(&returnAddr)
			select {
			case s.in <- b[:nRead]:
			default:
				packetPool.Put(b[:cap(b)])
			}
		}
	}()

	return gCancel, okChan, nil
}
