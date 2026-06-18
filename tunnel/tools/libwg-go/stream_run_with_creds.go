/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// winner holds a successfully allocated TURN session from the race in
// runWithCreds. The fields are the live resources handed off to the session:
// runSession owns them and is responsible for closing them.
type winner struct {
	client *turn.Client
	raw    net.Conn       // underlying dialed UDP/TCP conn
	relay  net.PacketConn // relay allocation from client.Allocate()
	addr   string         // TURN server that won
	rtt    time.Duration  // Dial → Allocate latency
}

// runWithCreds establishes one TURN session with pre-fetched credentials,
// racing the candidate servers ICE-style. With raceAll every server is dialed
// at once to elect the genuinely fastest — a one-off probe done by the first
// connection in a group. Otherwise the preferred server (addrs[0]) gets a
// head-start and the rest are raced only if it does not win within
// preferredHeadStart (failover, not a probe). The first server to complete
// Allocate wins; the losers are cancelled/closed. Retry and credential rotation
// are managed by the calling WorkerGroup.
func (s *stream) runWithCreds(ctx context.Context, user, pass string, addrs []string, cfg WorkerGroupConfig, raceAll bool) error {
	s.ready.Store(false)

	// raceCtx is cancelled the moment a winner is chosen (or ctx dies) so the
	// losing racers stop dialing / abort their semaphore wait promptly.
	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	var once sync.Once
	winCh := make(chan winner, 1)
	errCh := make(chan error, len(addrs))
	var wg sync.WaitGroup

	launch := func(addr string) {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			client, raw, relay, rtt, err := dialAndAllocate(raceCtx, s, user, pass, addr, cfg)
			if err != nil {
				errCh <- err
				return
			}
			claimed := false
			once.Do(func() {
				claimed = true
				cancelRace()
				winCh <- winner{client: client, raw: raw, relay: relay, addr: addr, rtt: rtt}
			})
			if !claimed {
				// Another server won first: release this surplus allocation
				// (relayConn.Close → Refresh(lifetime=0) deallocates server-side).
				relay.Close()
				client.Close()
				raw.Close()
			}
		}(addr)
	}

	launch(addrs[0])
	launchedCount := 1
	fannedOut := len(addrs) == 1

	var grace <-chan time.Time
	fanOut := func() {
		if fannedOut {
			return
		}
		for _, a := range addrs[1:] {
			launch(a)
			launchedCount++
		}
		fannedOut = true
		grace = nil
	}

	if raceAll {
		// Probe: race every server at once to elect the genuinely fastest.
		fanOut()
	} else if !fannedOut {
		// Head-start: let the preferred server (addrs[0]) try to win alone;
		// fan out to the rest only if it does not win within the grace window.
		t := time.NewTimer(preferredHeadStart)
		defer t.Stop()
		grace = t.C
	}

	var lastErr error
	errCount := 0
	for {
		select {
		case w := <-winCh:
			return s.runSession(ctx, w, cfg)
		case err := <-errCh:
			lastErr = err
			errCount++
			if !fannedOut {
				// Preferred failed before the grace window: race the rest now.
				fanOut()
			} else if errCount == launchedCount {
				return fmt.Errorf("TURN allocate: all %d servers failed: %w", len(addrs), lastErr)
			}
		case <-grace:
			fanOut()
		case <-ctx.Done():
			cancelRace()
			// A racer may still win after we leave; reap it so the allocation
			// and sockets don't leak.
			go reapRace(&wg, winCh)
			return ctx.Err()
		}
	}
}

// dialAndAllocate dials one TURN server and performs the Allocate handshake,
// measuring the Dial→Allocate latency. On any error it closes whatever it
// opened and returns. On success the caller owns client/raw/relay. Uses ctx for
// the dial and the allocSemaphore wait so a cancelled race aborts promptly.
func dialAndAllocate(ctx context.Context, s *stream, user, pass, addr string, cfg WorkerGroupConfig) (*turn.Client, net.Conn, net.PacketConn, time.Duration, error) {
	turnLog("[STREAM %d] Dial TURN %s (group %d)", s.id, addr, cfg.GroupID)
	start := time.Now()

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
		Control: protectControl,
	}

	var turnConn net.PacketConn
	var raw net.Conn
	if cfg.UseUDP {
		c, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, nil, nil, 0, fmt.Errorf("TURN UDP dial: %w", err)
		}
		raw = c
		turnConn = &connectedUDPConn{c.(*net.UDPConn)}
	} else {
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, nil, nil, 0, fmt.Errorf("TURN TCP dial: %w", err)
		}
		raw = c
		turnConn = turn.NewSTUNConn(c)
	}

	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: addr,
		TURNServerAddr: addr,
		Username:       user,
		Password:       pass,
		Conn:           turnConn,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		raw.Close()
		return nil, nil, nil, 0, fmt.Errorf("TURN client: %w", err)
	}

	if err := client.Listen(); err != nil {
		client.Close()
		raw.Close()
		return nil, nil, nil, 0, fmt.Errorf("TURN listen: %w", err)
	}

	select {
	case allocSemaphore <- struct{}{}:
	case <-ctx.Done():
		client.Close()
		raw.Close()
		return nil, nil, nil, 0, ctx.Err()
	}
	relay, err := client.Allocate()
	<-allocSemaphore
	if err != nil {
		client.Close()
		raw.Close()
		return nil, nil, nil, 0, fmt.Errorf("TURN allocate: %w", err)
	}

	return client, raw, relay, time.Since(start), nil
}

// runSession runs the relay session on the race winner and owns its lifecycle:
// it closes the relay, client and underlying conn on exit (matching the
// pre-race defer order). It also records the winning server as the group's
// preferred (warm cache) for the next reconnect.
func (s *stream) runSession(ctx context.Context, w winner, cfg WorkerGroupConfig) error {
	defer w.raw.Close()
	defer w.client.Close()
	defer w.relay.Close()

	turnLog("[STREAM %d] Race won by %s rtt=%v (group %d)", s.id, w.addr, w.rtt, cfg.GroupID)
	turnLog("[STREAM %d] Relay: %s", s.id, w.relay.LocalAddr())
	recordPreferred(cfg.GroupID, w.addr)

	sendBinding := w.client.SendBindingRequest

	switch cfg.PeerType {
	case "wireguard":
		return s.runNoDTLS(ctx, w.relay, cfg.PeerAddr, sendBinding)
	default:
		return s.runDTLS(ctx, w.relay, cfg.PeerAddr, true, sendBinding)
	}
}

// reapRace drains any late-arriving race winner (after the caller has given up
// on ctx cancellation) and closes its resources so they don't leak. winCh holds
// at most one winner (guarded by sync.Once), so a single non-blocking drain
// after all racers have exited is sufficient.
func reapRace(wg *sync.WaitGroup, winCh chan winner) {
	wg.Wait()
	select {
	case w := <-winCh:
		w.relay.Close()
		w.client.Close()
		w.raw.Close()
	default:
	}
}
