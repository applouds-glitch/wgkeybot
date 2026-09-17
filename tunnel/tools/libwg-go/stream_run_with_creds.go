/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// errDataPlaneHandshake marks a session that allocated a relay and then never
// completed the transport handshake through it. Allocate succeeded, so the
// credential and the control plane were fine at that moment; what failed is
// either the relay's data path or the uplink underneath it, and from one stream
// the two look the same. Nothing is remembered about the relay: the worker just
// starts its next attempt from the next one (see runWorker).
var errDataPlaneHandshake = errors.New("data-plane handshake failed")

// allocateFailedError is a connect attempt in which no relay produced an
// allocation. It keeps every relay's error rather than the last one to arrive:
// whether the credential should be rotated depends on what each of them said
// (see shouldRotateCredentials), and with only the last one a 486 from one relay
// could hide behind a timeout from the other, or the other way round.
type allocateFailedError struct{ errs []error }

func (e *allocateFailedError) Error() string {
	parts := make([]string, len(e.errs))
	for i, err := range e.errs {
		parts[i] = err.Error()
	}
	return fmt.Sprintf("TURN allocate: all %d servers failed: %s", len(e.errs), strings.Join(parts, "; "))
}

func (e *allocateFailedError) Unwrap() []error { return e.errs }

// winner holds a successfully allocated TURN session from the race in
// runWithCreds. The fields are the live resources handed off to the session:
// runSession owns them and is responsible for closing them.
type winner struct {
	client            *turn.Client
	raw               net.Conn       // underlying dialed UDP/TCP conn
	relay             net.PacketConn // relay allocation from client.Allocate()
	addr              string         // TURN server the session runs on
	rtt               time.Duration  // Dial → Allocate latency
	perm              *permWatch     // control-plane blackhole detector for this session
	releaseCredential func()         // returned only after the allocation closes
}

// runWithCreds establishes one TURN session with pre-fetched credentials on
// addrs[0] (see serversForAttempt). There is no latency race: only if that
// server fails to Allocate are the remaining candidates dialed, all at once, and
// the first of those to complete Allocate takes the session while the others
// are cancelled/closed. A session that allocates and then fails — handshake
// included — ends the attempt: the worker's next one starts from the next relay.
// Retry and credential rotation are managed by the calling WorkerGroup.
func (s *stream) runWithCreds(ctx context.Context, user, pass string, addrs []string, cfg WorkerGroupConfig) error {
	s.ready.Store(false)
	defer s.ready.Store(false)
	s.serverAddr = "" // set by runSession; an attempt that never allocates ran on no relay

	// raceCtx is cancelled the moment a winner is chosen (or ctx dies) so the
	// losing failover candidates stop dialing / abort their semaphore wait
	// promptly.
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
			release, err := acquireCredentialAllocation(raceCtx, user, pass)
			if err != nil {
				errCh <- err
				return
			}
			client, raw, relay, rtt, perm, err := dialAndAllocate(raceCtx, s, user, pass, addr, cfg)
			if err != nil {
				release()
				errCh <- err
				return
			}
			claimed := false
			once.Do(func() {
				claimed = true
				cancelRace()
				winCh <- winner{client: client, raw: raw, relay: relay, addr: addr, rtt: rtt, perm: perm, releaseCredential: release}
			})
			if !claimed {
				// Another failover candidate got there first: log this
				// server's RTT, then release the surplus allocation
				// (relayConn.Close → Refresh(lifetime=0) deallocates server-side).
				turnLog("[STREAM %d] Failover candidate %s lost rtt=%v (group %d)", s.id, addr, rtt, cfg.GroupID)
				relay.Close()
				client.Close()
				raw.Close()
				release()
			}
		}(addr)
	}

	launch(addrs[0])
	launchedCount := 1
	fannedOut := len(addrs) == 1

	fanOut := func() {
		if fannedOut {
			return
		}
		for _, a := range addrs[1:] {
			launch(a)
			launchedCount++
		}
		fannedOut = true
	}

	var errs []error
	for {
		select {
		case w := <-winCh:
			return s.runSession(ctx, w, cfg)
		case err := <-errCh:
			errs = append(errs, err)
			if !fannedOut {
				// The assigned server failed: try the failover candidates. Say
				// why before moving on — a failover that succeeds swallows this
				// error otherwise (only "all servers failed" ever surfaces it),
				// and a primary server refusing Allocate on every reconnect was
				// invisible in the log except as a second Dial line one RTT later.
				turnLog("[STREAM %d] %s failed (%v) — fanning out to %v (group %d)",
					s.id, addrs[0], err, addrs[1:], cfg.GroupID)
				fanOut()
			} else if len(errs) == launchedCount {
				return &allocateFailedError{errs}
			}
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
// measuring the Dial→Allocate latency — the network part only, not the time
// spent queued on allocSemaphore, which said nothing about the server and once
// booked a 6s "rtt" against a relay that answered in 230ms. On any error it
// closes whatever it opened and returns. On success the caller owns
// client/raw/relay. Uses ctx for the dial, the allocSemaphore wait and the
// Allocate itself so a cancelled race aborts promptly.
//
// Each attempt gets its own permWatch, wired into the pion logger factory
// before NewClient so it sees the allocation's whole lifecycle. Losing failover
// candidates simply drop theirs — a permWatch owns no goroutine, so an unwatched
// one costs nothing.
func dialAndAllocate(ctx context.Context, s *stream, user, pass, addr string, cfg WorkerGroupConfig) (*turn.Client, net.Conn, net.PacketConn, time.Duration, *permWatch, error) {
	usedLocal := make(map[string]bool)
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, 0, nil, err
		}
		if serverAllocationMismatchPaused(addr, time.Now()) {
			return nil, nil, nil, 0, nil, fmt.Errorf("TURN Allocate 437 retry pause on %s", addr)
		}
		client, raw, relay, rtt, perm, err := dialAndAllocateOnce(ctx, s, user, pass, addr, cfg, usedLocal)
		code, _ := turnErrorCode(err)
		if ctx.Err() != nil || code != stun.CodeAllocMismatch {
			return client, raw, relay, rtt, perm, err
		}
		if attempt == 3 {
			noteServerAllocationMismatch(addr, time.Now())
			turnLog("[STREAM %d] TURN Allocate 437 on %s after 3 local addresses — pausing new allocations for 2m", s.id, addr)
			return nil, nil, nil, 0, nil, err
		}
		turnLog("[STREAM %d] TURN Allocate 437 on %s (attempt %d/3) — retrying with a new local port, keeping credentials", s.id, addr, attempt)
	}
}

func dialAndAllocateOnce(ctx context.Context, s *stream, user, pass, addr string, cfg WorkerGroupConfig, usedLocal map[string]bool) (*turn.Client, net.Conn, net.PacketConn, time.Duration, *permWatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, 0, nil, err
	}
	if err := checkCredentialRelayQuota(user, pass, addr, time.Now()); err != nil {
		return nil, nil, nil, 0, nil, err
	}
	turnLog("[STREAM %d] Dial TURN %s (group %d)", s.id, addr, cfg.GroupID)
	dialStart := time.Now()
	perm := newPermWatch(s.id)

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
		Control: protectControl,
	}

	var turnConn net.PacketConn
	var raw net.Conn
	network := "tcp"
	if cfg.UseUDP {
		network = "udp"
	}
	// The OS may recycle a recently closed UDP port. Do not resend Allocate on
	// a local address already rejected in this retry sequence (RFC 8656 7.4).
	for dial := 0; dial < 4; dial++ {
		c, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, nil, nil, 0, nil, fmt.Errorf("TURN %s dial: %w", network, err)
		}
		local := c.LocalAddr().String()
		if usedLocal[local] {
			c.Close()
			continue
		}
		usedLocal[local] = true
		raw = c
		break
	}
	if raw == nil {
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN %s dial: could not select a fresh local address", network)
	}
	if cfg.UseUDP {
		turnConn = &connectedUDPConn{raw.(*net.UDPConn)}
	} else {
		turnConn = turn.NewSTUNConn(raw)
	}
	responses := &allocateResponseConn{PacketConn: turnConn, remote: raw.RemoteAddr().String()}

	// This socket is only used for TURN, never STUN Binding discovery. Setting
	// STUNServerAddr makes Pion stop its receive loop on unrelated UDP packets
	// from the relay, losing Allocate replies and leaving server-side allocations
	// occupied until expiry. With only TURNServerAddr those packets are ignored.
	client, err := newTURNClient(&turn.ClientConfig{
		TURNServerAddr: addr,
		Username:       user,
		Password:       pass,
		Conn:           responses,
		RTO:            turnClientRTO,
		// pion refreshes the peer permission every 120s by default. That is
		// twice as often as it needs to be: the permission's lifetime is a
		// fixed 300s (RFC 8656 section 9), so 240s renews it with a full 60s of
		// margin while halving the radio wake-ups this costs — on mobile each
		// refresh drags the radio into RRC-connected for the tail timer, and
		// these transactions are per stream and never coalesced with the 25s
		// keepalive grid.
		//
		// Not disabled outright (free-turn-proxy sets 24h) because after the
		// first WriteTo the data path never re-sends CreatePermission —
		// createPermission short-circuits on permStatePermitted
		// (internal/client/udp_conn.go:169) — leaving ChannelBind refresh as
		// the only thing that reinstalls the permission. pion fires that at
		// 300-330s (bindingRefreshInterval 5m, checked every 30s, condition is
		// a strict >, and refreshedAt is stamped after the transaction), i.e.
		// *after* the 300s permission has already lapsed. That would open a
		// ~30s window every 5 minutes in which the relay may drop inbound —
		// too short for the 90s dead-stream detector to catch, so it would
		// surface as unexplained downstream loss rather than a failed stream.
		// bindingRefreshInterval is unexported in ClientConfig, so the window
		// cannot be closed from here.
		//
		// permWatch still sees this class of failure, just at 2x240s instead of
		// 2x120s (~8 min). The faster detectors are unaffected: ChannelBind
		// latches in ~60s and a refused allocation refresh at once.
		PermissionRefreshInterval: 240 * time.Second,
		LoggerFactory:             pionLogFactory{streamID: s.id, watch: perm},
	})
	if err != nil {
		raw.Close()
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN client: %w", err)
	}

	if err := client.Listen(); err != nil {
		closeFailedAllocation(client, raw)
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN listen: %w", err)
	}

	dialed := time.Since(dialStart)

	select {
	case allocSemaphore <- struct{}{}:
	case <-ctx.Done():
		closeFailedAllocation(client, raw)
		return nil, nil, nil, 0, nil, ctx.Err()
	}
	if err := checkCredentialRelayQuota(user, pass, addr, time.Now()); err != nil {
		<-allocSemaphore
		closeFailedAllocation(client, raw)
		return nil, nil, nil, 0, nil, err
	}
	finishUse, err := beginCredentialUse(ctx, user, pass, time.Now())
	if err != nil {
		<-allocSemaphore
		closeFailedAllocation(client, raw)
		return nil, nil, nil, 0, nil, err
	}
	allocStart := time.Now()
	relay, err := allocateWithDeadline(ctx, allocateHandshakeTimeout, client.Allocate, func() {
		closeFailedAllocation(client, raw)
	})
	err = responses.allocationError(err)
	<-allocSemaphore
	if err != nil {
		closeFailedAllocation(client, raw)
		// A definite TURN error created no allocation; transport failure or
		// cancellation may have lost an already-successful response.
		_, definiteRefusal := turnErrorCode(err)
		finishUse(!definiteRefusal)
		// Only the relay's own 486 is remembered, and only against this identity.
		// A losing failover candidate — or any dial during a teardown — fails
		// because we cancelled its context, which says nothing at all.
		if ctx.Err() == nil && isQuotaError(err) {
			noteCredentialRelayQuota(user, pass, addr, time.Now())
		}
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN allocate: %w", err)
	}

	noteCredentialAllocationAccepted(user, pass)
	return client, raw, &credentialTrackedRelay{PacketConn: relay, finish: finishUse}, dialed + time.Since(allocStart), perm, nil
}

// turnClientRTO is pion's initial retransmit timer for every TURN transaction.
// pion's default is 200 ms, which is below the RTT this proxy actually sees:
// in the 2026-09-16 Pixel 6a logs every successful Allocate was answered in
// 231-261 ms and none on a retransmit, so at 200 ms the first copy of each
// request was always back on the wire before its reply could arrive — two
// copies of the 401 challenge and two of the authenticated Allocate per
// stream, on a relay whose lost replies leave allocations occupying the
// credential's quota until they expire. A sequential probe against the same
// relays with RTO 500 ms saw no loss at all. RFC 8489 section 6.2.1 recommends
// 500 ms as the default; use it. pion doubles the interval up to its 1600 ms
// cap, so one transaction retransmits for 500+1000+1600*5 = 9.5 s.
const turnClientRTO = 500 * time.Millisecond

// allocateHandshakeTimeout is a watchdog for blocked transport operations.
// Pion already bounds each of Allocate's two transactions (401 challenge, then
// authenticated request) to about 9.5s of retransmissions at turnClientRTO.
// Let both finish, including scheduler headroom. A 2s total budget cut off
// answering servers on slow or lossy links, sometimes after they had created
// an allocation whose response we could no longer receive or use to release it.
// Silent servers still fail on Pion's own timer; cancellation need not wait
// for either timer. Keep semaphore queue time out of this budget and the RTT.
const allocateHandshakeTimeout = 25 * time.Second

var errAllocateTimeout = errors.New("Allocate timed out")

// closeFailedAllocation aborts a pending Allocate. Pion holds mutexTrMap while
// retransmitting and Client.Close needs that same mutex: close the transport
// first so a blocked WriteTo cannot keep Close (and allocSemaphore) stuck.
// Established sessions close their relay first to send Refresh(lifetime=0).
func closeFailedAllocation(client *turn.Client, transport io.Closer) {
	transport.Close()
	client.Close()
}

// allocateWithDeadline runs allocate, giving up after timeout or when ctx is
// cancelled. abort must make a pending allocate return promptly — for pion
// that is closeFailedAllocation. A relay handed back while abort races with
// Allocate is closed to stop its local timers. Once the transport is closed,
// server-side release is no longer guaranteed; its lease may need to expire.
func allocateWithDeadline(ctx context.Context, timeout time.Duration, allocate func() (net.PacketConn, error), abort func()) (net.PacketConn, error) {
	type result struct {
		relay net.PacketConn
		err   error
	}
	done := make(chan result, 1)
	go func() {
		relay, err := allocate()
		done <- result{relay, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.relay, r.err
	case <-timer.C:
	case <-ctx.Done():
	}

	abort()
	if r := <-done; r.relay != nil {
		r.relay.Close()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w after %v", errAllocateTimeout, timeout)
}

// runSession runs the relay session on the connected server and owns its
// lifecycle: it closes the relay, client and underlying conn on exit.
func (s *stream) runSession(ctx context.Context, w winner, cfg WorkerGroupConfig) error {
	defer w.releaseCredential()
	defer w.raw.Close()
	defer w.client.Close()
	defer w.relay.Close()
	defer w.perm.stop()

	turnLog("[STREAM %d] TURN %s rtt=%v (group %d)", s.id, w.addr, w.rtt, cfg.GroupID)
	turnLog("[STREAM %d] Relay: %s", s.id, w.relay.LocalAddr())

	// Blackhole watchdog. When permWatch declares the allocation dead, close the
	// relay: that is the one handle all three transports block on, so whichever
	// loop owns this stream unwinds immediately instead of writing into a dead
	// allocation until the 90s no-RX detector eventually notices — or never
	// notices, because a shaped-but-alive path keeps the liveness clock fresh.
	// Closing here also sends Refresh(lifetime=0), releasing the server-side
	// allocation instead of leaving it to eat the credential's quota.
	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()
	go func() {
		select {
		case <-w.perm.deadCh():
			turnLog("[STREAM %d] Recycling allocation after blackhole", s.id)
			w.relay.Close()
		case <-sessCtx.Done():
		}
	}()

	// Which relay this attempt runs on: the transports name it in their log
	// lines, and runWorker keeps the stream on it once it has carried a session.
	s.serverAddr = w.addr

	var err error
	switch cfg.PeerType {
	case "wireguard":
		err = s.runNoDTLS(ctx, w.relay, cfg.PeerAddr)
	case "srtp":
		err = s.runSRTP(ctx, w.relay, cfg.PeerAddr)
	default:
		err = s.runDTLS(ctx, w.relay, cfg.PeerAddr, true)
	}

	// A blackhole teardown surfaces as "use of closed network connection", which
	// carries no diagnosis and — more importantly — no auth/quota wording for
	// classifyCredError to act on. Restate it with pion's own message so a
	// blackhole that was really a stale credential still rotates the credential.
	// A nil err means the loops exited cleanly, which WorkerGroup would read as
	// "server closed the stream": override it too, this was a failure.
	//
	// The cause is folded in with %s, not %w. classifyCredError is code-driven and
	// bails out early on any error whose chain contains a *net.OpError (see
	// isTransportError), and the relay we just closed ourselves puts exactly that
	// in the chain. Wrapping would therefore route every blackhole down the
	// "transport, not credential" branch and never rotate — which is the whole
	// reason this restatement exists. Flattening to text keeps pion's wording
	// ("error 401: Unauthorized") reachable by the substring fallback; nothing
	// downstream matches on this error's chain.
	if w.perm.fired() {
		if err == nil {
			return fmt.Errorf("TURN blackhole: %s", w.perm.why())
		}
		return fmt.Errorf("TURN blackhole: %s (%s)", w.perm.why(), err)
	}
	return err
}

// reapRace drains any late-arriving winner (after the caller has given up on
// ctx cancellation) and closes its resources so they don't leak. winCh holds at
// most one winner (guarded by sync.Once), so a single non-blocking drain after
// all dialers have exited is sufficient.
func reapRace(wg *sync.WaitGroup, winCh chan winner) {
	wg.Wait()
	select {
	case w := <-winCh:
		w.relay.Close()
		w.client.Close()
		w.raw.Close()
		w.releaseCredential()
	default:
	}
}
