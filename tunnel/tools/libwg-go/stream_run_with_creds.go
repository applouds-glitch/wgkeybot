/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/turn/v5"
)

// errDataPlaneHandshake marks the one failure the static assignment used to be
// blind to: Allocate succeeded, so the control plane and the credential are
// fine, and the transport handshake through the relay still never completed.
// Every transport wraps its handshake failure with this so runSession can tell
// it apart from a session that ran and then broke.
var errDataPlaneHandshake = errors.New("data-plane handshake failed")

// sessionVerdict is what a finished session says about the server it ran on.
type sessionVerdict int

const (
	// verdictNone: the session says nothing — we tore it down ourselves, or it
	// ended cleanly without lasting long enough to prove anything.
	verdictNone sessionVerdict = iota
	verdictSuccess
	verdictFailure
	// verdictHandshakeFailure: allocated, then never completed the transport
	// handshake. Acted on immediately rather than through the streak.
	verdictHandshakeFailure
)

func (v sessionVerdict) String() string {
	switch v {
	case verdictSuccess:
		return "success"
	case verdictFailure:
		return "failure"
	case verdictHandshakeFailure:
		return "handshake-failure"
	default:
		return "none"
	}
}

// sessionOutcome grades a finished session for the health accounting in
// turn_server_health.go.
//
// A blackholed allocation is the clearest verdict there is: the control plane
// answered, so the credential and the path are fine, and the host still ate the
// traffic. Otherwise a session that ran for a while proves the server works, and
// a short one that ended in an error counts against it. Teardowns are excluded —
// cancelled means cancelled by us, not by the server.
func sessionOutcome(cancelled, blackholed bool, dur time.Duration, err error) sessionVerdict {
	switch {
	case cancelled:
		return verdictNone
	case blackholed:
		return verdictFailure
	case dur >= healthySessionDuration:
		return verdictSuccess
	case errors.Is(err, errDataPlaneHandshake):
		return verdictHandshakeFailure
	case err != nil:
		return verdictFailure
	default:
		return verdictNone
	}
}

// winner holds a successfully allocated TURN session from the race in
// runWithCreds. The fields are the live resources handed off to the session:
// runSession owns them and is responsible for closing them.
type winner struct {
	client *turn.Client
	raw    net.Conn       // underlying dialed UDP/TCP conn
	relay  net.PacketConn // relay allocation from client.Allocate()
	addr   string         // TURN server the session runs on
	rtt    time.Duration  // Dial → Allocate latency
	perm   *permWatch     // control-plane blackhole detector for this session
}

// runWithCreds establishes one TURN session with pre-fetched credentials on the
// session's server, addrs[0] (see assignServers). There is no latency
// race: only if that server fails to Allocate are the remaining candidates
// dialed, all at once, and the first of those to complete Allocate takes the
// session while the others are cancelled/closed. The assignment is per attempt,
// so the next reconnect goes back to the stream's own server. Retry and
// credential rotation are managed by the calling WorkerGroup.
func (s *stream) runWithCreds(ctx context.Context, user, pass string, addrs []string, cfg WorkerGroupConfig) error {
	s.ready.Store(false)
	defer s.ready.Store(false)

	// raceCtx is cancelled the moment a winner is chosen (or ctx dies) so the
	// losing failover candidates stop dialing / abort their semaphore wait
	// promptly.
	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	var once sync.Once
	winCh := make(chan winner, 1)
	errCh := make(chan error, len(addrs))
	var wg sync.WaitGroup

	// allocating carries the first relay's Allocate slot to the loop below at the
	// moment its request goes out: that is when its head start begins.
	allocating := make(chan *allocSlot, 1)
	// Over TCP the relay can be silent a step earlier, on the connect, and gets a
	// head start for that too.
	connecting := make(chan struct{}, 1)

	launch := func(addr string) {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			opts := dialOpts{session: ctx}
			if addr == addrs[0] {
				opts.allocating = func(slot *allocSlot) { allocating <- slot }
				opts.connecting = func() { connecting <- struct{}{} }
			}
			client, raw, relay, rtt, perm, err := dialAndAllocate(raceCtx, s, user, pass, addr, cfg, opts)
			if err != nil {
				errCh <- err
				return
			}
			claimed := false
			once.Do(func() {
				claimed = true
				cancelRace()
				winCh <- winner{client: client, raw: raw, relay: relay, addr: addr, rtt: rtt, perm: perm}
			})
			if !claimed {
				// Another failover candidate got there first: log this
				// server's RTT, then release the surplus allocation
				// (relayConn.Close → Refresh(lifetime=0) deallocates server-side).
				turnLog("[STREAM %d] Failover candidate %s lost rtt=%v (group %d)", s.id, addr, rtt, cfg.GroupID)
				relay.Close()
				client.Close()
				raw.Close()
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

	var headSlot *allocSlot
	var headStart <-chan time.Time
	var headStartTimer *time.Timer
	defer func() {
		if headStartTimer != nil {
			headStartTimer.Stop()
		}
	}()
	// One clock, restarted per step: the TCP connect (if there is one), then the
	// Allocate. A relay that took its time over the connect has still answered,
	// and its Allocate gets a full head start of its own.
	startHeadStart := func() {
		if headStartTimer != nil {
			headStartTimer.Stop()
		}
		headStartTimer = time.NewTimer(relayHeadStart)
		headStart = headStartTimer.C
	}

	var lastErr error
	errCount := 0
	for {
		select {
		case w := <-winCh:
			return s.runSession(ctx, w, cfg)
		case <-connecting:
			if !fannedOut {
				startHeadStart()
			}
		case headSlot = <-allocating:
			if !fannedOut {
				startHeadStart()
			}
		case <-headStart:
			headStart = nil
			if fannedOut {
				continue
			}
			// Silent, not refused: race the rest now, and let the next worker in
			// this relay's queue start its own clock. The Allocate itself runs
			// on — see relayHeadStart. A TCP connect that is still hanging holds
			// no slot yet; it runs on as well, and is closed if it loses.
			if headSlot != nil {
				turnLog("[STREAM %d] %s has not answered Allocate for %v — racing %v (group %d)",
					s.id, addrs[0], relayHeadStart, addrs[1:], cfg.GroupID)
				headSlot.release()
			} else {
				turnLog("[STREAM %d] %s has not accepted the TCP connection for %v — racing %v (group %d)",
					s.id, addrs[0], relayHeadStart, addrs[1:], cfg.GroupID)
			}
			fanOut()
		case err := <-errCh:
			lastErr = err
			errCount++
			if !fannedOut {
				// The assigned server failed: try the failover candidates. Say
				// why before moving on — a failover that succeeds swallows this
				// error otherwise (only "all servers failed" ever surfaces it),
				// and an elected server refusing Allocate on every reconnect was
				// invisible in the log except as a second Dial line one RTT later.
				turnLog("[STREAM %d] %s failed (%v) — fanning out to %v (group %d)",
					s.id, addrs[0], err, addrs[1:], cfg.GroupID)
				fanOut()
			} else if errCount == launchedCount {
				return fmt.Errorf("TURN allocate: all %d servers failed: %w", len(addrs), lastErr)
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

// relayHeadStart is how long the attempt's first relay has to answer Allocate
// before the rest are dialed alongside it; the first to allocate takes the
// session and the others are released.
//
// Until now the others were dialed only after the first had failed, and a relay
// that has gone silent does not fail: pion retransmits for ~7.8s before giving
// up. With three Allocates in flight at a time, nine workers took three such
// rounds — about 25s to move a session to a relay that was answering in 200ms
// (field logs of 2026-09-18: 56 and 23 Allocate timeouts). v1.6.0 raced after
// 400ms; that is below a healthy Allocate on a slow network (two round trips:
// 180-200ms on LTE, 290-410ms on the test Wi-Fi), so it dialed the second relay
// on every ordinary connect and scattered streams across relays. 1.2s leaves a
// healthy relay room for a retransmission or two and still costs a dark one a
// second instead of eight.
//
// The clock starts when this worker's Allocate is actually sent, not while it
// queues for a slot: after a network return every worker dials at once, and a
// healthy relay must not lose the race to its own queue. When the head start
// runs out the hanging Allocate gives up its slot — the next worker in the
// queue can start its own clock — but is not aborted: cutting an Allocate short
// is how ghost allocations were made (a reply still on its way allocates on the
// relay with nobody left to release it). If the relay does answer late, the
// loser path below releases that allocation properly.
const relayHeadStart = 1200 * time.Millisecond

// dialOpts is what only runWithCreds needs from a dial; the zero value is a
// plain dial.
type dialOpts struct {
	// session is the attempt's own context. A failed Allocate counts against
	// the server while it is alive — even after the race was won elsewhere and
	// ctx cancelled, because Allocate is not cancellable: what it reports is
	// the relay's answer, or its silence. nil means ctx.
	session context.Context
	// allocating is called once the dial holds its Allocate slot, just before
	// the request goes out.
	allocating func(*allocSlot)
	// connecting is called just before a TCP connect to the relay starts. Over
	// UDP there is no such moment: the "dial" sends nothing.
	connecting func()
}

// dialAndAllocate dials one TURN server and performs the Allocate handshake,
// measuring the Dial→Allocate latency — the network part only, not the time
// spent queued for an Allocate slot, which said nothing about the server and once
// booked a 6s "rtt" against a relay that answered in 230ms (the election ranks
// servers by this number). On any error it closes whatever it opened and
// returns. On success the caller owns client/raw/relay. Uses ctx for
// the dial and the slot wait so a cancelled race aborts promptly.
//
// Each attempt gets its own permWatch, wired into the pion logger factory
// before NewClient so it sees the allocation's whole lifecycle. Losing failover
// candidates simply drop theirs — a permWatch owns no goroutine, so an unwatched
// one costs nothing.
func dialAndAllocate(ctx context.Context, s *stream, user, pass, addr string, cfg WorkerGroupConfig, opts dialOpts) (*turn.Client, net.Conn, net.PacketConn, time.Duration, *permWatch, error) {
	// Decided per dial, not per proxy start — see relayTransportChoice.
	overTCP := relayOverTCP(cfg)
	if overTCP {
		turnLog("[STREAM %d] Dial TURN %s over TCP (group %d)", s.id, addr, cfg.GroupID)
	} else {
		turnLog("[STREAM %d] Dial TURN %s (group %d)", s.id, addr, cfg.GroupID)
	}
	dialStart := time.Now()
	perm := newPermWatch(s.id)

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
		Control: protectControl,
	}

	var turnConn net.PacketConn
	var raw net.Conn
	if !overTCP {
		c, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, nil, nil, 0, nil, fmt.Errorf("TURN UDP dial: %w", err)
		}
		raw = c
		turnConn = &connectedUDPConn{c.(*net.UDPConn)}
	} else {
		if opts.connecting != nil {
			opts.connecting()
		}
		c, err := connectRelayTCP(ctx, dialer, addr)
		if err != nil {
			// Over TCP the connect is the relay's first chance to be silent or to
			// refuse, so it counts against the server on the same terms as a
			// failed Allocate below. A connect that our own race cancelled does
			// not: unlike an Allocate it really is cancelled, and says nothing.
			session := opts.session
			if session == nil {
				session = ctx
			}
			if session.Err() == nil && ctx.Err() == nil {
				noteServerFailure(addr)
			}
			return nil, nil, nil, 0, nil, fmt.Errorf("TURN TCP dial: %w", err)
		}
		raw = c
		turnConn = turn.NewSTUNConn(c)
	}
	responses := &allocateResponseConn{PacketConn: turnConn, remote: raw.RemoteAddr().String()}

	// This socket is only used for TURN, never STUN Binding discovery. With
	// STUNServerAddr set, pion ends its receive loop on the first datagram from
	// that address that is neither STUN nor ChannelData (client.go HandleInbound:
	// errNonSTUNMessage → "Exiting loop"), and on a connected socket every
	// datagram comes from that address. From then on nothing is read: Allocate
	// replies are lost, and later refreshes and channel binds fail as if the relay
	// had gone dark. With only TURNServerAddr such packets are ignored.
	client, err := newTURNClient(&turn.ClientConfig{
		TURNServerAddr: addr,
		Username:       user,
		Password:       pass,
		Conn:           responses,
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
		// latches in ~60s and allocation refresh on a single failure.
		PermissionRefreshInterval: 240 * time.Second,
		LoggerFactory:             pionLogFactory{streamID: s.id, watch: perm},
	})
	if err != nil {
		raw.Close()
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN client: %w", err)
	}

	if err := client.Listen(); err != nil {
		client.Close()
		raw.Close()
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN listen: %w", err)
	}

	dialed := time.Since(dialStart)

	slot := acquireAllocSlot(ctx, addr)
	if slot == nil {
		client.Close()
		raw.Close()
		return nil, nil, nil, 0, nil, ctx.Err()
	}
	if opts.allocating != nil {
		opts.allocating(slot)
	}
	allocStart := time.Now()
	relay, err := client.Allocate()
	err = responses.allocationError(err)
	slot.release()
	if err != nil {
		client.Close()
		raw.Close()
		// Only a genuine refusal or silence counts against the server, and only
		// while the attempt itself is alive: a dial during a teardown says
		// nothing about the host. Losing the race does not excuse it — nothing
		// here cancels an Allocate, so a relay that was still silent when
		// another one won has earned the strike (see dialOpts.session).
		//
		// Nor does 486. The quota is per credential on this relay, and what fills
		// it is our own allocations — usually ghosts of sockets that died with
		// the path. The relay answered; the fix is the credential rotation that
		// 486 already triggers (refreshGroupCreds, quotaCooldown), not a
		// five-minute stand-down. Field log 18.09: 91.231.135.87 proved an SRTP
		// session at 09:58:31, a run of 486s on the old credential stood it down
		// at 09:58:40, and the fresh credential eight seconds later had only the
		// relay that never carried a byte left to go to.
		session := opts.session
		if session == nil {
			session = ctx
		}
		if session.Err() == nil && !isQuotaError(err) {
			noteServerFailure(addr)
		}
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN allocate: %w", err)
	}
	// Counted live until closed, so that losing it without a release marks this
	// relay as still holding our quota (orphaned_allocations.go).
	relay = trackAllocation(relay, user, addr)
	if overTCP {
		// Outermost, so the deadline is on the socket before the release is
		// written; trackedRelay beneath it books a release that timed out.
		relay = boundRelayClose(relay, raw)
	}

	return client, raw, relay, dialed + time.Since(allocStart), perm, nil
}

// runSession runs the relay session on the connected server and owns its
// lifecycle: it closes the relay, client and underlying conn on exit.
func (s *stream) runSession(ctx context.Context, w winner, cfg WorkerGroupConfig) error {
	defer w.raw.Close()
	defer w.client.Close()
	defer w.relay.Close()

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

	// The transports report their own handshake success against this address
	// (noteServerHandshakeOK), which is what lets a sibling's success vouch for
	// the uplink when another server fails its handshake in the same window.
	s.serverAddr = w.addr

	// Stamped before the transport runs, so a server that goes on to prove its
	// data plane already has a latency the election can rank it by.
	noteServerRTT(w.addr, w.rtt)

	// Only for the log line below: which side of the relay a failed data-plane
	// handshake died on (see relayWriteProbe).
	relay := newRelayWriteProbe(w.relay)

	started := time.Now()
	var err error
	switch cfg.PeerType {
	case "wireguard":
		err = s.runNoDTLS(ctx, relay, cfg.PeerAddr)
	case "srtp":
		err = s.runSRTP(ctx, relay, cfg.PeerAddr)
	default:
		err = s.runDTLS(ctx, relay, cfg.PeerAddr, true)
	}

	// Health accounting for the static assignment (see turn_server_health.go).
	switch sessionOutcome(ctx.Err() != nil, w.perm.fired(), time.Since(started), err) {
	case verdictSuccess:
		noteServerSuccess(w.addr)
	case verdictHandshakeFailure:
		turnLog("[STREAM %d] %s handshake: %s", s.id, w.addr, relay.describe(time.Now()))
		noteServerHandshakeFailure(w.addr, started)
	case verdictFailure:
		noteServerFailure(w.addr)
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
	default:
	}
}
