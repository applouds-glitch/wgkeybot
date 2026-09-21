/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// restoreTransport puts the transport back after the test. Registered before the
// workers are started, so it runs after they have stopped.
func restoreTransport(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { setRelayTransport(relayTransportAsConfigured) })
}

// tcpRelayBeside starts a TCP relay on the port a UDP relay already has: the
// same address reached either way, as VK's are.
func tcpRelayBeside(t *testing.T, udpAddr string) *tcpTestRelay {
	t.Helper()
	ln, err := net.Listen("tcp4", udpAddr)
	if errors.Is(err, syscall.EADDRINUSE) {
		t.Skipf("the UDP relay's port is taken over TCP: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return startTCPTestRelay(t, &countingListener{Listener: ln})
}

// longWaits reports the waits a worker goes into that are at least atLeast long,
// through the seam runWorker calls as it enters one.
func longWaits(t *testing.T, atLeast time.Duration) <-chan bool {
	t.Helper()
	entered := make(chan bool, 16)
	prev := workerWaits
	workerWaits = func(_ int, delay time.Duration, wakeable bool) {
		if delay >= atLeast {
			select {
			case entered <- wakeable:
			default:
			}
		}
	}
	t.Cleanup(func() { workerWaits = prev })
	return entered
}

func awaitLongWait(t *testing.T, entered <-chan bool, wantWakeable bool) {
	t.Helper()
	select {
	case wakeable := <-entered:
		if wakeable != wantWakeable {
			t.Fatalf("the worker's wait is wakeable=%v, want %v", wakeable, wantWakeable)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the worker never went into a long wait: the test staged nothing")
	}
}

// The setting has to take effect, not wait for the next reconnect: a session
// that is up moves to the transport chosen, and back. And only a change of the
// transport in effect moves anybody.
func TestChoosingATransportMovesALiveSessionOntoIt(t *testing.T) {
	restoreTransport(t)
	udp := startTestRelay(t, listenFakeRelay(t), 0)
	tcp := tcpRelayBeside(t, udp.addr)

	h := runWorkersAgainst(t, 134, 1, []string{udp.addr})
	s := h.streams[0]
	waitFor(t, "a stream over UDP", 5*time.Second, func() bool { return h.ready() == 1 && !s.overTCP.Load() })
	// Stood down for what it did over UDP — which says nothing about TCP. A
	// penalty, not a demotion: a handshake alone does not lift it.
	for i := 3; i > 0; i-- {
		noteServerFailureAt(udp.addr, time.Now().Add(-time.Duration(i)*2*serverFailCoalesce))
	}
	if !serverPenalized(udp.addr, time.Now()) {
		t.Fatal("the test did not get the relay stood down")
	}

	setRelayTransport(relayTransportTCP)
	waitFor(t, "the stream over TCP", 5*time.Second, func() bool {
		return tcp.ln.accepted.Load() >= 1 && h.ready() == 1 && s.overTCP.Load()
	})
	if serverPenalized(udp.addr, time.Now()) {
		t.Fatal("the relay's UDP record followed it onto TCP")
	}

	setRelayTransport(relayTransportUDP)
	waitFor(t, "the stream back over UDP", 5*time.Second, func() bool { return h.ready() == 1 && !s.overTCP.Load() })
	sessions := udp.seen.count()

	// The config says UDP: "as configured" is the transport already in effect.
	setRelayTransport(relayTransportAsConfigured)
	time.Sleep(500 * time.Millisecond)
	if h.ready() != 1 || udp.seen.count() != sessions || tcp.ln.accepted.Load() != 1 {
		t.Fatal("a change of setting that changed no transport recycled the session")
	}
}

// The field case: UDP carries no session on this network, the worker has backed
// off, and the user picks TCP. The delay belonged to the transport that is no
// longer in use — it must not be sat out.
func TestChoosingATransportWakesAWorkerFromItsReconnectDelay(t *testing.T) {
	restoreTransport(t)
	refuser, _ := startInitialRefusalServer(t, 1000, stun.CodeForbidden)
	addr := refuser.LocalAddr().String()
	tcp := tcpRelayBeside(t, addr)

	entered := longWaits(t, 5*time.Second)
	h := runWorkersAgainst(t, 135, 1, []string{addr})
	// Two refusals in a row: the second wait is reconnectDelay(2), 7-17s.
	awaitLongWait(t, entered, true)

	setRelayTransport(relayTransportTCP)
	waitFor(t, "a stream over TCP", 4*time.Second, func() bool { return tcp.ln.accepted.Load() >= 1 && h.ready() == 1 })
}

// What a change of transport must not cut short: the cooldown after a 486 on a
// credential that is still current. The quota is the credential's on the relay,
// however the relay is reached.
func TestChoosingATransportDoesNotCutTheQuotaCooldown(t *testing.T) {
	restoreTransport(t)
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	resetServerHealth()
	const group = 101
	dropCredSlot(t, group)
	refuser, _ := startInitialRefusalServer(t, 1000, stun.CodeAllocQuotaReached)
	addr := refuser.LocalAddr().String()
	tcp := tcpRelayBeside(t, addr)

	// Just rotated: the 486 below cannot rotate again, so the credential stays
	// current and the worker takes the long cooldown (5-13s).
	cache := getStreamCache(group * streamsPerCredValue())
	cache.refreshMu.Lock()
	cache.lastRefresh = time.Now()
	cache.refreshMu.Unlock()

	entered := longWaits(t, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := runWorkerAgainst(t, ctx, group, addr, fixedCredsAt(t.Name(), addr))
	defer func() {
		cancel()
		<-done
	}()
	awaitLongWait(t, entered, false)

	setRelayTransport(relayTransportTCP)
	time.Sleep(3 * time.Second)
	if n := tcp.ln.accepted.Load(); n != 0 {
		t.Fatalf("%d TCP dial(s) within 3s of the change: the quota cooldown was cut short", n)
	}
	waitFor(t, "the dial over TCP once the cooldown is over", 12*time.Second, func() bool { return tcp.ln.accepted.Load() >= 1 })
}

func fixedCredsAt(user, addr string) fetchFunc {
	return func(context.Context, string) (string, string, []string, int, error) {
		return user, "pass", []string{addr}, 0, nil
	}
}

// The network and the transport arrive in one report and are taken in one step:
// an attempt begun after it is where it should be on both counts and is not
// recycled again; and nothing is recycled for its transport while the network
// is away — Auto reports "as configured" with no network to ask.
func TestNetworkAndTransportAreTakenTogether(t *testing.T) {
	restoreTransport(t)
	resetNetworkSwitch(t)
	now := time.Now()
	udpCfg := WorkerGroupConfig{UseUDP: true}

	setNetworkState(switchNetA, relayTransportAsConfigured, now)
	old := beginAttempt(context.Background(), udpCfg)
	if old.overTCP {
		t.Fatal("an attempt under a UDP config and no override was tagged TCP")
	}

	setNetworkState(switchNetB, relayTransportTCP, now) // Wi-Fi to the operator that needs TCP
	if !cancelled(old.ctx) || !old.end() {
		t.Fatal("the attempt on the old network and transport was not recycled")
	}
	fresh := beginAttempt(context.Background(), udpCfg)
	if !fresh.overTCP {
		t.Fatal("an attempt begun after the report does not dial over TCP")
	}
	if cfg := udpCfg.pinTransport(fresh.overTCP); !relayOverTCP(cfg) {
		t.Fatal("the attempt's config does not carry the transport it was tagged with")
	}
	setNetworkState(switchNetB, relayTransportTCP, now) // Kotlin pushes on re-addressing too
	if cancelled(fresh.ctx) {
		t.Fatal("an attempt already on the new network and transport was recycled again")
	}

	// The network goes away: Auto has nobody to ask and says "as configured".
	setNetworkState(0, relayTransportAsConfigured, now)
	if cancelled(fresh.ctx) {
		t.Fatal("a session was recycled for its transport while the network was away")
	}
	// Pinned: whatever the setting says meanwhile, this attempt's dials are TCP.
	if !relayOverTCP(udpCfg.pinTransport(fresh.overTCP)) || relayOverTCP(udpCfg) {
		t.Fatal("the pin did not hold, or the unpinned config did not follow the setting")
	}
	// It comes back needing TCP still: the session that survived stays.
	setNetworkState(switchNetB, relayTransportTCP, now)
	if cancelled(fresh.ctx) {
		t.Fatal("a session on the right network and transport was recycled when the network returned")
	}
	// It comes back as one where UDP works: compared then, and moved.
	setNetworkState(0, relayTransportAsConfigured, now)
	setNetworkState(switchNetB, relayTransportUDP, now)
	if !cancelled(fresh.ctx) || !fresh.end() {
		t.Fatal("a TCP session was left running when the network returned wanting UDP")
	}
}
