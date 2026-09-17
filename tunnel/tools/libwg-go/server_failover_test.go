/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

// The control plane still answers Allocate, but the allocation discards uplink
// packets. This reproduces a relay that cannot prove its data plane.
type silentRelayConn struct{ net.PacketConn }

func (c *silentRelayConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }

type testRelayGenerator struct {
	turn.RelayAddressGeneratorStatic
	silent bool
}

func (g *testRelayGenerator) AllocatePacketConn(conf turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	pc, addr, err := g.RelayAddressGeneratorStatic.AllocatePacketConn(conf)
	if err == nil && g.silent {
		pc = &silentRelayConn{pc}
	}
	return pc, addr, err
}

func startFailoverTestServer(t *testing.T, silent, rejectAuth bool) (string, *atomic.Int32) {
	t.Helper()
	pc := listenFakeRelay(t)
	requests := &atomic.Int32{}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "failover-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			requests.Add(1)
			return a.Username, turn.GenerateAuthKey(a.Username, "failover-test", "pass"), !rejectAuth
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &testRelayGenerator{
				RelayAddressGeneratorStatic: turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      "127.0.0.1",
				},
				silent: silent,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return pc.LocalAddr().String(), requests
}

func TestRunWithCredsUsesFallbackOnlyAfterPrimaryFails(t *testing.T) {
	for _, failure := range []string{"none", "allocate"} {
		t.Run(failure, func(t *testing.T) {
			primary, primaryRequests := startFailoverTestServer(t, false, failure == "allocate")
			fallback, fallbackRequests := startFailoverTestServer(t, false, false)
			addrs := []string{primary, fallback}
			s, _ := newNoDTLSTestStream(t)
			ready := make(chan struct{}, 1)
			s.okFunc = func() { ready <- struct{}{} }
			answer := make(chan struct{})
			close(answer)
			peer := fakeRelay(t, answer)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			done := make(chan error, 1)
			go func() {
				done <- s.runWithCreds(ctx, "user", "pass", addrs, WorkerGroupConfig{
					UseUDP: true, PeerType: "wireguard", PeerAddr: peer,
				})
			}()
			defer func() {
				cancel()
				select {
				case <-done:
					waitCredentialSlots(t, "user", "pass", 0, 0)
				case <-time.After(5 * time.Second):
					t.Error("stream did not stop after cancellation")
				}
			}()

			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal("stream never proved a working relay")
			}
			if primaryRequests.Load() == 0 {
				t.Fatal("primary was skipped")
			}
			if got := fallbackRequests.Load(); (got > 0) != (failure != "none") {
				t.Fatalf("fallback requests=%d with primary failure=%s", got, failure)
			}
		})
	}
}

// A relay that allocates and then swallows the data plane ends the attempt; the
// stream's next one starts from the next relay. No ledger is involved, so the
// same sequence under a dark uplink leaves nothing behind that could keep a
// working relay out of the list afterwards.
func TestSilentRelayCostsOneAttemptThenTheNextRelayCarriesTheStream(t *testing.T) {
	resetCredentialQuota()
	defer resetCredentialQuota()
	silent, silentRequests := startFailoverTestServer(t, true, false)
	working, workingRequests := startFailoverTestServer(t, false, false)
	addrs := []string{silent, working}
	s, _ := newNoDTLSTestStream(t)
	s.id = 0
	ready := make(chan struct{}, 1)
	s.okFunc = func() { ready <- struct{}{} }
	answer := make(chan struct{})
	close(answer)
	peer := fakeRelay(t, answer)
	cfg := WorkerGroupConfig{UseUDP: true, PeerType: "wireguard", PeerAddr: peer}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := s.runWithCreds(ctx, "user", "pass", serversForAttempt(addrs, s.id+s.addrShift, "user", "pass", time.Now()), cfg)
	if !errors.Is(err, errDataPlaneHandshake) {
		t.Fatalf("silent relay returned %v, not a data-plane handshake failure", err)
	}
	if silentRequests.Load() == 0 || workingRequests.Load() != 0 {
		t.Fatalf("first attempt dialed silent=%d working=%d", silentRequests.Load(), workingRequests.Load())
	}
	if shouldRotateCredentials(err, "user", "pass", addrs, time.Now()) {
		t.Fatal("a silent relay rotated the credential")
	}
	s.noteRelayOutcome(addrs, false)

	done := make(chan error, 1)
	go func() {
		done <- s.runWithCreds(ctx, "user", "pass", serversForAttempt(addrs, s.id+s.addrShift, "user", "pass", time.Now()), cfg)
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("the next attempt never reached the working relay")
	}
	if s.serverAddr != working {
		t.Fatalf("stream ready on %s, want %s", s.serverAddr, working)
	}
	cancel()
	select {
	case <-done:
		waitCredentialSlots(t, "user", "pass", 0, 0)
	case <-time.After(5 * time.Second):
		t.Error("stream did not stop after cancellation")
	}
}

// Nine existing allocations leave only one slot for a reconnect. Its two
// fallback candidates must share that slot instead of both allocating and
// temporarily taking the credential above quota.
func TestRunWithCredsCountsFallbackAttemptsAgainstQuota(t *testing.T) {
	user, pass := t.Name(), "pass"
	releases := make([]func(), 10)
	for i := range releases {
		var err error
		releases[i], err = acquireCredentialAllocation(context.Background(), user, pass)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(releases[i])
	}
	primary, primaryRequests := startFailoverTestServer(t, false, true)
	fallback1, requests1 := startFailoverTestServer(t, false, false)
	fallback2, requests2 := startFailoverTestServer(t, false, false)
	s, _ := newNoDTLSTestStream(t)
	ready := make(chan struct{}, 1)
	s.okFunc = func() { ready <- struct{}{} }
	answer := make(chan struct{})
	close(answer)
	peer := fakeRelay(t, answer)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- s.runWithCreds(ctx, user, pass, []string{primary, fallback1, fallback2}, WorkerGroupConfig{
			UseUDP: true, PeerType: "wireguard", PeerAddr: peer,
		})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
			for _, release := range releases {
				release()
			}
			waitCredentialSlots(t, user, pass, 0, 0)
		case <-time.After(5 * time.Second):
			t.Error("stream did not stop after cancellation")
		}
	}()

	waitCredentialSlots(t, user, pass, 10, 11)
	if primaryRequests.Load() != 0 {
		t.Fatal("TURN request sent while all ten credential slots were occupied")
	}
	releases[0]()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("fallback never became ready after a slot was released")
	}
	waitCredentialSlots(t, user, pass, 10, 10)
	if primaryRequests.Load() == 0 {
		t.Fatal("primary was skipped")
	}
	if (requests1.Load() > 0) == (requests2.Load() > 0) {
		t.Fatalf("expected one fallback to allocate, got requests %d and %d", requests1.Load(), requests2.Load())
	}
}
