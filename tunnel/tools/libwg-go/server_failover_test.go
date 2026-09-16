/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
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
	for _, failure := range []string{"none", "allocate", "data-plane-after-outage"} {
		t.Run(failure, func(t *testing.T) {
			resetServerHealth()
			defer resetServerHealth()
			primary, primaryRequests := startFailoverTestServer(t, failure == "data-plane-after-outage", failure == "allocate")
			fallback, fallbackRequests := startFailoverTestServer(t, false, false)
			addrs := []string{primary, fallback}
			if failure == "data-plane-after-outage" {
				// Both hosts failed on the old uplink. Retrying the full list
				// must reach the second host even if the first still blackholes.
				for _, addr := range addrs {
					noteServerDemotedAt(addr, time.Now().Add(-time.Minute))
				}
			}
			s, _ := newNoDTLSTestStream(t)
			ready := make(chan struct{}, 1)
			s.okFunc = func() { ready <- struct{}{} }
			answer := make(chan struct{})
			close(answer)
			peer := fakeRelay(t, answer)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			done := make(chan error, 1)
			go func() {
				done <- s.runWithCreds(ctx, "user", "pass", assignServers(addrs), WorkerGroupConfig{
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

// Nine existing allocations leave only one slot for a reconnect. Its two
// fallback candidates must share that slot instead of both allocating and
// temporarily taking the credential above quota.
func TestRunWithCredsCountsFallbackAttemptsAgainstQuota(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()
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
