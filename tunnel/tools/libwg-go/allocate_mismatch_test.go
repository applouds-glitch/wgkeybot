/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// Refuse the first N client addresses before auth, exactly like the observed
// VK 437 response (ERROR-CODE/FINGERPRINT, no NONCE or REALM). Accepted sockets
// go through a real TURN server, including authentication and relay cleanup.
type initialAllocateRefuser struct {
	net.PacketConn
	mu        sync.Mutex
	addresses map[string]bool
	refuse    int
	code      stun.ErrorCode
}

func (c *initialAllocateRefuser) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		m := &stun.Message{Raw: b[:n]}
		if m.Decode() == nil && m.Type == stun.NewType(stun.MethodAllocate, stun.ClassRequest) && !m.Contains(stun.AttrMessageIntegrity) {
			c.mu.Lock()
			reject, seen := c.addresses[addr.String()]
			if !seen {
				reject = len(c.addresses) < c.refuse
				c.addresses[addr.String()] = reject
			}
			c.mu.Unlock()
			if reject {
				reply := stun.MustBuild(stun.NewTransactionIDSetter(m.TransactionID), stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse), stun.ErrorCodeAttribute{Code: c.code}, stun.Fingerprint)
				if _, err := c.PacketConn.WriteTo(reply.Raw, addr); err != nil {
					return 0, nil, err
				}
				continue
			}
		}
		return n, addr, nil
	}
}

func (c *initialAllocateRefuser) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.addresses)
}

func startInitialRefusalServer(t *testing.T, n int, code stun.ErrorCode) (*initialAllocateRefuser, *turn.Server) {
	t.Helper()
	pc := &initialAllocateRefuser{PacketConn: listenFakeRelay(t), addresses: make(map[string]bool), refuse: n, code: code}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "initial-refusal-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "initial-refusal-test", "pass"), a.Username == t.Name()
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	t.Cleanup(resetServerHealth)
	return pc, server
}

func TestAllocateMismatchRetriesNewPortsWithSameCredentials(t *testing.T) {
	pc, server := startInitialRefusalServer(t, 2, stun.CodeAllocMismatch)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, raw, relay, _, _, err := dialAndAllocate(ctx, &stream{}, t.Name(), "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
	if err != nil {
		t.Fatalf("two 437s should recover on the third socket: %v", err)
	}
	defer closeFailedAllocation(client, raw)
	defer relay.Close()
	if pc.count() != 3 || server.AllocationCount() != 1 {
		t.Fatalf("addresses=%d allocations=%d, want 3 and 1", pc.count(), server.AllocationCount())
	}
	if serverPenalized(pc.LocalAddr().String(), time.Now()) {
		t.Fatal("successful retry penalized the relay")
	}
}

func TestAllocateMismatchBoundsRetriesAndPausesServer(t *testing.T) {
	pc, server := startInitialRefusalServer(t, 100, stun.CodeAllocMismatch)
	addr := pc.LocalAddr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, _, _, _, err := dialAndAllocate(ctx, &stream{}, t.Name(), "pass", addr, WorkerGroupConfig{UseUDP: true})
	if code, ok := turnErrorCode(err); !ok || code != stun.CodeAllocMismatch {
		t.Fatalf("lost 437: %v", err)
	}
	if classifyCredError(err) || isQuotaError(err) {
		t.Fatalf("437 should preserve credentials: %v", err)
	}
	if pc.count() != 3 || server.AllocationCount() != 0 {
		t.Fatalf("addresses=%d allocations=%d", pc.count(), server.AllocationCount())
	}
	_, _, _, _, _, err = dialAndAllocate(ctx, &stream{}, t.Name(), "pass", addr, WorkerGroupConfig{UseUDP: true})
	if err == nil || classifyCredError(err) || pc.count() != 3 {
		t.Fatalf("paused server retried/refetched: err=%v count=%d", err, pc.count())
	}
	if !serverPenalized(addr, time.Now()) || serverAllocationMismatchPaused(addr, time.Now().Add(2*time.Minute+time.Second)) {
		t.Fatal("wrong mismatch pause lifetime")
	}
	if got := assignServers([]string{addr, "other:3478"}); len(got) != 1 || got[0] != "other:3478" {
		t.Fatalf("paused relay not filtered: %v", got)
	}
	if len(allocSemaphore) != 0 {
		t.Fatal("437 retries leaked Allocate semaphore")
	}
}

func TestInitialAllocateErrorKeepsActualCode(t *testing.T) {
	for _, code := range []stun.ErrorCode{stun.CodeAllocQuotaReached, stun.CodeForbidden} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			pc, _ := startInitialRefusalServer(t, 100, code)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _, _, _, _, err := dialAndAllocate(ctx, &stream{}, t.Name(), "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
			if got, ok := turnErrorCode(err); !ok || got != code {
				t.Fatalf("want %d, got %v", code, err)
			}
			if pc.count() != 1 {
				t.Fatalf("non-437 retried %d sockets", pc.count())
			}
		})
	}
}

func TestRunWithCredsMismatchFallsBackAfterBoundedRetries(t *testing.T) {
	primary, _ := startInitialRefusalServer(t, 100, stun.CodeAllocMismatch)
	fallback, _ := startInitialRefusalServer(t, 0, stun.CodeAllocMismatch)
	s, _ := newNoDTLSTestStream(t)
	ready := make(chan struct{}, 1)
	s.okFunc = func() { ready <- struct{}{} }
	answer := make(chan struct{})
	close(answer)
	peer := fakeRelay(t, answer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- s.runWithCreds(ctx, t.Name(), "pass", []string{primary.LocalAddr().String(), fallback.LocalAddr().String()}, WorkerGroupConfig{UseUDP: true, PeerType: "wireguard", PeerAddr: peer})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
			waitCredentialSlots(t, t.Name(), "pass", 0, 0)
		case <-time.After(3 * time.Second):
			t.Error("mismatch/fallback leaked a credential slot or socket")
		}
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("fallback failed to carry a relay handshake after 437 retries")
	}
	if primary.count() != 3 || fallback.count() != 1 {
		t.Fatalf("primary/fallback addresses = %d/%d, want 3/1", primary.count(), fallback.count())
	}
}
