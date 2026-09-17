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
// VK refusal (ERROR-CODE/FINGERPRINT, no NONCE or REALM). Accepted sockets
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

// VK answers a refused initial Allocate with ERROR-CODE and FINGERPRINT only.
// pion reads NONCE/REALM before the code and reports a missing attribute; the
// code is restored from the reply itself (allocateResponseConn), so the worker
// classifies what the relay actually said. One socket per attempt: a refusal is
// retried by the worker's own loop, not inside the dial.
func TestInitialAllocateErrorKeepsActualCode(t *testing.T) {
	for _, code := range []stun.ErrorCode{stun.CodeAllocMismatch, stun.CodeAllocQuotaReached, stun.CodeForbidden} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			pc, _ := startInitialRefusalServer(t, 100, code)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _, _, _, _, err := dialAndAllocate(ctx, &stream{}, t.Name(), "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
			if got, ok := turnErrorCode(err); !ok || got != code {
				t.Fatalf("want %d, got %v", code, err)
			}
			if pc.count() != 1 {
				t.Fatalf("Allocate retried on %d sockets", pc.count())
			}
			if len(allocSemaphore) != 0 {
				t.Fatal("refused Allocate kept a semaphore slot")
			}
		})
	}
}

// 437 rotates the credential, as it always has: the refusal now arrives with
// its code instead of as a missing attribute, and both classify the same way.
func TestAllocateMismatchRotatesCredentials(t *testing.T) {
	pc, _ := startInitialRefusalServer(t, 100, stun.CodeAllocMismatch)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, _, _, _, err := dialAndAllocate(ctx, &stream{}, t.Name(), "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
	if !classifyCredError(err) || isQuotaError(err) {
		t.Fatalf("437 should rotate the credential without the quota cooldown: %v", err)
	}
}
