/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// Delay both the challenge and authenticated Allocate reply without blocking
// the server's read loop or changing Pion's retransmission logic.
type delayedAllocateReplies struct {
	net.PacketConn
	delay time.Duration
}

// Live relays can send unrelated UDP datagrams before the Allocate response.
// The server has already reserved an allocation at this point: losing the
// response leaves it occupied even though the client reports a timeout.
type noisyAllocateReplies struct {
	net.PacketConn
	injected atomic.Int32
}

func (c *noisyAllocateReplies) WriteTo(b []byte, addr net.Addr) (int, error) {
	m := &stun.Message{Raw: append([]byte(nil), b...)}
	if m.Decode() == nil && m.Type == stun.NewType(stun.MethodAllocate, stun.ClassSuccessResponse) {
		noise := make([]byte, 1200)
		// Same non-STUN/non-ChannelData header shape observed on the phone.
		copy(noise, []byte{0xc3, 0, 0, 0, 1, 8})
		if _, err := c.PacketConn.WriteTo(noise, addr); err != nil {
			return 0, err
		}
		c.injected.Add(1)
	}
	return c.PacketConn.WriteTo(b, addr)
}

func TestDialAndAllocateIgnoresUnrelatedDatagrams(t *testing.T) {
	pc := listenFakeRelay(t)
	noisy := &noisyAllocateReplies{PacketConn: pc}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "noisy-allocate-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "noisy-allocate-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: noisy,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer resetServerHealth()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, raw, relay, _, _, err := dialAndAllocate(ctx, &stream{}, "noisy-user", "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true}, dialOpts{})
	if err != nil {
		t.Fatalf("Allocate lost after unrelated datagram: %v (server allocations: %d, injected: %d)", err, server.AllocationCount(), noisy.injected.Load())
	}
	defer raw.Close()
	defer client.Close()
	defer relay.Close()
	if noisy.injected.Load() == 0 {
		t.Fatal("server did not inject the unrelated datagram")
	}
	if got := server.AllocationCount(); got != 1 {
		t.Fatalf("active allocations=%d, want 1", got)
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for server.AllocationCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("Refresh(lifetime=0) did not release the allocation after noise")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *delayedAllocateReplies) WriteTo(b []byte, addr net.Addr) (int, error) {
	m := &stun.Message{Raw: append([]byte(nil), b...)}
	if m.Decode() == nil && m.Type.Method == stun.MethodAllocate && c.delay > 0 {
		payload := append([]byte(nil), b...)
		time.AfterFunc(c.delay, func() { c.PacketConn.WriteTo(payload, addr) })
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, addr)
}

func TestDialAndAllocateAcceptsSlowRepliesAndReleasesAllocation(t *testing.T) {
	for _, delay := range []time.Duration{0, 1100 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			pc := listenFakeRelay(t)
			server, err := turn.NewServer(turn.ServerConfig{
				Realm: "allocate-test",
				AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
					return a.Username, turn.GenerateAuthKey(a.Username, "allocate-test", "pass"), true
				},
				PacketConnConfigs: []turn.PacketConnConfig{{
					PacketConn: &delayedAllocateReplies{PacketConn: pc, delay: delay},
					RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
						RelayAddress: net.ParseIP("127.0.0.1"),
						Address:      "127.0.0.1",
					},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			defer resetServerHealth()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, raw, relay, rtt, _, err := dialAndAllocate(ctx, &stream{}, "user", "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true}, dialOpts{})
			if err != nil {
				t.Fatalf("answering TURN server rejected: %v (active allocations: %d)", err, server.AllocationCount())
			}
			defer raw.Close()
			defer client.Close()
			defer relay.Close()
			if rtt < 2*delay {
				t.Fatalf("rtt=%v, want both delayed round trips (%v)", rtt, 2*delay)
			}
			if got := server.AllocationCount(); got != 1 {
				t.Fatalf("active allocations=%d, want 1", got)
			}
			if err := relay.Close(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for server.AllocationCount() != 0 {
				if time.Now().After(deadline) {
					t.Fatal("Refresh(lifetime=0) did not release the allocation")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if len(allocSlotsFor(pc.LocalAddr().String())) != 0 {
				t.Fatal("successful Allocate kept a semaphore slot")
			}
		})
	}
}

// A silent server must exhaust Pion's retries, without being cut off by a
// shorter timer that also hurts slow replies.
func TestDialAndAllocateLetsPionExhaustRetransmissions(t *testing.T) {
	pc := listenFakeRelay(t) // accepts datagrams but never replies
	defer resetServerHealth()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	_, _, _, _, _, err := dialAndAllocate(ctx, &stream{}, "user", "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true}, dialOpts{})
	if err == nil || !strings.Contains(err.Error(), "all retransmissions failed") {
		t.Fatalf("want Pion's retransmission failure, got %v", err)
	}
	if len(allocSlotsFor(pc.LocalAddr().String())) != 0 {
		t.Fatal("failed Allocate kept a semaphore slot")
	}
}
