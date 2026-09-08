/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
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
			client, raw, relay, rtt, _, err := dialAndAllocate(ctx, &stream{}, "user", "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
			if err != nil {
				t.Fatalf("answering TURN server rejected: %v (active allocations: %d)", err, server.AllocationCount())
			}
			defer closeFailedAllocation(client, raw)
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
			if len(allocSemaphore) != 0 {
				t.Fatal("successful Allocate kept a semaphore slot")
			}
		})
	}
}

// A silent server must exhaust Pion's retries, without waiting for the outer
// watchdog or being cut off by a shorter timer that also hurts slow replies.
func TestDialAndAllocateLetsPionExhaustRetransmissions(t *testing.T) {
	pc := listenFakeRelay(t) // accepts datagrams but never replies
	defer resetServerHealth()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	_, _, _, _, _, err := dialAndAllocate(ctx, &stream{}, "user", "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
	if err == nil || !strings.Contains(err.Error(), "all retransmissions failed") {
		t.Fatalf("want Pion's retransmission failure, got %v", err)
	}
	if len(allocSemaphore) != 0 {
		t.Fatal("failed Allocate kept a semaphore slot")
	}
}

// A stream losing a failover race must release its semaphore slot immediately,
// even though the server has not replied and Pion's retry budget remains.
func TestDialAndAllocateCancellationReleasesSlot(t *testing.T) {
	pc := listenFakeRelay(t)
	defer resetServerHealth()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	go func() {
		buf := make([]byte, 2048)
		pc.ReadFrom(buf)
		cancel()
	}()
	_, _, _, _, _, err := dialAndAllocate(ctx, &stream{}, "user", "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	if len(allocSemaphore) != 0 {
		t.Fatal("cancelled Allocate kept a semaphore slot")
	}
}

// Pion holds its transaction mutex while retransmitting. Block that write
// until Close, as a stalled transport can do, to exercise the real lock order.
type blockedAllocateRetransmit struct {
	closed    chan struct{}
	blocked   chan struct{}
	writes    atomic.Int32
	closeOnce sync.Once
	blockOnce sync.Once
}

func (c *blockedAllocateRetransmit) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *blockedAllocateRetransmit) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.writes.Add(1) == 1 {
		return len(b), nil
	}
	c.blockOnce.Do(func() { close(c.blocked) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockedAllocateRetransmit) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*blockedAllocateRetransmit) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (*blockedAllocateRetransmit) SetDeadline(time.Time) error      { return nil }
func (*blockedAllocateRetransmit) SetReadDeadline(time.Time) error  { return nil }
func (*blockedAllocateRetransmit) SetWriteDeadline(time.Time) error { return nil }

func TestAllocateAbortUnblocksPionRetransmit(t *testing.T) {
	for _, cancelRace := range []bool{false, true} {
		name := "watchdog"
		if cancelRace {
			name = "cancelled-race"
		}
		t.Run(name, func(t *testing.T) {
			raw := &blockedAllocateRetransmit{closed: make(chan struct{}), blocked: make(chan struct{})}
			client, err := turn.NewClient(&turn.ClientConfig{Conn: raw, TURNServerAddr: "127.0.0.1:3478", Username: "user", Password: "pass"})
			if err != nil {
				t.Fatal(err)
			}
			// Keep test cleanup able to unblock a regression in the helper itself.
			defer client.Close()
			defer raw.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout := 2 * time.Second
			if cancelRace {
				timeout = time.Minute
			}
			done := make(chan error, 1)
			go func() {
				_, err := allocateWithDeadline(ctx, timeout, client.Allocate, func() { closeFailedAllocation(client, raw) })
				done <- err
			}()
			select {
			case <-raw.blocked:
			case <-time.After(time.Second):
				t.Fatal("Pion never started the retransmission")
			}
			want := errAllocateTimeout
			wait := 3 * time.Second
			if cancelRace {
				cancel()
				want = context.Canceled
				wait = time.Second
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("err=%v, want %v", err, want)
				}
			case <-time.After(wait):
				t.Fatal("abort blocked behind Pion's retransmission mutex")
			}
		})
	}
}
