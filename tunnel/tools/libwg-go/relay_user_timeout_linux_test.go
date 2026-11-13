//go:build linux

/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The limit has to be on the socket the TURN traffic is written through — and
// the production one, not whatever a test left behind.
func TestRelayTCPConnectionCarriesTheUserTimeout(t *testing.T) {
	if relayTCPUserTimeout != 30*time.Second {
		t.Fatalf("relayTCPUserTimeout is %v, want 30s: the reasoning beside it is for that number", relayTCPUserTimeout)
	}
	ln := listenTCPRelay(t)
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	conn, err := connectRelayTCP(context.Background(), &net.Dialer{}, ln.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	tc := relayTCPConn(conn)
	if tc == nil {
		t.Fatal("no TCP connection under the relay conn")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ms int
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		ms, optErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
	}); err != nil || optErr != nil {
		t.Fatalf("getsockopt: %v / %v", err, optErr)
	}
	if got := time.Duration(ms) * time.Millisecond; got != relayTCPUserTimeout {
		t.Fatalf("TCP_USER_TIMEOUT on the relay connection is %v, want %v", got, relayTCPUserTimeout)
	}
	if relayFlowGaveUp(conn) == nil {
		t.Fatal("the relay connection does not report its flow being given up")
	}
}

// A healthy idle stream hears its relay once per interval of the keepalive
// grid. A kernel probe before that is a second burst of packets per period on
// every socket (field measurement of 2026-11-12: the LTE radio never slept), so
// the first one has to wait until the stream has missed its echo — on the wide
// grid too (keepalive_economy.go): the socket is not dialed again when the grid
// changes.
func TestRelayTCPConnectionIsNotProbedBetweenKeepalives(t *testing.T) {
	if relayTCPKeepAlive.Idle < economyKeepaliveInterval+keepaliveSpread+5*time.Second {
		t.Fatalf("the kernel probes an idle relay socket after %v: inside a healthy stream's gap between two echoes on the wide grid (%v + %v + a round trip)",
			relayTCPKeepAlive.Idle, economyKeepaliveInterval, keepaliveSpread)
	}
	ln := listenTCPRelay(t)
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	// The dialer the streams use carries no keepalive settings of its own.
	conn, err := connectRelayTCP(context.Background(), &net.Dialer{}, ln.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	tc := relayTCPConn(conn)
	if tc == nil {
		t.Fatal("no TCP connection under the relay conn")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	opt := func(level, name int) int {
		t.Helper()
		var v int
		var optErr error
		if err := raw.Control(func(fd uintptr) {
			v, optErr = unix.GetsockoptInt(int(fd), level, name)
		}); err != nil || optErr != nil {
			t.Fatalf("getsockopt: %v / %v", err, optErr)
		}
		return v
	}
	if opt(unix.SOL_SOCKET, unix.SO_KEEPALIVE) == 0 {
		t.Fatal("keepalive is off on the relay connection: the reserve behind our own keepalive is gone")
	}
	if got := time.Duration(opt(unix.IPPROTO_TCP, unix.TCP_KEEPIDLE)) * time.Second; got != relayTCPKeepAlive.Idle {
		t.Fatalf("TCP_KEEPIDLE on the relay connection is %v, want %v", got, relayTCPKeepAlive.Idle)
	}
	if got := time.Duration(opt(unix.IPPROTO_TCP, unix.TCP_KEEPINTVL)) * time.Second; got != relayTCPKeepAlive.Interval {
		t.Fatalf("TCP_KEEPINTVL on the relay connection is %v, want %v", got, relayTCPKeepAlive.Interval)
	}
}
