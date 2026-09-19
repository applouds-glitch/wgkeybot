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
