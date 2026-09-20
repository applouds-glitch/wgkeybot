//go:build linux

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
)

func sendMSS(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	s, ok := readRelaySocket(c)
	if !ok {
		t.Fatal("TCP_INFO unreadable")
	}
	return s.sndMSS
}

// The cap has to hold in BOTH directions, and what comes down from the relay is
// the one that matters: the relay keeps to it only if our SYN announced it, which
// is why the option goes on before the connect. Loopback's own MSS is ~65000, so
// nothing but the option brings either side down here.
func TestRelayTCPSegmentsAreCappedBothWays(t *testing.T) {
	if relayTCPMaxSegment != 1240 {
		t.Fatalf("relayTCPMaxSegment is %d, want 1240: the reasoning beside it is for that number", relayTCPMaxSegment)
	}
	ln := listenTCPRelay(t)
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c.(*net.TCPConn)
		}
	}()

	protected := 0
	d := &net.Dialer{Control: func(_, _ string, _ syscall.RawConn) error { protected++; return nil }}
	conn, err := connectRelayTCP(context.Background(), d, ln.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	far := <-accepted
	defer far.Close()

	if protected != 1 {
		t.Fatalf("the dialer's own control ran %d time(s), want 1: the socket must still be protected", protected)
	}
	// Timestamps take 12 bytes out of every segment; never more than the cap.
	if got := sendMSS(t, relayTCPConn(conn)); got > relayTCPMaxSegment || got < relayTCPMaxSegment-40 {
		t.Fatalf("our segments to the relay: mss %d, want at most %d", got, relayTCPMaxSegment)
	}
	if got := sendMSS(t, far); got > relayTCPMaxSegment || got < relayTCPMaxSegment-40 {
		t.Fatalf("the relay's segments to us: mss %d, want at most %d — the cap was not in the SYN", got, relayTCPMaxSegment)
	}
}

// A socket that cannot be protected is not connected, cap or no cap.
func TestRelayTCPConnectStillFailsOnAnUnprotectedSocket(t *testing.T) {
	ln := listenTCPRelay(t)
	d := &net.Dialer{Control: func(_, _ string, _ syscall.RawConn) error { return errSocketNotProtected }}
	conn, err := connectRelayTCP(context.Background(), d, ln.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("connected through a socket whose protect failed")
	}
	if !errors.Is(err, errSocketNotProtected) {
		t.Fatalf("the protect error was lost: %v", err)
	}
}
