/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"math"
	"net"
	"testing"
	"time"
)

// The relay proof over UDP waits relayProofRTTs of the round trips the session
// timed, between relayProofTimeout and dataPlaneHandshakeTimeout. The 20.10
// figures are the field log behind it (relayProofLimit): a window those round
// trips no longer fit is how a congested cell stood two working relays down.
func TestUDPRelayProofLimit(t *testing.T) {
	for _, c := range []struct {
		name string
		rtt  time.Duration
		want time.Duration
	}{
		{"round trip not timed", 0, relayProofTimeout},
		{"negative is not a round trip", -time.Second, relayProofTimeout},
		{"a healthy Allocate", 230 * time.Millisecond, relayProofTimeout},
		{"the last round trip the floor covers", time.Second, relayProofTimeout},
		{"just past it", 1100 * time.Millisecond, 2200 * time.Millisecond},
		{"20.10: permission granted in 1.616s", 1616 * time.Millisecond, 3232 * time.Millisecond},
		{"20.10: permission granted in 2.648s", 2648 * time.Millisecond, 5296 * time.Millisecond},
		{"20.10: Allocate in 3.3s", 3300 * time.Millisecond, 6600 * time.Millisecond},
		{"the first round trip the ceiling cuts", dataPlaneHandshakeTimeout / relayProofRTTs, dataPlaneHandshakeTimeout},
		{"20.10: Allocate in 7.4s", 7400 * time.Millisecond, dataPlaneHandshakeTimeout},
		{"a round trip that would overflow", time.Duration(math.MaxInt64), dataPlaneHandshakeTimeout},
	} {
		if got := udpRelayProofLimit(c.rtt); got != c.want {
			t.Errorf("%s: udpRelayProofLimit(%v) = %v, want %v", c.name, c.rtt, got, c.want)
		}
	}
}

// Over TCP the limit is already the ceiling (relayProofLimit); a measured round
// trip changes nothing there.
func TestRelayProofLimitOverTCPIgnoresTheRoundTrip(t *testing.T) {
	s := &stream{}
	s.overTCP.Store(true)
	for _, rtt := range []time.Duration{0, 300 * time.Millisecond, 3 * time.Second, time.Minute} {
		if got := s.relayProofLimit(rtt); got != relayProofTimeoutTCP {
			t.Fatalf("over TCP with rtt %v the limit is %v, want relayProofTimeoutTCP (%v)", rtt, got, relayProofTimeoutTCP)
		}
	}
	s.overTCP.Store(false)
	if got := s.relayProofLimit(3 * time.Second); got != udpRelayProofLimit(3*time.Second) {
		t.Fatalf("over UDP the limit is %v, want udpRelayProofLimit's %v", got, udpRelayProofLimit(3*time.Second))
	}
}

// Only a permission the relay granted is a round trip; one still waited on, one
// refused, and a conn nobody timed say nothing about the path's pace.
func TestPermissionGrantedIn(t *testing.T) {
	if got := permissionGrantedIn(&scriptedRelay{}); got != 0 {
		t.Fatalf("a conn without a probe gave %v", got)
	}

	p := newRelayWriteProbe(&scriptedRelay{})
	if got := permissionGrantedIn(p); got != 0 {
		t.Fatalf("a probe nothing was written through gave %v", got)
	}

	relay := &scriptedRelay{release: make(chan struct{})}
	p = newRelayWriteProbe(relay)
	returned := make(chan struct{})
	go func() {
		p.WriteTo([]byte("hello"), probePeer)
		close(returned)
	}()
	for !p.started.Load() {
		time.Sleep(time.Millisecond)
	}
	if got := permissionGrantedIn(p); got != 0 {
		t.Fatalf("a permission still waited on gave %v", got)
	}
	time.Sleep(50 * time.Millisecond)
	close(relay.release)
	<-returned
	if got := permissionGrantedIn(p); got < 50*time.Millisecond || got != p.took {
		t.Fatalf("a granted permission gave %v, want the first write's %v", got, p.took)
	}

	p = newRelayWriteProbe(&scriptedRelay{err: errors.New("error 403: Forbidden")})
	p.WriteTo([]byte("hello"), probePeer)
	if got := permissionGrantedIn(p); got != 0 {
		t.Fatalf("a refused permission gave %v", got)
	}
}

// slowPermissionConn holds its first write for delay, as pion's relay WriteTo
// holds the first packet to a peer until CreatePermission is answered, and
// closes granted when it returns. That write is the header burst's, before
// runNoDTLS starts any goroutine, so first needs no lock.
type slowPermissionConn struct {
	net.PacketConn
	delay   time.Duration
	granted chan struct{}
	first   bool
}

func (c *slowPermissionConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !c.first {
		c.first = true
		time.Sleep(c.delay)
		defer close(c.granted)
	}
	return c.PacketConn.WriteTo(b, addr)
}

// awaitProofPastTheFloor runs runNoDTLS against a relay that starts echoing
// echoAfter after opened, and fails the test unless the stream proves its path.
func awaitProofPastTheFloor(t *testing.T, s *stream, relayConn net.PacketConn, opened <-chan struct{}, echoAfter time.Duration) {
	t.Helper()
	answer := make(chan struct{})
	peer := fakeRelay(t, answer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.runNoDTLS(ctx, relayConn, peer) }()

	<-opened
	time.AfterFunc(echoAfter, func() { close(answer) })
	deadline := time.After(echoAfter + 2*time.Second)
	for !s.ready.Load() {
		select {
		case err := <-done:
			t.Fatalf("a relay that answered %v into the proof failed the stream: %v", echoAfter, err)
		case <-deadline:
			t.Fatal("a relay that answered never made the stream ready")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Field log 20.10: a relay that granted the permission in 1.6-2.6s was failed at
// relayProofTimeout, while nine other streams carried traffic over it. A
// permission that slow now buys the echo the room for its own round trip.
func TestNoDTLSWaitsForTheEchoOnASlowPermission(t *testing.T) {
	defer resetServerHealth()
	resetServerHealth()

	s, relayConn := newNoDTLSTestStream(t)
	slow := &slowPermissionConn{PacketConn: relayConn, delay: 1800 * time.Millisecond, granted: make(chan struct{})}
	// Window: 2 × 1.8s = 3.6s from the end of the header burst; the echo comes
	// 2.4s after the permission, past relayProofTimeout.
	awaitProofPastTheFloor(t, s, newRelayWriteProbe(slow), slow.granted, relayProofTimeout+400*time.Millisecond)
}

// ...and so does a slow Allocate: its round trips count as much as the
// permission's.
func TestNoDTLSWaitsForTheEchoAfterASlowAllocate(t *testing.T) {
	defer resetServerHealth()
	resetServerHealth()

	s, relayConn := newNoDTLSTestStream(t)
	s.allocateRTT = 1800 * time.Millisecond
	opened := make(chan struct{})
	close(opened)
	// Window: 2 × 1.8s = 3.6s; the echo comes at 2.4s, past relayProofTimeout.
	awaitProofPastTheFloor(t, s, relayConn, opened, relayProofTimeout+400*time.Millisecond)
}
