/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

// countingListener counts the connections a TCP relay accepted: whether a relay
// was dialed at all is what several tests here turn on.
type countingListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

type tcpTestRelay struct {
	addr string
	ln   *countingListener
}

func listenTCPRelay(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return &countingListener{Listener: ln}
}

func startTCPTestRelay(t *testing.T, ln *countingListener) *tcpTestRelay {
	t.Helper()
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "tcp-relay-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "tcp-relay-test", "pass"), true
		},
		ListenerConfigs: []turn.ListenerConfig{{
			Listener:              ln,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return &tcpTestRelay{addr: ln.Addr().String(), ln: ln}
}

// twoTCPRelayListeners returns two listeners in the order the session would
// dial their addresses, like twoRelaySockets does for UDP.
func twoTCPRelayListeners(t *testing.T) (first, second *countingListener) {
	t.Helper()
	a, b := listenTCPRelay(t), listenTCPRelay(t)
	if assignServers([]string{a.Addr().String(), b.Addr().String()})[0] == a.Addr().String() {
		return a, b
	}
	return b, a
}

// overTCP pushes the TCP choice the way wgSetNetwork does, for one test.
func overTCP(t *testing.T) {
	t.Helper()
	setRelayTransport(relayTransportTCP)
	t.Cleanup(func() { setRelayTransport(relayTransportAsConfigured) })
}

// hangConnectsTo makes the TCP connect to addr hang until it is cancelled or
// times out — a blackholed SYN — and reports the timeout each dial was given.
func hangConnectsTo(t *testing.T, addr string) *atomic.Int64 {
	t.Helper()
	var timeout atomic.Int64
	prev := dialRelayTCP
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, to string) (net.Conn, error) {
		timeout.Store(int64(d.Timeout))
		if to != addr {
			return prev(ctx, d, to)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(d.Timeout):
			return nil, errors.New("i/o timeout")
		}
	}
	t.Cleanup(func() { dialRelayTCP = prev })
	return &timeout
}

// The whole path over TCP: connect, Allocate, and the relay proof — a round trip
// through the relay to the peer and back, framed over the stream. The config
// says UDP; the network's choice, read at the dial, is what decides.
func TestWorkerReachesTheRelayOverTCP(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t)) // listens on TCP only
	overTCP(t)

	h := runWorkersAgainst(t, 111, 1, []string{relay.addr})
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	if n := relay.ln.accepted.Load(); n != 1 {
		t.Fatalf("the relay accepted %d TCP connection(s), want 1", n)
	}
}

func TestRelayTransportFollowsTheConfigUnlessTheNetworkSaysOtherwise(t *testing.T) {
	t.Cleanup(func() { setRelayTransport(relayTransportAsConfigured) })
	udpConfig, tcpConfig := WorkerGroupConfig{UseUDP: true}, WorkerGroupConfig{UseUDP: false}

	for _, tc := range []struct {
		choice         int32
		udpCfg, tcpCfg bool // want relayOverTCP
	}{
		{relayTransportAsConfigured, false, true},
		{relayTransportUDP, false, false},
		{relayTransportTCP, true, true},
		{99, false, true}, // anything unknown is "as configured", not TCP
	} {
		setRelayTransport(tc.choice)
		if got := relayOverTCP(udpConfig); got != tc.udpCfg {
			t.Errorf("choice %d, UseUDP=true: over TCP = %v, want %v", tc.choice, got, tc.udpCfg)
		}
		if got := relayOverTCP(tcpConfig); got != tc.tcpCfg {
			t.Errorf("choice %d, UseUDP=false: over TCP = %v, want %v", tc.choice, got, tc.tcpCfg)
		}
	}
}

// Over TCP a dark relay is silent a step earlier than over UDP: the connect
// hangs, and no Allocate is ever sent for the Allocate head start to time. The
// connect has to have a head start of its own, or the attempt sits out the
// whole connect timeout before the answering relay is even dialed.
func TestSilentTCPConnectIsRacedAfterTheHeadStart(t *testing.T) {
	first, second := twoTCPRelayListeners(t)
	live := startTCPTestRelay(t, second)
	dark := first.Addr().String()
	overTCP(t)
	timeout := hangConnectsTo(t, dark)

	started := time.Now()
	h := runWorkersAgainst(t, 112, 1, []string{dark, live.addr})

	waitFor(t, "a stream on the answering relay", relayHeadStart+3*time.Second, func() bool { return h.ready() == 1 })
	if took := time.Since(started); took < relayHeadStart {
		t.Fatalf("up after %v: the second relay was dialed before the head start ran out", took)
	}
	if got := h.streams[0].serverAddr; got != live.addr {
		t.Fatalf("session runs on %s, want the answering relay %s", got, live.addr)
	}
	if got := time.Duration(timeout.Load()); got != relayTCPConnectTimeout {
		t.Fatalf("TCP connect was given %v, want %v", got, relayTCPConnectTimeout)
	}
}

// A healthy first relay wins alone over TCP as well.
func TestHealthyTCPRelayIsNotRaced(t *testing.T) {
	first, second := twoTCPRelayListeners(t)
	a := startTCPTestRelay(t, first)
	b := startTCPTestRelay(t, second)
	overTCP(t)

	h := runWorkersAgainst(t, 113, 1, []string{a.addr, b.addr})
	waitFor(t, "a stream on the first relay", 3*time.Second, func() bool { return h.ready() == 1 })
	time.Sleep(relayHeadStart + 300*time.Millisecond)

	if n := b.ln.accepted.Load(); n != 0 {
		t.Fatalf("the second relay was dialed %d time(s) although the first answered at once", n)
	}
}

// A refused connect is an answer: fan out at once, and hold it against the
// relay the way a failed Allocate is held.
func TestRefusedTCPConnectCountsAgainstTheRelay(t *testing.T) {
	first, second := twoTCPRelayListeners(t)
	live := startTCPTestRelay(t, second)
	refusing := first.Addr().String()
	first.Close() // nothing listens there any more
	overTCP(t)

	started := time.Now()
	h := runWorkersAgainst(t, 114, 1, []string{refusing, live.addr})
	waitFor(t, "a stream on the answering relay", 3*time.Second, func() bool { return h.ready() == 1 })
	if took := time.Since(started); took >= relayHeadStart {
		t.Fatalf("up after %v: a refusal waited out the head start", took)
	}

	serverHealthState.Lock()
	entry := serverHealthState.byAddr[refusing]
	serverHealthState.Unlock()
	if entry == nil || entry.failures == 0 {
		t.Fatal("the refused connect was not counted against the relay")
	}
}

// recordingConn keeps every Write as its own record, which is how segments are
// told apart here.
type recordingWriteConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordingWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}

func TestFirstWriteToTheRelayIsSplitAheadOfTheMagicCookie(t *testing.T) {
	rec := &recordingWriteConn{}
	conn := &splitFirstWriteConn{Conn: rec}

	request := bytes.Repeat([]byte{0xAB}, 28)
	if n, err := conn.Write(request); err != nil || n != len(request) {
		t.Fatalf("first write: n=%d err=%v, want %d", n, err, len(request))
	}
	second := bytes.Repeat([]byte{0xCD}, 40)
	if n, err := conn.Write(second); err != nil || n != len(second) {
		t.Fatalf("second write: n=%d err=%v, want %d", n, err, len(second))
	}

	if len(rec.writes) != 3 {
		t.Fatalf("%d writes reached the socket, want 3 (the first one split, the second whole)", len(rec.writes))
	}
	// The STUN magic cookie sits at bytes 4..8: the cut has to fall before its end.
	if got := len(rec.writes[0]); got != firstWriteSplit || got >= 8 {
		t.Fatalf("first segment is %d bytes, want %d (< 8)", got, firstWriteSplit)
	}
	if !bytes.Equal(append(append([]byte(nil), rec.writes[0]...), rec.writes[1]...), request) {
		t.Fatal("the two segments do not add up to the request")
	}
	if !bytes.Equal(rec.writes[2], second) {
		t.Fatal("a later write was not passed through whole")
	}
}

// The wrapper is no use unless the connection TURN is written through is the
// wrapped one: what reaches the relay first must be the short segment.
func TestRelayTCPConnectionSplitsItsFirstWrite(t *testing.T) {
	ln := listenTCPRelay(t)
	firstRead := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		n, _ := c.Read(make([]byte, 1500))
		firstRead <- n
	}()

	conn, err := connectRelayTCP(context.Background(), &net.Dialer{}, ln.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(bytes.Repeat([]byte{0xAB}, 28)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case n := <-firstRead:
		if n != firstWriteSplit {
			t.Fatalf("the relay's first read got %d bytes, want the %d-byte first segment", n, firstWriteSplit)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the relay never read anything")
	}
}
