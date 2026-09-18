/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// scriptedRelay stands in for pion's relay conn: every WriteTo waits for
// release (nil = return at once) and then returns err.
type scriptedRelay struct {
	net.PacketConn
	release chan struct{}
	err     error
	writes  int
}

func (r *scriptedRelay) WriteTo(b []byte, _ net.Addr) (int, error) {
	r.writes++
	if r.release != nil {
		<-r.release
	}
	if r.err != nil {
		return 0, r.err
	}
	return len(b), nil
}

var probePeer = &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 56000}

// Each outcome of the first write names a different side of the relay; the
// wording is what a field log gets, so it is pinned here.
func TestRelayWriteProbeNamesTheFailingSide(t *testing.T) {
	t.Run("nothing written", func(t *testing.T) {
		p := newRelayWriteProbe(&scriptedRelay{})
		if got := p.describe(time.Now()); !strings.Contains(got, "nothing was written") {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("permission unanswered", func(t *testing.T) {
		relay := &scriptedRelay{release: make(chan struct{})}
		p := newRelayWriteProbe(relay)
		returned := make(chan struct{})
		go func() {
			p.WriteTo([]byte("hello"), probePeer)
			close(returned)
		}()
		for !p.started.Load() {
			time.Sleep(time.Millisecond)
		}
		got := p.describe(p.startAt.Add(8 * time.Second))
		close(relay.release)
		<-returned
		if !strings.Contains(got, "never answered") || !strings.Contains(got, "8s") {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("permission refused", func(t *testing.T) {
		p := newRelayWriteProbe(&scriptedRelay{err: errors.New("error 403: Forbidden")})
		if _, err := p.WriteTo([]byte("hello"), probePeer); err == nil {
			t.Fatal("the probe swallowed the relay's refusal")
		}
		if got := p.describe(time.Now()); !strings.Contains(got, "failed") || !strings.Contains(got, "403") {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("peer silent", func(t *testing.T) {
		p := newRelayWriteProbe(&scriptedRelay{})
		p.WriteTo([]byte("hello"), probePeer)
		if got := p.describe(time.Now()); !strings.Contains(got, "no reply came back") {
			t.Fatalf("got %q", got)
		}
	})
}

// Only the first write is timed; the rest go straight through and do not
// overwrite its verdict.
func TestRelayWriteProbeKeepsTheFirstVerdict(t *testing.T) {
	relay := &scriptedRelay{}
	p := newRelayWriteProbe(relay)
	p.WriteTo([]byte("first"), probePeer)
	relay.err = errors.New("use of closed network connection")
	for i := 0; i < 3; i++ {
		p.WriteTo([]byte("later"), probePeer)
	}
	if relay.writes != 4 {
		t.Fatalf("relay saw %d writes, want 4", relay.writes)
	}
	if got := p.describe(time.Now()); !strings.Contains(got, "no reply came back") {
		t.Fatalf("a later write replaced the first verdict: %q", got)
	}
}
