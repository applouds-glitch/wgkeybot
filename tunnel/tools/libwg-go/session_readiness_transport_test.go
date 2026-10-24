/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// Close closes the underlying socket, but deliberately cannot release the
// marker's WriteTo. The transport must withdraw ready before joining TX.
type readinessBlockedWriter struct {
	net.PacketConn
	marker  []byte
	entered chan struct{}
	release chan struct{}
}

func (c *readinessBlockedWriter) WriteTo(p []byte, addr net.Addr) (int, error) {
	if bytes.Equal(p, c.marker) {
		close(c.entered)
		<-c.release
	}
	return c.PacketConn.WriteTo(p, addr)
}

func TestNoDTLSDropsReadyBeforeBlockedTXReturns(t *testing.T) {
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	s, conn := newNoDTLSTestStream(t)
	answer := make(chan struct{})
	close(answer)
	peer := fakeRelay(t, answer)
	writer := &readinessBlockedWriter{
		PacketConn: conn,
		marker:     []byte("readiness-blocked-TX"),
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	s.okFunc = func() { close(ready) }
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runNoDTLS(ctx, writer, peer)
	}()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(writer.release) }) }
	t.Cleanup(func() {
		cancel()
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("runNoDTLS did not stop during cleanup")
		}
	})
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("answering relay never made the transport ready")
	}
	marker := packetPool.Get().([]byte)[:len(writer.marker)]
	copy(marker, writer.marker)
	s.in <- marker
	select {
	case <-writer.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("TX never entered the blocked marker write")
	}
	// Fail RX while TX cannot return, even when teardown calls Close.
	conn.Close()
	waitFor(t, "ready=false while TX is still blocked", 2*time.Second, func() bool { return !s.ready.Load() })
	select {
	case <-done:
		t.Fatal("runNoDTLS returned before TX was released")
	default:
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runNoDTLS did not return after TX was released")
	}
	if s.ready.Load() {
		t.Fatal("runNoDTLS returned with ready still true")
	}
}
