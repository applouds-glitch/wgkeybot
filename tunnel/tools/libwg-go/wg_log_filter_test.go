/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"reflect"
	"testing"
	"time"
)

type wgLogCapture struct {
	clock time.Time
	lines []string
	l     *wgLogThinner
}

func newWGLogCapture() *wgLogCapture {
	c := &wgLogCapture{clock: time.Unix(1_000_000, 0)}
	c.l = newWGLogThinner(
		func(s string) { c.lines = append(c.lines, "D "+s) },
		func(s string) { c.lines = append(c.lines, "E "+s) },
	)
	c.l.now = func() time.Time { return c.clock }
	return c
}

func (c *wgLogCapture) at(d time.Duration) *wgLogCapture {
	c.clock = time.Unix(1_000_000, 0).Add(d)
	return c
}

func (c *wgLogCapture) expect(t *testing.T, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	got := c.lines
	if got == nil {
		got = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lines:\n got  %q\n want %q", got, want)
	}
}

const testPeer = "peer(QEw9…YHlE)"

// The format strings below are wireguard-go's own (device/send.go,
// device/receive.go, device/uapi.go): the thinner matches on them.

func TestWGLogThinnerDropsWorkerRoutines(t *testing.T) {
	c := newWGLogCapture()
	for id := 1; id <= 8; id++ {
		c.l.Verbosef("Routine: encryption worker %d - started", id)
		c.l.Verbosef("Routine: decryption worker %d - started", id)
		c.l.Verbosef("Routine: handshake worker %d - started", id)
		c.l.Verbosef("Routine: handshake worker %d - stopped", id)
	}
	c.l.Verbosef("Routine: TUN reader - started")
	c.expect(t, "D Routine: TUN reader - started")
}

func TestWGLogThinnerCollapsesKeepalivesUntilTheNextLine(t *testing.T) {
	c := newWGLogCapture()
	for i := 0; i < 6; i++ {
		c.at(time.Duration(i)*25*time.Second).l.Verbosef("%v - Sending keepalive packet", testPeer)
	}
	c.expect(t)
	c.at(145*time.Second).l.Verbosef("%v - Sending handshake initiation", testPeer)
	c.expect(t,
		"D "+testPeer+" - Sending keepalive packet ×6 over 2m5s, the last 20s ago",
		"D "+testPeer+" - Sending handshake initiation")
}

func TestWGLogThinnerSingleLineReadsAsWritten(t *testing.T) {
	c := newWGLogCapture()
	c.l.Verbosef("%v - Receiving keepalive packet", testPeer)
	c.l.Verbosef("%v - Received handshake response", testPeer)
	c.at(10*time.Second).l.Verbosef("%v - Receiving keepalive packet", testPeer)
	c.at(40*time.Second).l.Verbosef("%v - Sending handshake initiation", testPeer)
	c.expect(t,
		"D "+testPeer+" - Receiving keepalive packet",
		"D "+testPeer+" - Received handshake response",
		"D "+testPeer+" - Receiving keepalive packet (30s ago)",
		"D "+testPeer+" - Sending handshake initiation")
}

func TestWGLogThinnerKeepsKindsApartInOrderOfFirstAppearance(t *testing.T) {
	c := newWGLogCapture()
	c.at(0).l.Verbosef("%v - Receiving keepalive packet", testPeer)
	c.at(1*time.Second).l.Verbosef("%v - Sending keepalive packet", testPeer)
	c.at(26*time.Second).l.Verbosef("%v - Sending keepalive packet", testPeer)
	c.at(30*time.Second).l.Verbosef("%v - Receiving keepalive packet", testPeer)
	c.at(30 * time.Second).l.Verbosef("Device closing")
	c.expect(t,
		"D "+testPeer+" - Receiving keepalive packet ×2 over 30s",
		"D "+testPeer+" - Sending keepalive packet ×2 over 25s, the last 4s ago",
		"D Device closing")
}

func TestWGLogThinnerCollapsesAllowedIPs(t *testing.T) {
	c := newWGLogCapture()
	for i := 0; i < 96; i++ {
		c.l.Verbosef("%v - UAPI: %s allowedip", testPeer, "Adding")
	}
	c.l.Verbosef("%v - Starting", testPeer)
	c.expect(t,
		"D "+testPeer+" - UAPI: Adding allowedip ×96",
		"D "+testPeer+" - Starting")
}

// Nothing else may be logged for a long while; the counted lines must not wait
// for it indefinitely.
func TestWGLogThinnerFlushesARunOnceItIsTheWindowOld(t *testing.T) {
	c := newWGLogCapture()
	step := 25 * time.Second
	var i int
	for ; time.Duration(i)*step < wgLogCollapseWindow; i++ {
		c.at(time.Duration(i)*step).l.Verbosef("%v - Sending keepalive packet", testPeer)
		c.expect(t)
	}
	c.at(time.Duration(i)*step).l.Verbosef("%v - Sending keepalive packet", testPeer)
	c.expect(t, "D "+testPeer+" - Sending keepalive packet ×13 over 5m0s")

	c.lines = nil
	c.at(time.Duration(i+1)*step).l.Verbosef("%v - Sending keepalive packet", testPeer)
	c.at(time.Duration(i+1) * step).l.Verbosef("Device closing")
	c.expect(t,
		"D "+testPeer+" - Sending keepalive packet",
		"D Device closing")
}

func TestWGLogThinnerLetsPendingRunsOutAheadOfAnError(t *testing.T) {
	c := newWGLogCapture()
	c.at(0).l.Verbosef("%v - Sending keepalive packet", testPeer)
	c.at(25*time.Second).l.Verbosef("%v - Sending keepalive packet", testPeer)
	c.at(30*time.Second).l.Errorf("%v - Failed to send data packets: %v", testPeer, "network is unreachable")
	c.expect(t,
		"D "+testPeer+" - Sending keepalive packet ×2 over 25s, the last 5s ago",
		"E "+testPeer+" - Failed to send data packets: network is unreachable")
}
