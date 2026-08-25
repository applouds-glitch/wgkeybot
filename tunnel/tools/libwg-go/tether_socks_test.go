/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"io"
	"net"
	"testing"
	"time"
)

// socksGreet performs the SOCKS5 method negotiation and fails the test if the
// proxy does not settle on "no authentication".
func socksGreet(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("greeting reply %v, want [5 0]", reply)
	}
}

// Desktop clients point their system SOCKS setting at us; a CONNECT to a name
// must be resolved on the phone and answered with a success reply.
func TestTetherSocksConnectByDomain(t *testing.T) {
	dial := newRecordingDial()
	p := newTestTetherProxy(t, dial.fn)

	c := dialProxy(t, p)
	socksGreet(t, c)

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x01, 0xbb) // port 443
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	up := dial.upstream(t)
	if got := dial.lastCall(t); got != "example.com:443" {
		t.Fatalf("dialled %q, want example.com:443", got)
	}

	reply := make([]byte, 10)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("reply code 0x%02x, want 0x00 (succeeded)", reply[1])
	}

	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, 4)
	_ = up.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(up, buf); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("upstream got %q, want ping", buf)
	}
}

// A literal IPv4 target skips the resolver entirely.
func TestTetherSocksConnectByIPv4(t *testing.T) {
	dial := newRecordingDial()
	p := newTestTetherProxy(t, dial.fn)

	c := dialProxy(t, p)
	socksGreet(t, c)

	if _, err := c.Write([]byte{0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = dial.upstream(t)
	if got := dial.lastCall(t); got != "93.184.216.34:80" {
		t.Fatalf("dialled %q, want 93.184.216.34:80", got)
	}
}

// UDP ASSOCIATE belongs to the transparent-client stage; refusing it explicitly
// is what lets a client fall back to TCP instead of hanging.
func TestTetherSocksRefusesUdpAssociate(t *testing.T) {
	p := newTestTetherProxy(t, failingDial)

	c := dialProxy(t, p)
	socksGreet(t, c)

	if _, err := c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply := make([]byte, 10)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x07 {
		t.Fatalf("reply code 0x%02x, want 0x07 (command not supported)", reply[1])
	}
}

// A client configured for username/password auth offers no 0x00, and answering
// "no authentication" regardless left it waiting for an exchange that was never
// going to happen. RFC 1928 asks for 0xFF and a close, which reads as a
// misconfiguration instead of a hang.
func TestTetherSocksRefusesWhenNoAuthNotOffered(t *testing.T) {
	p := newTestTetherProxy(t, failingDial)

	c := dialProxy(t, p)
	// One method offered: 0x02, username/password.
	if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	reply := make([]byte, 2)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0xff {
		t.Fatalf("greeting reply %v, want [5 255] (no acceptable methods)", reply)
	}
	if !readClosed(c, 2*time.Second) {
		t.Fatal("proxy kept a refused SOCKS client open")
	}
}
