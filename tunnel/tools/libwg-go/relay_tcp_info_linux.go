//go:build linux

/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// readRelaySocket reads the kernel's view of one relay connection. Read-only:
// one getsockopt on a socket we opened, which an app may do on Android.
//
// The struct has grown with the kernel and an older one fills only the front of
// it: what it does not know stays zero — byte counters before 4.1, unsent bytes
// and data segments before 4.6, the busy/limited times before 4.10 — and the
// summary leaves those parts out.
func readRelaySocket(c *net.TCPConn) (relaySocketSample, bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return relaySocketSample{}, false
	}
	var info *unix.TCPInfo
	var infoErr error
	if err := raw.Control(func(fd uintptr) {
		info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil || infoErr != nil || info == nil {
		return relaySocketSample{}, false
	}

	s := relaySocketSample{
		acked:    info.Bytes_acked,
		received: info.Bytes_received,
		segsOut:  uint64(info.Data_segs_out),
		retrans:  uint64(info.Total_retrans),
		backlog:  int(info.Unacked)*int(info.Snd_mss) + int(info.Notsent_bytes),
		timeouts: int(info.Retransmits),
		rtt:      time.Duration(info.Rtt) * time.Microsecond,

		busy:               time.Duration(info.Busy_time) * time.Microsecond,
		waitedOnPeerWindow: time.Duration(info.Rwnd_limited) * time.Microsecond,
		waitedOnSendBuffer: time.Duration(info.Sndbuf_limited) * time.Microsecond,
	}
	// A closed window is probed rather than retransmitted into: the head segment
	// was never sent, so Retransmits stays zero while Probes counts.
	if info.Probes > 0 && s.timeouts == 0 {
		s.timeouts, s.probing = int(info.Probes), true
	}
	return s, true
}

// setTCPUserTimeout sets TCP_USER_TIMEOUT: an ordinary socket option, open to an
// app on Android like any other, there since Linux 2.6.37.
func setTCPUserTimeout(c *net.TCPConn, d time.Duration) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(d/time.Millisecond))
	}); err != nil {
		return err
	}
	return optErr
}
