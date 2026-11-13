//go:build linux

/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"sync/atomic"
	"syscall"
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
	queued, queuedErr := 0, error(nil)
	if err := raw.Control(func(fd uintptr) {
		info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		// Only to tell the kinds of probe apart, below: what the socket holds
		// not yet acknowledged, sent or not, on any kernel.
		if infoErr == nil && info != nil && info.Probes > 0 && info.Retransmits == 0 {
			queued, queuedErr = unix.IoctlGetInt(int(fd), unix.SIOCOUTQ)
		}
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

		sinceData: time.Duration(info.Last_data_recv) * time.Millisecond,
		sinceAck:  time.Duration(info.Last_ack_recv) * time.Millisecond,
		sndMSS:    int(info.Snd_mss),
		rcvMSS:    int(info.Rcv_mss),
		pathMTU:   int(info.Pmtu),
	}
	if info.Snd_wnd > 0 && !relayKernelSaysSendWindow.Load() {
		relayKernelSaysSendWindow.Store(true)
	}
	// A closed window is probed rather than retransmitted into: the head segment
	// was never sent, so Retransmits stays zero while Probes counts.
	//
	// The kernel keeps that one count for the keepalive probes of an idle
	// connection too (icsk_probes_out), and Go's dialer turns keepalive on. A
	// window probe stands in for data the window keeps from leaving: nothing in
	// flight and bytes waiting. Anything else is a keepalive probe — sent with
	// nothing waiting, or still unanswered under data written since. Field log,
	// 2026-11-09, RTK over TCP, the tunnel idle: two streams on two relays at
	// once were reported as "the relay's receive window closed, 1 window
	// probe(s) unanswered, up to 0 KB waiting in the socket".
	//
	// And it counts the same way when the window is open and the segment still
	// does not go out: the probe timer is what retries a send that failed on the
	// phone (tcp_send_probe0 counts whenever nothing is in flight afterwards).
	// The window the relay last advertised tells the two apart, on a kernel that
	// reports it; a window too small for the segment is not a third case, the
	// probe sends what fits. See stallHeldHere for the log behind this.
	if info.Probes > 0 && s.timeouts == 0 {
		s.timeouts = int(info.Probes)
		if queuedErr != nil {
			queued = int(info.Notsent_bytes) // zero before 4.6: reads as a keepalive probe
		}
		s.stall = relayProbeKind(int(info.Unacked), queued, int(info.Snd_wnd), relayKernelSaysSendWindow.Load())
	}
	return s, true
}

// relayKernelSaysSendWindow is set once any relay socket has shown a send
// window. tcpi_snd_wnd came with Linux 5.4; an older kernel leaves it zero on
// every socket, which must not read as every window being closed. A live
// connection has a window from its handshake on, so on a kernel that reports it
// the first sample of the first socket sets this.
var relayKernelSaysSendWindow atomic.Bool

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

// setTCPMaxSegment sets TCP_MAXSEG on a socket that has not connected yet.
func setTCPMaxSegment(c syscall.RawConn, mss int) error {
	var optErr error
	if err := c.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, mss)
	}); err != nil {
		return err
	}
	return optErr
}
