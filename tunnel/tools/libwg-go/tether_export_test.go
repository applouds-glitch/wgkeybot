/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"strconv"
	"testing"
)

// tunnelAddrsForTest stands in for the tunnel's Interface.Address list, which
// startTetherProxy now requires: without it there is nothing for the egress
// guard to verify an upstream socket against, and sharing refuses to start.
const tunnelAddrsForTest = "10.10.11.126/32"

// freePort picks a port that was free a moment ago. Racy in principle, fine for
// a single-process test.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// Kotlin needs the port back to print the proxy address and the PAC URL, and the
// port it gets must be the one actually bound.
func TestStartTetherProxyBindsAndReportsPort(t *testing.T) {
	port := freePort(t)
	if rc := startTetherProxy("127.0.0.1", port, "127.0.0.1:53", tunnelAddrsForTest); rc != 0 {
		t.Fatalf("startTetherProxy returned %d, want 0", rc)
	}
	defer stopTetherProxy()

	if got := currentTetherStats().Port; got != port {
		t.Fatalf("stats report port %d, want %d", got, port)
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("proxy is not accepting on the reported port: %v", err)
	}
	_ = c.Close()
}

// A busy range is reported as its own failure so the UI can say something better
// than "unknown error".
func TestStartTetherProxyReportsBindFailure(t *testing.T) {
	saved := tetherPortSpan
	tetherPortSpan = 1
	defer func() { tetherPortSpan = saved }()

	port := freePort(t)
	blocker, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer blocker.Close()

	if rc := startTetherProxy("127.0.0.1", port, "", tunnelAddrsForTest); rc != -2 {
		stopTetherProxy()
		t.Fatalf("startTetherProxy returned %d, want -2", rc)
	}
}

// Stop runs on tunnel-down, on fatal errors and on user action; it must not care
// how many times it is called.
func TestStopTetherProxyIsIdempotent(t *testing.T) {
	port := freePort(t)
	if rc := startTetherProxy("127.0.0.1", port, "", tunnelAddrsForTest); rc != 0 {
		t.Fatalf("startTetherProxy returned %d, want 0", rc)
	}
	stopTetherProxy()
	stopTetherProxy()

	if got := currentTetherStats().Port; got != 0 {
		t.Fatalf("stats still report port %d after stop, want 0", got)
	}
}

// takeCurrentTetherProxy peeks at the installed proxy without retiring it.
func takeCurrentTetherProxy() *tetherProxy {
	tetherMu.Lock()
	defer tetherMu.Unlock()
	return tetherCurrent
}

// onFatal and onLeak are dispatched on their own goroutines — neither may block
// the connection it is serving — so one can arrive after the user has switched
// sharing off and on again. Retiring "whatever is current" tore down the healthy
// session that had replaced the failed one.
func TestRetireTetherProxyLeavesASuccessorAlone(t *testing.T) {
	reported := make(chan string, 4)
	saved := reportTetherStopped
	reportTetherStopped = func(reason string) { reported <- reason }
	defer func() { reportTetherStopped = saved }()

	if rc := startTetherProxy("127.0.0.1", freePort(t), "", tunnelAddrsForTest); rc != 0 {
		t.Fatalf("startTetherProxy returned %d, want 0", rc)
	}
	stale := takeCurrentTetherProxy()

	port := freePort(t)
	if rc := startTetherProxy("127.0.0.1", port, "", tunnelAddrsForTest); rc != 0 {
		t.Fatalf("restarting sharing returned %d, want 0", rc)
	}
	defer stopTetherProxy()

	retireTetherProxy(stale, "late accept failure")

	if got := currentTetherStats().Port; got != port {
		t.Fatalf("a late callback from the replaced proxy retired the current one (port %d, want %d)", got, port)
	}
	select {
	case r := <-reported:
		t.Fatalf("a late callback reported %q to Android for a proxy that was already gone", r)
	default:
	}
}

// The Android side otherwise learns of a self-retirement only from its next stats
// poll — thirty seconds apart with the screen off, all of it spent advertising an
// SSID, a password and a QR for a proxy that will never serve another client.
func TestRetireTetherProxyTellsAndroid(t *testing.T) {
	reported := make(chan string, 4)
	saved := reportTetherStopped
	reportTetherStopped = func(reason string) { reported <- reason }
	defer func() { reportTetherStopped = saved }()

	if rc := startTetherProxy("127.0.0.1", freePort(t), "", tunnelAddrsForTest); rc != 0 {
		t.Fatalf("startTetherProxy returned %d, want 0", rc)
	}
	retireTetherProxy(takeCurrentTetherProxy(), "egress leak")

	select {
	case r := <-reported:
		if r != "egress leak" {
			t.Fatalf("reported %q, want %q", r, "egress leak")
		}
	default:
		t.Fatal("a self-retirement was not reported to Android")
	}
	if got := currentTetherStats().Port; got != 0 {
		t.Fatalf("the retired proxy is still installed on port %d", got)
	}
}
