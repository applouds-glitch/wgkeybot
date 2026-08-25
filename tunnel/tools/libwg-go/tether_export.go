/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <stdlib.h>
extern int wgProtectSocketNoBind(int fd);
extern void notifyTetherStopped(const char *reason);
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

// tetherProtectControl is the sharing path's protect hook: VpnService.protect()
// and nothing else.
//
// It exists instead of protectControl because protectControl also binds the
// socket to the cached physical network, which is right for a TURN dial and
// fatally wrong here — see the comment on wgProtectSocketNoBind in jni.c and the
// protect policy at the top of tether_proxy.go.
func tetherProtectControl(network, address string, c syscall.RawConn) error {
	var protectErr error
	if err := c.Control(func(fd uintptr) {
		if C.wgProtectSocketNoBind(C.int(fd)) != 0 {
			protectErr = errSocketNotProtected
		}
	}); err != nil {
		return err
	}
	return protectErr
}

// defaultTetherProtect is injected into new proxies. It lives here rather than
// next to the proxy because it needs cgo and tether_proxy.go is deliberately
// cgo-free.
//
// The host build stubs wgProtectSocketNoBind to always return 0, so the failure
// path is unreachable in tests unless it can be injected.
func defaultTetherProtect(c net.Conn) error {
	sc, ok := c.(syscall.Conn)
	if !ok {
		// If the connection doesn't support SyscallConn, we cannot protect it.
		// Fail closed: an unprotected socket would have replies routed into the
		// tunnel and dropped, hanging the client.
		return errors.New("connection does not support syscall.Conn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		// Same reasoning: if we can't get the raw connection, we can't protect it.
		return err
	}
	return tetherProtectControl("tcp", c.LocalAddr().String(), raw)
}

// tetherPortSpan is how many consecutive ports we try before giving up. A var so
// tests can narrow the range instead of occupying twelve ports.
var tetherPortSpan = 12

var (
	tetherMu      sync.Mutex
	tetherCurrent *tetherProxy
)

// startTetherProxy is the Go half of wgTetherStart; it is kept separate from the
// cgo entry point so the whole start/stop cycle is testable on the host.
//
// tunnelAddrsCsv is the tunnel's own Interface.Address list; without it there is
// nothing to check an upstream socket's local address against, so sharing does
// not start at all rather than start unverified (see tether_guard.go).
func startTetherProxy(bindIP string, port int, dnsCsv, tunnelAddrsCsv string) int32 {
	stopTetherProxy()

	guard, err := newTetherEgressGuard(bindIP, tunnelAddrsCsv)
	if err != nil {
		turnLog("[TETHER] refusing to start: %v", err)
		return -4
	}

	lc := net.ListenConfig{Control: tetherProtectControl}
	var ln net.Listener
	for i := 0; i < tetherPortSpan; i++ {
		ln, err = lc.Listen(context.Background(), "tcp", net.JoinHostPort(bindIP, strconv.Itoa(port+i)))
		if err == nil {
			break
		}
		ln = nil
	}
	if ln == nil {
		turnLog("[TETHER] cannot bind %s ports %d-%d: %v", bindIP, port, port+tetherPortSpan-1, err)
		if errors.Is(err, errSocketNotProtected) {
			return -3
		}
		return -2
	}

	resolver := newCachingLookup(newTunnelResolver(tetherDNSServers(dnsCsv)))
	p := newTetherProxy(ln, newTetherDial(resolver, guard))
	// An unrecoverable Accept error must clear tetherCurrent, not just end the
	// accept loop: otherwise wgTetherStats keeps describing a live session over a
	// proxy that will never serve another client. Same for the guard catching
	// traffic that would have left outside the tunnel. Both retire BY IDENTITY —
	// see retireTetherProxy.
	p.onFatal = func() { retireTetherProxy(p, "accept failed") }
	guard.onLeak = func() { retireTetherProxy(p, "egress leak") }
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	tetherMu.Lock()
	tetherCurrent = p
	tetherMu.Unlock()

	go p.serve(ctx)
	turnLog("[TETHER] sharing proxy listening on %s", ln.Addr())
	return 0
}

// stopTetherProxy retires whatever proxy is installed. This is the deliberate
// teardown: wgTetherStop, and the first thing a fresh start does.
func stopTetherProxy() {
	p := takeTetherProxy(nil)
	if p == nil {
		return
	}
	p.stop()
	turnLog("[TETHER] sharing proxy stopped")
}

// retireTetherProxy is what a proxy's own failure paths call: the accept loop
// giving up, and the egress guard tripping.
//
// It retires BY IDENTITY, and that is not defensive programming. Both callers
// dispatch on a fresh goroutine — neither may block the connection it is serving
// — so a late one can arrive after the user has already switched sharing off and
// back on. Stopping "whatever is current" then tore down the healthy session
// that had replaced the failed one.
//
// It also tells the Android side, which otherwise learns of this only from its
// next stats poll: up to thirty seconds, screen off, of a sheet advertising an
// SSID, a password and a QR for a proxy that will never serve another client.
func retireTetherProxy(p *tetherProxy, reason string) {
	if takeTetherProxy(p) == nil {
		return
	}
	p.stop()
	turnLog("[TETHER] sharing proxy retired itself (%s)", reason)
	reportTetherStopped(reason)
}

// takeTetherProxy clears tetherCurrent and hands back what it held. With only
// non-nil it clears nothing unless that is the proxy installed right now.
func takeTetherProxy(only *tetherProxy) *tetherProxy {
	tetherMu.Lock()
	defer tetherMu.Unlock()
	p := tetherCurrent
	if p == nil || (only != nil && p != only) {
		return nil
	}
	tetherCurrent = nil
	return p
}

// reportTetherStopped hands the reason up to TurnBackend.onTetherStopped so the
// access point comes down with the proxy. A var so the host tests can observe it
// without a JVM.
var reportTetherStopped = func(reason string) {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	C.notifyTetherStopped(cReason)
}

func currentTetherStats() tetherStats {
	tetherMu.Lock()
	p := tetherCurrent
	tetherMu.Unlock()
	if p == nil {
		return tetherStats{}
	}
	return p.stats()
}

//export wgTetherStart
func wgTetherStart(bindIPC *C.char, portC C.int, dnsCsvC, tunnelAddrsC *C.char) int32 {
	return startTetherProxy(C.GoString(bindIPC), int(portC), C.GoString(dnsCsvC), C.GoString(tunnelAddrsC))
}

//export wgTetherStop
func wgTetherStop() {
	stopTetherProxy()
}

// wgTetherStats returns a C string owned by the caller; the jni.c wrapper frees
// it right after NewStringUTF, the same as wgVersion and wgGetConfig.
//
//export wgTetherStats
func wgTetherStats() *C.char {
	b, err := json.Marshal(currentTetherStats())
	if err != nil {
		return C.CString(`{"port":0,"clients":0,"conns":0,"up":0,"down":0}`)
	}
	return C.CString(string(b))
}
