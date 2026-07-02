/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2023 The Pion community <https://pion.ly>
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <stdlib.h>
#include <android/log.h>
extern int wgProtectSocket(int fd);
extern const char* getNetworkDnsServers(long long network_handle);
*/
import "C"

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	srtpwrap "golang.zx2c4.com/wireguard/android/srtpwrap"
)

var turnClientTag = C.CString("WireGuard/TurnClient")

func turnLog(format string, args ...interface{}) {
	l := AndroidLogger{level: C.ANDROID_LOG_INFO, tag: turnClientTag}
	l.Printf(format, args...)
}

func protectControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		C.wgProtectSocket(C.int(fd))
	})
}

// listenUDP binds a UDP socket with SO_REUSEADDR so a quick tunnel restart can
// reclaim 127.0.0.1:9000 while the previous listener is still tearing down
// (its lc.Close() runs async via context.AfterFunc, so a back-to-back reconnect
// can otherwise race the close and fail with "bind: address already in use").
func listenUDP(addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var setErr error
			if err := c.Control(func(fd uintptr) {
				setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return setErr
		},
	}
	return lc.ListenPacket(context.Background(), "udp", addr)
}

func init() {
	os.Setenv("GODEBUG", "netdns=go")
}

// clearTransientState resets DNS cache and HTTP connections without touching
// credential caches. Called on every tunnel start so stale DNS/sockets are
// flushed, but credentials earned in a prior session are reused if still valid.
func clearTransientState() {
	ClearCache()
	turnHTTPClient.CloseIdleConnections()
	turnLog("[PROXY] Transient state cleared (DNS + HTTP; creds preserved)")
}

//export wgNotifyNetworkChange
func wgNotifyNetworkChange() {
	ClearCache()
	turnHTTPClient.CloseIdleConnections()
	turnLog("[NETWORK] Network change: DNS cache + HTTP connections reset (creds preserved)")
}

var turnHTTPClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: protectControl,
		}).DialContext,
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// stream — single TURN connection
// ─────────────────────────────────────────────────────────────────────────────

type stream struct {
	ctx context.Context // set to the global tunnel context

	id  int
	in  chan []byte
	out net.PacketConn

	peer   atomic.Pointer[net.Addr]
	ready  atomic.Bool
	okFunc func() // called once when stream becomes ready

	sessionID       []byte
	cert            *tls.Certificate
	watchdogTimeout int

	// wrapKey is an optional 32-byte ChaCha20 key for WRAP obfuscation.
	// When non-nil, raw UDP packets to/from the TURN relay are encrypted with
	// wrapPacket / unwrapPacket before any DTLS processing.
	// nil = WRAP disabled (plain mode).
	wrapKey []byte
}

// stunBindingIndication is a minimal STUN Binding Indication (RFC 5389, 20 bytes).
// Sent periodically to keep TURN relay allocations and NAT mappings alive.
// Peers that don't handle STUN will safely drop it.
var stunBindingIndication = []byte{
	0x00, 0x11, // type: Binding Indication
	0x00, 0x00, // message length: 0 attributes
	0x21, 0x12, 0xA4, 0x42, // magic cookie
	0x00, 0x00, 0x00, 0x00, // transaction ID (12 bytes, all zero)
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// isStunKeepalive reports whether b is a 20-byte STUN message with the magic
// cookie at offset 4 — i.e. the server's echoed keepalive. These are used
// purely as a relay-liveness signal and must not be forwarded to WireGuard.
func isStunKeepalive(b []byte) bool {
	return len(b) == 20 && b[4] == 0x21 && b[5] == 0x12 && b[6] == 0xA4 && b[7] == 0x42
}

const iPacketBuffMaxSize = 2048

// Keepalive cadence. A single per-stream goroutine (runKeepalive) sends the STUN
// Binding Indication AND runs dead-stream detection, replacing the former triad
// of a 25s Indication ticker + a 10s TURN Binding Request probe + an optional
// watchdog. The send interval and the dead-stream threshold adapt to app state
// (see globalIdleFlag):
//
//	active — foreground / screen on: fast keepalive so a broken stream is
//	         detected and rebuilt within ~35s.
//	idle   — screen off / Doze: keepalive relaxes to the NAT-hold floor and the
//	         detector widens to ~90s, cutting per-stream radio wakeups ~2.5×.
//
// The NAT-hold floor (25s) is the hard ceiling: carrier CGNAT UDP mappings
// commonly expire in 30-60s, so an idle keepalive must not exceed ~25-30s or the
// relay path silently dies. WireGuard's own PersistentKeepalive=25 holds the far
// leg in lock-step. Liveness is proved only by a real packet FROM the peer (WG
// data or the server's echo of our Indication) landing in the RX goroutine and
// bumping lastRx — a successful send proves nothing (a dead TURN allocation still
// accepts WriteTo, since SEND indications are fire-and-forget).
const (
	kaActiveInterval = 10 * time.Second
	kaActiveDead     = 35 * time.Second
	kaIdleInterval   = 25 * time.Second
	kaIdleDead       = 90 * time.Second
)

// keepaliveCadence returns the current keepalive send interval and dead-stream
// detection threshold for the active/idle mode (see globalIdleFlag).
func keepaliveCadence() (interval, dead time.Duration) {
	if atomic.LoadInt32(&globalIdleFlag) != 0 {
		return kaIdleInterval, kaIdleDead
	}
	return kaActiveInterval, kaActiveDead
}

// alignedSleep blocks until the next multiple of interval on a global wall-clock
// grid (shared by every stream), then reports true; it reports false if ctx is
// cancelled first. Because all streams align to the same grid with the same
// interval, their keepalives fire in one coalesced burst — the radio wakes once
// per interval instead of once per stream — with no cross-stream coordination.
func alignedSleep(ctx context.Context, interval time.Duration) bool {
	next := time.Now().Truncate(interval).Add(interval)
	t := time.NewTimer(time.Until(next))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// freezeSlack is how far past the requested interval a runKeepalive sleep may run
// before it is treated as a host freeze (iOS extension suspend, aggressive Doze)
// rather than a dead path. On a detected freeze the liveness clock is reset and
// the stream is NOT torn down — otherwise every stream would tear down on thaw
// and mass-reconnect on one credential, tripping the TURN 486 quota → captcha.
const freezeSlack = 20 * time.Second

// runKeepalive is the single per-stream keepalive + liveness loop shared by all
// three transports. Each iteration sleeps on the shared aligned grid (coalesced
// across streams), tears the stream down when no real packet has arrived within
// the current dead-stream threshold (so WorkerGroup rebuilds it), then emits one
// keepalive via send. send receives the tick counter (used by NoDTLS to pace
// cover traffic) and returns any transport write error (logged, non-fatal — only
// a stale lastRx tears the stream down). Returns when ctx is cancelled or the
// dead-stream detector fires.
func (s *stream) runKeepalive(ctx context.Context, lastRx *atomic.Int64, reportErr func(error), send func(tick int) error) {
	for tick := 0; ; tick++ {
		interval, dead := keepaliveCadence()
		before := time.Now()
		if !alignedSleep(ctx, interval) {
			return
		}
		if slept := time.Since(before); slept > interval+freezeSlack {
			// The host froze us (iOS extension suspend / deep Doze): lastRx is
			// stale through no fault of the path. Reset the clock and re-stimulate
			// the path instead of tearing the stream down on thaw.
			turnLog("[STREAM %d] keepalive: slept %v (freeze) — resetting liveness clock", s.id, slept.Round(time.Second))
			lastRx.Store(time.Now().Unix())
			if err := send(tick); err != nil {
				turnLog("[STREAM %d] keepalive send error: %v", s.id, err)
			}
			continue
		}
		if time.Since(time.Unix(lastRx.Load(), 0)) > dead {
			turnLog("[STREAM %d] dead-stream detector: no RX for >%v — closing", s.id, dead)
			reportErr(fmt.Errorf("dead-stream: no RX for >%v", dead))
			return
		}
		if err := send(tick); err != nil {
			turnLog("[STREAM %d] keepalive send error: %v", s.id, err)
		}
	}
}

// sendSessionHSBurst sends the 17-byte session header burstCount times
// with burstGap between sends. The redundancy survives UDP loss and gives
// the server multiple chances to receive the header before the first WG
// packet arrives — without it, a single race or drop costs a full 5s WG
// handshake retry (and with 3 hashes commonly compounds to ~15s).
func (s *stream) sendSessionHSBurst(relayConn net.PacketConn, peer net.Addr, sessionHS []byte, hasWrap bool) error {
	const burstCount = 3
	const burstGap = 50 * time.Millisecond
	for i := 0; i < burstCount; i++ {
		var payload []byte
		if hasWrap {
			enc, err := wrapPacket(s.wrapKey, sessionHS)
			if err != nil {
				return fmt.Errorf("session handshake wrap #%d: %w", i+1, err)
			}
			payload = enc
		} else {
			payload = sessionHS
		}
		if _, err := relayConn.WriteTo(payload, peer); err != nil {
			return fmt.Errorf("session handshake send #%d: %w", i+1, err)
		}
		if i < burstCount-1 {
			time.Sleep(burstGap)
		}
	}
	return nil
}

var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, iPacketBuffMaxSize)
	},
}

// Metrics
var (
	dtlsTxDropCount    atomic.Uint64
	dtlsRxErrorCount   atomic.Uint64
	relayTxErrorCount  atomic.Uint64
	relayRxErrorCount  atomic.Uint64
	noDtlsTxDropCount  atomic.Uint64
	noDtlsRxErrorCount atomic.Uint64
)

// ─────────────────────────────────────────────────────────────────────────────
// runNoDTLS — direct relay, no DTLS
// ─────────────────────────────────────────────────────────────────────────────

func (s *stream) runNoDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()

	// firstErr captures the root cause when a goroutine fails and calls sCancel().
	// See runDTLS for full rationale.
	firstErr := make(chan error, 1)
	reportErr := func(err error) {
		select {
		case firstErr <- err:
		default:
		}
	}

	hasWrap := s.wrapKey != nil
	turnLog("[STREAM %d] NoDTLS mode (wrap=%v) — %s", s.id, hasWrap, peer)

	// Session handshake: 17-byte header (sessionID + streamID). Kept in
	// sessionHS so the keepalive goroutine can re-announce it periodically.
	// Sent in a small burst so a single UDP drop or server-side scheduling
	// race doesn't push the first WG packet ahead of the registered stream.
	var sessionHS []byte
	if s.sessionID != nil {
		sessionHS = make([]byte, 17)
		copy(sessionHS[:16], s.sessionID)
		sessionHS[16] = byte(s.id)
		if hErr := s.sendSessionHSBurst(relayConn, peer, sessionHS, hasWrap); hErr != nil {
			return hErr
		}
		turnLog("[STREAM %d] Session handshake burst sent", s.id)
	}

	// Cancelling sCtx (watchdog, error, parent stop) closes the relay conn so
	// the RX goroutine's blocking ReadFrom unblocks immediately instead of
	// waiting out its 60s deadline.
	context.AfterFunc(sCtx, func() { relayConn.Close() })

	// lastRx tracks the last sign of life on the relay path — only a real
	// packet from the peer (WG data or the server's keepalive echo) counts and
	// bumps it in the RX goroutine. A keepalive *send* must never refresh it: a
	// dead TURN allocation still accepts WriteTo (SEND indications are
	// fire-and-forget), so "sent OK" proves nothing. runKeepalive tears the
	// stream down once lastRx goes stale past the current dead-stream threshold.
	var lastRx atomic.Int64
	lastRx.Store(time.Now().Unix())

	var wg sync.WaitGroup
	wg.Add(3)

	// TX: WireGuard → relay
	go func() {
		defer wg.Done()
		defer sCancel()
		for {
			select {
			case <-sCtx.Done():
				return
			case b := <-s.in:
				var payload []byte
				if hasWrap {
					var err error
					payload, err = wrapPacket(s.wrapKey, b)
					if err != nil {
						packetPool.Put(b[:cap(b)])
						noDtlsTxDropCount.Add(1)
						turnLog("[STREAM %d] WRAP TX error: %v", s.id, err)
						reportErr(fmt.Errorf("WRAP TX: %w", err))
						return
					}
				} else {
					payload = b
				}
				_, err := relayConn.WriteTo(payload, peer)
				packetPool.Put(b[:cap(b)])
				if err != nil {
					noDtlsTxDropCount.Add(1)
					turnLog("[STREAM %d] TX error: %v", s.id, err)
					reportErr(fmt.Errorf("relay TX: %w", err))
					return
				}
			}
		}
	}()

	// RX: relay → WireGuard
	go func() {
		defer wg.Done()
		defer sCancel()
		wire := make([]byte, iPacketBuffMaxSize)
		plain := make([]byte, iPacketBuffMaxSize)
		for {
			n, from, err := relayConn.ReadFrom(wire)
			if err != nil {
				noDtlsRxErrorCount.Add(1)
				reportErr(fmt.Errorf("relay RX: %w", err))
				return
			}
			if from.String() != peer.String() {
				continue
			}
			// A real packet from the peer is the only proof the relay path is
			// alive — record it so runKeepalive's dead-stream detector holds off.
			// Covers both WG data and the server's STUN-keepalive echo.
			lastRx.Store(time.Now().Unix())
			a := s.peer.Load()
			if a == nil {
				continue
			}
			if hasWrap {
				m, unwrapErr := unwrapPacket(s.wrapKey, wire[:n], plain)
				if unwrapErr != nil {
					turnLog("[STREAM %d] WRAP RX skip: %v", s.id, unwrapErr)
					continue
				}
				if m == 0 {
					continue
				}
				if isStunKeepalive(plain[:m]) {
					continue // liveness already recorded; don't feed it to WG
				}
				if _, err := s.out.WriteTo(plain[:m], *a); err != nil {
					noDtlsRxErrorCount.Add(1)
					reportErr(fmt.Errorf("TUN write: %w", err))
					return
				}
			} else {
				if isStunKeepalive(wire[:n]) {
					continue // liveness already recorded; don't feed it to WG
				}
				if _, err := s.out.WriteTo(wire[:n], *a); err != nil {
					noDtlsRxErrorCount.Add(1)
					reportErr(fmt.Errorf("TUN write: %w", err))
					return
				}
			}
		}
	}()

	// Keepalive + cover traffic + dead-stream detection (one coalesced,
	// app-state-adaptive loop; see runKeepalive). Sends the STUN Indication
	// (liveness stimulus + NAT hold), paces WRAP cover traffic every 3rd tick,
	// and re-announces the 17-byte session header so a restarted server re-adopts
	// this stream within one tick without a reconnect. A send never refreshes
	// lastRx — only the server's echo (in the RX goroutine) proves the path.
	go func() {
		defer wg.Done()
		defer sCancel()
		s.runKeepalive(sCtx, &lastRx, reportErr, func(tick int) error {
			var sendErr error
			if hasWrap {
				if enc, err := wrapPacket(s.wrapKey, stunBindingIndication); err == nil {
					_, sendErr = relayConn.WriteTo(enc, peer)
				} else {
					sendErr = err
				}
				if tick%3 == 0 {
					if cover, cErr := wrapCoverPacket(s.wrapKey); cErr == nil {
						relayConn.WriteTo(cover, peer)
					}
				}
			} else {
				_, sendErr = relayConn.WriteTo(stunBindingIndication, peer)
			}
			if sessionHS != nil {
				if hasWrap {
					if enc, wErr := wrapPacket(s.wrapKey, sessionHS); wErr == nil {
						relayConn.WriteTo(enc, peer)
					}
				} else {
					relayConn.WriteTo(sessionHS, peer)
				}
			}
			return sendErr
		})
	}()

	// Give the server a moment to process the session handshake before
	// we mark the stream as ready. Reduced from 300ms because the burst
	// above already gives the server 3 chances spread across ~100ms; only
	// a short tail wait is needed for the last burst packet to land.
	time.Sleep(200 * time.Millisecond)

	s.ready.Store(true)
	s.okFunc()
	wg.Wait()
	select {
	case err := <-firstErr:
		return err
	default:
		return nil
	}
}
func (s *stream) runDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, sendHandshake bool) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()

	// firstErr captures the root cause when a goroutine fails and calls sCancel().
	// Without this, any internal failure (watchdog, RX error, TX error) would
	// return nil, which WorkerGroup misinterprets as "server closed stream,
	// rotate credentials" — causing an infinite stream creation/destruction loop
	// when DPI blocks traffic through an otherwise healthy DTLS tunnel.
	firstErr := make(chan error, 1)
	reportErr := func(err error) {
		select {
		case firstErr <- err:
		default:
		}
	}

	c1, c2 := connutil.AsyncPacketPipe()
	defer c1.Close()
	defer c2.Close()

	dtlsConn, err := dtls.Client(c1, peer, &dtls.Config{
		Certificates:         []tls.Certificate{*s.cert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		// Connection ID lets the DTLS session survive a client-side NAT
		// rebind (mobile network switch, NAT timeout) without a fresh
		// handshake. The server negotiates CID too; if a peer doesn't,
		// pion silently falls back to no-CID.
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	})
	if err != nil {
		return fmt.Errorf("DTLS client creation failed: %w", err)
	}
	defer dtlsConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	context.AfterFunc(sCtx, func() {
		relayConn.Close()
		c1.Close()
	})

	// Dead-stream detection lives in runKeepalive below: it watches lastRx (bumped
	// by the DTLS→WireGuard RX goroutine on every decrypted packet, including the
	// server's keepalive echo) and, when it goes stale, cancels sCtx — which the
	// AfterFunc above turns into relayConn.Close(), unblocking this relay RX.

	// ── Pipe → Relay (TX) ────────────────────────────────────────────────────
	// When WRAP is enabled, each outgoing DTLS record is encrypted with
	// wrapPacket before being sent to the relay over UDP.
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, _, err := c2.ReadFrom(buf)
			if err != nil {
				return
			}

			var payload []byte
			if s.wrapKey != nil {
				payload, err = wrapPacket(s.wrapKey, buf[:n])
				if err != nil {
					turnLog("[STREAM %d] WRAP TX error: %v", s.id, err)
					relayTxErrorCount.Add(1)
					reportErr(fmt.Errorf("WRAP TX: %w", err))
					return
				}
			} else {
				payload = buf[:n]
			}

			if _, err := relayConn.WriteTo(payload, peer); err != nil {
				relayTxErrorCount.Add(1)
				turnLog("[STREAM %d] relay TX error: %v", s.id, err)
				reportErr(fmt.Errorf("relay TX: %w", err))
				return
			}
		}
	}()

	// ── Relay → Pipe (RX) ────────────────────────────────────────────────────
	// When WRAP is enabled, incoming UDP datagrams are decrypted with
	// unwrapPacket before being fed into the DTLS pipe.
	go func() {
		defer wg.Done()
		defer sCancel()
		wire := make([]byte, iPacketBuffMaxSize)
		plain := make([]byte, iPacketBuffMaxSize)
		for {
			n, from, err := relayConn.ReadFrom(wire)
			if err != nil {
				relayRxErrorCount.Add(1)
				turnLog("[STREAM %d] relay RX error: %v", s.id, err)
				reportErr(fmt.Errorf("relay RX: %w", err))
				return
			}
			if from.String() == peer.String() {
				var data []byte
				if s.wrapKey != nil {
					m, unwrapErr := unwrapPacket(s.wrapKey, wire[:n], plain)
					if unwrapErr != nil {
						// Corrupted or unrecognised packet — skip silently.
						turnLog("[STREAM %d] WRAP RX skip: %v", s.id, unwrapErr)
						continue
					}
					data = plain[:m]
				} else {
					data = wire[:n]
				}
				if _, err := c2.WriteTo(data, peer); err != nil {
					relayTxErrorCount.Add(1)
					reportErr(fmt.Errorf("pipe write: %w", err))
					return
				}
			}
		}
	}()

	turnLog("[STREAM %d] DTLS handshake...", s.id)
	dtlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := dtlsConn.HandshakeContext(sCtx); err != nil {
		return fmt.Errorf("DTLS handshake failed: %w", err)
	}
	dtlsConn.SetDeadline(time.Time{})
	turnLog("[STREAM %d] DTLS handshake OK", s.id)

	// Session + stream ID handshake (proxy_v2 only). Sent as a small burst
	// for the same reason as runNoDTLS — even though DTLS is ordered, the
	// server's handleConn does the session-ID parse on the first record only,
	// so a missed/delayed first record can stall the stream. Duplicates after
	// the first are skipped server-side (17-byte filter).
	if sendHandshake {
		dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 17)
		copy(buf[:16], s.sessionID)
		buf[16] = byte(s.id)
		const burstCount = 3
		const burstGap = 50 * time.Millisecond
		for i := 0; i < burstCount; i++ {
			if _, err := dtlsConn.Write(buf); err != nil {
				return fmt.Errorf("session handshake send #%d: %w", i+1, err)
			}
			if i < burstCount-1 {
				time.Sleep(burstGap)
			}
		}
		dtlsConn.SetWriteDeadline(time.Time{})
	}

	s.ready.Store(true)
	s.okFunc()

	var lastRx atomic.Int64
	lastRx.Store(time.Now().Unix())

	wg.Add(3)

	// WireGuard → DTLS (TX)
	go func() {
		defer wg.Done()
		defer sCancel()
		for {
			select {
			case <-sCtx.Done():
				return
			case b := <-s.in:
				_, err := dtlsConn.Write(b)
				packetPool.Put(b[:cap(b)])
				if err != nil {
					dtlsTxDropCount.Add(1)
					reportErr(fmt.Errorf("DTLS write: %w", err))
					return
				}
			}
		}
	}()

	// DTLS → WireGuard (RX)
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, err := dtlsConn.Read(buf)
			if err != nil {
				dtlsRxErrorCount.Add(1)
				reportErr(fmt.Errorf("DTLS read: %w", err))
				return
			}
			lastRx.Store(time.Now().Unix())
			if isStunKeepalive(buf[:n]) {
				continue // keepalive echo: liveness recorded, don't feed it to WG
			}
			if a := s.peer.Load(); a != nil {
				if _, err := s.out.WriteTo(buf[:n], *a); err != nil {
					dtlsRxErrorCount.Add(1)
					reportErr(fmt.Errorf("TUN write: %w", err))
					return
				}
			}
		}
	}()

	// Keepalive + dead-stream detection (one coalesced, app-state-adaptive loop;
	// see runKeepalive). The STUN Indication goes via dtlsConn.Write so the server
	// receives a valid DTLS ApplicationData record (refreshing its 5-min read
	// deadline) and echoes the 20 bytes straight back through this stream; the
	// echo bumps lastRx in the DTLS→WireGuard RX goroutine — the only proof of a
	// live path (a dead allocation still accepts the write). runKeepalive tears
	// the stream down when lastRx goes stale past the current dead-stream
	// threshold, replacing the former 10s TURN Binding Request probe and watchdog.
	go func() {
		defer wg.Done()
		defer sCancel()
		s.runKeepalive(sCtx, &lastRx, reportErr, func(int) error {
			_, err := dtlsConn.Write(stunBindingIndication)
			return err
		})
	}()

	wg.Wait()
	select {
	case err := <-firstErr:
		return err
	default:
		return nil
	}
}

// runSRTP — DTLS-SRTP transport (peer-type "srtp", VP8-mimic).
//
// Structurally a sibling of runDTLS, but the relay TX/RX + DTLS pipework is
// owned by srtpwrap.Client: it terminates a DTLS-SRTP session over the TURN
// relay and returns a net.Conn where each Write frames one payload as an
// RTP+SRTP packet (PayloadType 100 — looks like VP8 WebRTC video to VK's
// content classifier) and each Read returns one decrypted payload. WRAP is
// not used here — SRTP already encrypts. The session/stream multiplexing
// model is preserved exactly: the 17-byte session header is sent first, so
// the server aggregates this stream's sibling SRTP sessions onto one
// WireGuard backend conn.
func (s *stream) runSRTP(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()

	// firstErr captures the root cause when a goroutine fails and calls sCancel().
	// See runDTLS for the full rationale (nil return would be misread by
	// WorkerGroup as "server closed stream, rotate credentials").
	firstErr := make(chan error, 1)
	reportErr := func(err error) {
		select {
		case firstErr <- err:
		default:
		}
	}

	// srtpwrap.Client owns the relayConn read loop internally; closing the
	// relay on ctx cancel unblocks it so the session tears down cleanly.
	context.AfterFunc(sCtx, func() { relayConn.Close() })

	turnLog("[STREAM %d] SRTP handshake...", s.id)
	hsCtx, hsCancel := context.WithTimeout(sCtx, 30*time.Second)
	srtpConn, err := srtpwrap.Client(hsCtx, relayConn, peer)
	hsCancel()
	if err != nil {
		return fmt.Errorf("SRTP handshake failed: %w", err)
	}
	defer srtpConn.Close()
	context.AfterFunc(sCtx, func() { srtpConn.Close() })
	turnLog("[STREAM %d] SRTP handshake OK", s.id)

	// Session + stream ID handshake (proxy_v2 model). Sent as a small burst
	// for the same reason as runDTLS — the server parses the session ID on the
	// first payload; duplicates after the first are skipped server-side
	// (17-byte filter).
	{
		srtpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 17)
		copy(buf[:16], s.sessionID)
		buf[16] = byte(s.id)
		const burstCount = 3
		const burstGap = 50 * time.Millisecond
		for i := 0; i < burstCount; i++ {
			if _, err := srtpConn.Write(buf); err != nil {
				return fmt.Errorf("session handshake send #%d: %w", i+1, err)
			}
			if i < burstCount-1 {
				time.Sleep(burstGap)
			}
		}
		srtpConn.SetWriteDeadline(time.Time{})
	}

	s.ready.Store(true)
	s.okFunc()

	var lastRx atomic.Int64
	lastRx.Store(time.Now().Unix())

	var wg sync.WaitGroup
	wg.Add(3)

	// WireGuard → SRTP (TX)
	go func() {
		defer wg.Done()
		defer sCancel()
		for {
			select {
			case <-sCtx.Done():
				return
			case b := <-s.in:
				srtpConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				_, err := srtpConn.Write(b)
				packetPool.Put(b[:cap(b)])
				if err != nil {
					dtlsTxDropCount.Add(1)
					reportErr(fmt.Errorf("SRTP write: %w", err))
					return
				}
			}
		}
	}()

	// SRTP → WireGuard (RX)
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, err := srtpConn.Read(buf)
			if err != nil {
				dtlsRxErrorCount.Add(1)
				reportErr(fmt.Errorf("SRTP read: %w", err))
				return
			}
			lastRx.Store(time.Now().Unix())
			if isStunKeepalive(buf[:n]) {
				continue // keepalive echo: liveness recorded, don't feed it to WG
			}
			if a := s.peer.Load(); a != nil {
				if _, err := s.out.WriteTo(buf[:n], *a); err != nil {
					dtlsRxErrorCount.Add(1)
					reportErr(fmt.Errorf("TUN write: %w", err))
					return
				}
			}
		}
	}()

	// Keepalive + dead-stream detection (one coalesced, app-state-adaptive loop;
	// see runKeepalive). The STUN Indication goes through the SRTP pipe; the
	// server echoes it back through this stream and the echo bumps lastRx in the
	// SRTP→WireGuard RX goroutine — the only proof of a live path. runKeepalive
	// tears the stream down when lastRx goes stale, replacing the former 10s TURN
	// Binding Request probe and watchdog. (srtpwrap owns the relay read loop, so
	// this per-stream detector is the only dead-path signal SRTP has.)
	go func() {
		defer wg.Done()
		defer sCancel()
		s.runKeepalive(sCtx, &lastRx, reportErr, func(int) error {
			_, err := srtpConn.Write(stunBindingIndication)
			return err
		})
	}()

	wg.Wait()
	select {
	case err := <-firstErr:
		return err
	default:
		return nil
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Global state
// ─────────────────────────────────────────────────────────────────────────────

var currentTurnCancel context.CancelFunc
var currentTurnDone <-chan struct{}
var turnMutex sync.Mutex
var globalGetCreds getCredsFunc

// globalPauseFlag is set to 1 by Android when the device enters Doze mode.
// WorkerGroup checks this atomically and suspends credential rotation while set.
var globalPauseFlag int32

//export wgSetPauseFlag
func wgSetPauseFlag(flag C.int) {
	atomic.StoreInt32(&globalPauseFlag, int32(flag))
	turnLog("[PROXY] PauseFlag=%d", flag)
}

// globalIdleFlag is set to 1 by the host app when the device/screen goes idle
// (Android: screen off / Doze). While set, per-stream keepalives relax to the
// NAT-hold floor (kaIdleInterval) and the dead-stream detector widens
// (kaIdleDead) to save radio wakeups without dropping the tunnel — see
// keepaliveCadence. Hosts that never call this (iOS/Windows) stay in the fast
// active cadence, which is the safe default.
var globalIdleFlag int32

//export wgSetIdleMode
func wgSetIdleMode(idle C.int) {
	atomic.StoreInt32(&globalIdleFlag, int32(idle))
	turnLog("[PROXY] IdleMode=%d", idle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Link parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

func parseLinks(raw string, maxLinks int) []string {
	raw = strings.ReplaceAll(raw, "|", ",")
	var links []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			links = append(links, p)
		}
	}
	if len(links) == 0 {
		return []string{""}
	}
	if len(links) > maxLinks {
		links = links[:maxLinks]
	}
	return links
}

// ─────────────────────────────────────────────────────────────────────────────
// wgTurnProxyStart / wgTurnProxyStop
// ─────────────────────────────────────────────────────────────────────────────

//export wgTurnProxyStart
func wgTurnProxyStart(peerAddrC *C.char, vklinkC *C.char, modeC *C.char, n C.int, udp C.int, listenAddrC *C.char, turnIpC *C.char, turnPortC C.int, peerTypeC *C.char, streamsPerCredC C.int, watchdogTimeoutC C.int, wrapKeyC *C.char, networkHandleC C.longlong) int32 {
	clearTransientState()                  // flush DNS + HTTP without clearing credential caches
	atomic.StoreInt32(&globalPauseFlag, 0) // reset on each new tunnel start
	atomic.StoreInt32(&globalIdleFlag, 0)  // start in fast/active keepalive cadence
	globalCaptchaLockout.Store(0)          // reset captcha lockout on fresh start

	if networkHandleC != 0 {
		if dnsStr := C.getNetworkDnsServers(C.longlong(networkHandleC)); dnsStr != nil {
			dnsGo := C.GoString(dnsStr)
			C.free(unsafe.Pointer(dnsStr))
			InitSystemDns(strings.Split(dnsGo, ","))
		}
	}

	peerAddr := C.GoString(peerAddrC)
	vklink := C.GoString(vklinkC)
	mode := C.GoString(modeC)
	listenAddr := C.GoString(listenAddrC)
	turnIp := C.GoString(turnIpC)
	turnPort := int(turnPortC)
	peerType := C.GoString(peerTypeC)
	streamsPerCred = int(streamsPerCredC)
	watchdogTimeout := int(watchdogTimeoutC)

	// ── WRAP key parsing ──────────────────────────────────────────────────────
	var wrapKey []byte
	if wrapKeyStr := C.GoString(wrapKeyC); wrapKeyStr != "" {
		decoded, err := decodeWrapKey(true, wrapKeyStr)
		if err != nil {
			turnLog("[PROXY] Invalid wrapKey: %v", err)
			return -1
		}
		wrapKey = decoded
		turnLog("[PROXY] WRAP obfuscation enabled")
	}

	turnMutex.Lock()
	if currentTurnCancel != nil {
		currentTurnCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	currentTurnCancel = cancel
	turnMutex.Unlock()

	// ── Credential mode setup ─────────────────────────────────────────────────
	turnLog("[PROXY] VK Link credential mode")
	rawLinks := parseLinks(vklink, 8)
	links := make([]string, len(rawLinks))
	for i, raw := range rawLinks {
		parts := strings.Split(raw, "join/")
		lk := parts[len(parts)-1]
		if idx := strings.IndexAny(lk, "/?#"); idx != -1 {
			lk = lk[:idx]
		}
		links[i] = lk
	}
	globalGetCreds = func(ctx context.Context, lk string, streamID int) (string, string, []string, error) {
		return getCredsCached(ctx, lk, streamID, fetchVkCreds)
	}

	// ── Apply StreamNum cap / expand ─────────────────────────────────────────
	// StreamNum (n) constrains total streams.
	//   • n < defaultTotal: reduce streamsPerCred so total matches n.
	//   • n > defaultTotal: add extra groups by cycling links, so total = n.
	// streamsPerCred must stay in sync because credential cache slots are keyed
	// by streamID/streamsPerCred (credentials.go:getCacheID).
	if maxTotal := int(n); maxTotal > 0 {
		defaultTotal := len(links) * streamsPerCred
		if maxTotal < defaultTotal {
			perGroup := maxTotal / len(links)
			if perGroup < 1 {
				perGroup = 1
			}
			streamsPerCred = perGroup
		} else if maxTotal > defaultTotal {
			numGroups := (maxTotal + streamsPerCred - 1) / streamsPerCred
			origLinks := links
			links = make([]string, numGroups)
			for i := range links {
				links[i] = origLinks[i%len(origLinks)]
			}
		}
	}

	totalStreams := len(links) * streamsPerCred
	turnLog("[PROXY] Starting: listen=%s StreamNum=%d streamsPerGroup=%d links=%d actualTotal=%d mode=%s peerType=%s watchdog=%ds",
		listenAddr, int(n), streamsPerCred, len(links), totalStreams, mode, peerType, watchdogTimeout)
	turnLog("[PROXY] Identities (%d): %v", len(links), links)

	// ── DNS resolution ────────────────────────────────────────────────────────
	peer, err := resolvePeer(peerAddr)
	if err != nil {
		turnLog("[PROXY] Cannot resolve peer %s: %v", peerAddr, err)
		return -1
	}

	// ── Local listener ────────────────────────────────────────────────────────
	lc, err := listenUDP(listenAddr)
	if err != nil {
		turnLog("[PROXY] ListenPacket failed: %v", err)
		return -1
	}
	context.AfterFunc(ctx, func() { lc.Close() })

	sessionID, _ := uuid.New().MarshalBinary()
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		turnLog("[PROXY] DTLS cert generation failed: %v", err)
		return -1
	}

	var packetLc net.PacketConn = lc

	// ── Pre-fetch credentials for all groups ─────────────────────────────────
	// Done before VPN tunnel is established so any captcha WebView runs over
	// the physical network. vkSemaphore(2) allows pairs of groups to fetch in
	// parallel. WorkerGroups will get cache hits on their first cycle and start
	// streams immediately without waiting for another VK round-trip.
	turnLog("[PROXY] Pre-fetching credentials for %d group(s)...", len(links))
	var prefetchWg sync.WaitGroup
	var callRequiresAuth int32 // set to 1 if any group gets error_code 9005
	var prefetchOk int32       // set to 1 if any group succeeds
	var prefetchLockout int32  // set to 1 if any group hits the global lockout
	for i, lk := range links {
		prefetchWg.Add(1)
		go func(groupID int, link string) {
			defer prefetchWg.Done()
			select {
			case vkSemaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			_, _, _, prefetchErr := fetchCreds(ctx, link, groupID)
			<-vkSemaphore
			if prefetchErr != nil {
				if ctx.Err() == nil {
					if strings.Contains(prefetchErr.Error(), "CALL_REQUIRES_AUTH") {
						atomic.StoreInt32(&callRequiresAuth, 1)
						turnLog("[PROXY] Pre-fetch group %d: CALL_REQUIRES_AUTH — aborting", groupID)
					} else {
						turnLog("[PROXY] Pre-fetch group %d failed: %v (WorkerGroup will retry)", groupID, prefetchErr)
						if strings.Contains(prefetchErr.Error(), "CAPTCHA_WAIT_REQUIRED") {
							atomic.StoreInt32(&prefetchLockout, 1)
						}
					}
				}
			} else {
				atomic.StoreInt32(&prefetchOk, 1)
				turnLog("[PROXY] Pre-fetch group %d OK", groupID)
			}
		}(i, lk)
	}
	prefetchWg.Wait()
	if atomic.LoadInt32(&callRequiresAuth) == 1 {
		cancel()
		return -2
	}
	if atomic.LoadInt32(&prefetchOk) == 0 && atomic.LoadInt32(&prefetchLockout) == 1 {
		turnLog("[PROXY] All pre-fetches failed due to CAPTCHA_WAIT_REQUIRED — aborting startup")
		cancel()
		return -3 // distinct code: captcha lockout — caller must not retry other stream counts
	}

	// ── Launch groups ─────────────────────────────────────────────────────────
	_, okChan, done, err := StartTunnelGroups(ctx, packetLc, TunnelGroupsConfig{
		Links:           links,
		PeerAddr:        peer,
		PeerType:        peerType,
		UseUDP:          udp != 0,
		TurnIP:          turnIp,
		TurnPort:        turnPort,
		StreamsPerGroup: streamsPerCred,
		Cert:            &cert,
		SessionID:       sessionID,
		WatchdogTimeout: watchdogTimeout,
		PauseFlag:       &globalPauseFlag,
		WrapKey:         wrapKey,
	})
	if err != nil {
		turnLog("[PROXY] StartTunnelGroups failed: %v", err)
		cancel()
		return -1
	}
	// Publish the done channel so wgTurnProxyStop can wait for every group (and
	// thus every relayConn.Close() / allocation-delete) to drain.
	turnMutex.Lock()
	currentTurnDone = done
	turnMutex.Unlock()

	// Startup timeout: if no stream completes its DTLS handshake within this
	// window, the server is unreachable or DTLS is being blocked. Bail out so
	// the UI can surface a "failed to connect" state instead of spinning forever.
	// 30s matches the inner DTLS handshake deadline — one attempt is enough to
	// tell whether the path works; further worker retries are wasted at startup.
	const startupTimeout = 30 * time.Second
	select {
	case <-okChan:
		turnLog("[PROXY] First stream ready — tunnel is up")
		return 0
	case <-ctx.Done():
		turnLog("[PROXY] Startup cancelled")
		return -1
	case <-time.After(startupTimeout):
		turnLog("[PROXY] Startup timeout — no DTLS handshake within %v", startupTimeout)
		cancel()
		return -1
	}
}

// allocationDrainTimeout bounds how long wgTurnProxyStop waits for worker
// goroutines to unwind (and flush their TURN allocation-delete packets).
const allocationDrainTimeout = 3 * time.Second

//export wgTurnProxyStop
func wgTurnProxyStop() {
	turnMutex.Lock()
	cancel := currentTurnCancel
	done := currentTurnDone
	currentTurnCancel = nil
	currentTurnDone = nil
	turnMutex.Unlock()

	if cancel != nil {
		turnLog("[PROXY] Stopping TURN proxy")
		cancel()
		// Wait (bounded) for worker goroutines to unwind so each stream's
		// relayConn.Close() runs and sends TURN Refresh(lifetime=0) — this frees
		// the server-side allocation now instead of letting it linger until its
		// lifetime expires (which would otherwise eat the per-credential quota
		// on a quick reconnect).
		if done != nil {
			select {
			case <-done:
			case <-time.After(allocationDrainTimeout):
				turnLog("[PROXY] Stop: allocation drain timed out")
			}
		}
	}
	// Credential caches are intentionally preserved across stops so an immediate
	// reconnect gets a cache hit and avoids a fresh VK API round-trip (and captcha).
	// If old TURN allocations lingered (drain timed out) and the quota is exhausted,
	// a worker hitting 486 calls refreshGroupCreds → its next reconnect re-fetches
	// a fresh credential automatically.
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func resolvePeer(peerAddr string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(peerAddr)
	if err != nil {
		return net.ResolveUDPAddr("udp", peerAddr)
	}
	if net.ParseIP(host) == nil {
		resolvedIP, err := hostCache.Resolve(context.Background(), host)
		if err != nil {
			turnLog("[DNS] Peer resolution warning: %v — using original", err)
		} else {
			peerAddr = net.JoinHostPort(resolvedIP, port)
		}
	}
	return net.ResolveUDPAddr("udp", peerAddr)
}

type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
