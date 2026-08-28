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
	"errors"
	"fmt"
	"net"
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

// errSocketNotProtected aborts a dial whose socket VpnService.protect() refused.
// This app is deliberately kept inside its own tunnel (GoBackend never excludes
// its own package), and the WireGuard endpoint is the local TURN listener, so an
// unprotected TURN/DNS/HTTP socket does not merely leak — its packets are routed
// back into the tunnel and loop. Failing the dial is the safe outcome: every
// caller propagates it into an existing retry/backoff path.
var errSocketNotProtected = errors.New("VpnService.protect() failed; refusing to dial an unprotected socket")

func protectControl(network, address string, c syscall.RawConn) error {
	var protectErr error
	if err := c.Control(func(fd uintptr) {
		if C.wgProtectSocket(C.int(fd)) != 0 {
			protectErr = errSocketNotProtected
		}
	}); err != nil {
		return err
	}
	return protectErr
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

// clearTransientState resets the DNS cache without touching credential caches.
// Called on every tunnel start so stale DNS is flushed, but credentials earned
// in a prior session are reused if still valid. No HTTP pool is flushed here:
// the VK cred fetch builds a per-fetch tlsclient and closes its idle
// connections when done, and the DoH resolver does the same — there is no
// long-lived shared client to reset.
func clearTransientState() {
	ClearCache()
	turnLog("[PROXY] Transient state cleared (DNS; creds preserved)")
}

//export wgNotifyNetworkChange
func wgNotifyNetworkChange() {
	resetNetworkPathProof()
	ClearCache()
	turnLog("[NETWORK] Network change: path proof and DNS cache reset (creds preserved)")
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

	// serverAddr is the TURN server this attempt runs on, set by runSession
	// before the transport starts. The transports use it to report their own
	// handshake verdict to turn_server_health.go; it is rewritten on every
	// attempt and read only by the single goroutine driving this stream.
	serverAddr string

	// wrapKey is an optional 32-byte ChaCha20 key for WRAP obfuscation.
	// When non-nil, raw UDP packets to/from the TURN relay are encrypted with
	// wrapPacket / unwrapPacket before any DTLS processing.
	// nil = WRAP disabled (plain mode).
	wrapKey []byte

	// kaPhase is this stream's offset within the shared keepalive grid window,
	// derived from id and the total stream count at startup (see keepalivePhase).
	// Constant for the stream's life, so its NAT-hold gap stays exactly one
	// keepaliveInterval.
	kaPhase time.Duration

	// wrapTx carries this stream's outbound WRAP SSRC and counter. Both are
	// per-stream, so each stream (and each device) uses a distinct keystream
	// even at the same counter, and its RTP sequence advances one step per
	// packet. Created in StartTunnelGroups; see wrapTxState.
	wrapTx *wrapTxState

	networkGeneration uint64
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

// sameRelayPeer reports whether from is the expected relay peer. The obvious
// from.String() != peer.String() costs two string allocations on every single
// received packet; pion's relay conn always hands back a *net.UDPAddr (both the
// Data-indication and the ChannelData path construct one), so the fast path is
// the only one taken in practice. peerStr — precomputed once by the caller —
// preserves the old semantics for any other net.Addr implementation.
func sameRelayPeer(from net.Addr, peer *net.UDPAddr, peerStr string) bool {
	if ua, ok := from.(*net.UDPAddr); ok {
		return ua.Port == peer.Port && ua.IP.Equal(peer.IP)
	}
	return from.String() == peerStr
}

const iPacketBuffMaxSize = 2048

// runKeepalive is the single per-stream NAT-hold and liveness loop shared by
// all transports. Connections are established with a safety stagger, but every
// ready stream sends its normal keepalive on the same 25s wall-clock grid so the
// packets and their echoes occupy one short radio-active window — staggered
// inside that window by the stream's phase (see keepalivePhase), so one lost
// burst cannot starve every sibling's liveness clock at the same instant. A
// failed write may retry early; after success the stream rejoins the grid.
// Only a validated inbound packet proves liveness, except after a host freeze,
// where a stale clock says nothing about the path and is reset (see freezeSlack).
func (s *stream) runKeepalive(ctx context.Context, activity *streamActivity, reportErr func(error), send func(tick int) error) {
	var retryAt time.Time
	tick := 0
	for {
		deadline, wakeReason := activity.nextDeadline(time.Now(), retryAt)
		before := time.Now()
		if !waitUntil(ctx, deadline) {
			return
		}

		now := time.Now()
		rxAge := activity.rxAge(now)

		// nextDeadline never returns a point further out than the shared grid, so
		// a sleep this long means the host froze us rather than that the path went
		// quiet. Reset the liveness clock and re-stimulate the path; tearing the
		// stream down here would mass-reconnect every stream on thaw.
		if slept := now.Sub(before); slept > keepaliveInterval+freezeSlack {
			turnLog("[STREAM %d] keepalive: slept %v (freeze) — resetting liveness clock", s.id, slept.Round(time.Second))
			activity.resetLiveness(now)
			// A thawed host must re-stimulate both layers in the same radio
			// window: one WireGuard keepalive for this grid, then this stream's
			// TURN liveness probe.
			sendWireGuardKeepaliveOnSharedGrid(now)
			err := send(tick)
			tick++
			if err != nil {
				turnLog("[STREAM %d] keepalive send error: %v", s.id, err)
				retryAt = now.Add(keepaliveSendRetry)
				continue
			}
			retryAt = time.Time{}
			continue
		}

		if rxAge >= deadStreamTimeout {
			turnLog("[STREAM %d] dead-stream detector: no RX for %v — closing", s.id, rxAge.Round(time.Second))
			reportErr(fmt.Errorf("dead-stream: no RX for %v", rxAge.Round(time.Second)))
			return
		}
		// An RX that arrived after the timer was armed may make an old liveness
		// deadline harmless. Recalculate instead of emitting an off-grid packet.
		if wakeReason == keepaliveDeadCheckWake {
			continue
		}
		if wakeReason == keepaliveGridWake {
			// Every stream reaches this shared bucket within keepaliveSpread.
			// The coordinator lets only the first one enqueue a WireGuard
			// keepalive, coalescing it with the TURN/STUN burst below.
			sendWireGuardKeepaliveOnSharedGrid(now)
		}
		err := send(tick)
		tick++
		if err != nil {
			turnLog("[STREAM %d] keepalive send error: %v", s.id, err)
			retryAt = now.Add(keepaliveSendRetry)
			continue
		}
		retryAt = time.Time{}
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
			enc, err := wrapPacket(s.wrapKey, sessionHS, s.wrapTx)
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

const (
	// relayProofTimeout bounds the wait for the relay to answer (see runNoDTLS).
	// Short enough that a bad relay is out of the way with room for WireGuard's
	// own retries inside the 25s connect budget, long enough to survive a mobile
	// RTT plus a lost probe — a full DTLS-SRTP handshake over these relays
	// measures 130-220ms, so a single round trip has an order of magnitude of
	// headroom here.
	relayProofTimeout = 2 * time.Second

	// relayProbeInterval re-sends the probe (and the session header with it, in
	// case that is what was lost) while waiting. UDP loses packets; one silent
	// drop must not read as a dead relay.
	relayProbeInterval = 400 * time.Millisecond
)

// runNoDTLS carries WireGuard straight over the relay, optionally WRAP-obfuscated.
//
// Unlike DTLS and SRTP this transport has no handshake of its own — the server
// answers the 17-byte session header with nothing — so readiness used to be a
// blind 200ms sleep. That made a relay which allocates and then swallows
// everything look exactly like a working one: the dispatcher kept feeding the
// dead stream (init_groups.go sends eight consecutive packets through one
// stream, and before the tunnel is up those eight are all of WireGuard's
// handshake retries), and TunnelManager tore the tunnel down at its 25s
// handshake deadline — long before the 90s dead-stream detector had said a word.
// Allocate had succeeded, so nothing counted against the server either, and the
// next attempt went back to the same dead host.
//
// The proof was already on the wire: the server echoes a STUN keepalive back
// through the stream once it has registered the session header, and that echo is
// a full round trip through the relay. So probe with one and wait for it, and
// fail the stream if it never comes.
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

	// Closed by the RX goroutine on the first packet the relay hands back that
	// survives the peer and WRAP checks. That packet is the whole proof this
	// transport gets that the relay round trip works.
	proofCh := make(chan struct{})
	var proofOnce sync.Once
	proven := func() { proofOnce.Do(func() { close(proofCh) }) }

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
			return fmt.Errorf("%w: %w", errDataPlaneHandshake, hErr)
		}
		turnLog("[STREAM %d] Session handshake burst sent", s.id)
	}

	// Cancelling sCtx (watchdog, error, parent stop) closes the relay conn so
	// the RX goroutine's blocking ReadFrom unblocks immediately instead of
	// waiting out its 60s deadline.
	context.AfterFunc(sCtx, func() { relayConn.Close() })

	activity := newStreamActivity(time.Now(), s.kaPhase)

	var wg sync.WaitGroup
	wg.Add(3)

	// TX: WireGuard → relay
	go func() {
		defer wg.Done()
		defer sCancel()
		// Scratch buffer for WRAP encryption, owned by this goroutine alone.
		// relayConn.WriteTo copies the payload into its own STUN/ChannelData
		// message, so the buffer is free to be reused on the next packet.
		var txBuf []byte
		if hasWrap {
			txBuf = make([]byte, iPacketBuffMaxSize+wrapMaxOverhead)
		}
		for {
			select {
			case <-sCtx.Done():
				return
			case b := <-s.in:
				var payload []byte
				if hasWrap {
					n, wrapErr := wrapPacketInto(txBuf, s.wrapKey, b, s.wrapTx)
					if wrapErr != nil {
						packetPool.Put(b[:cap(b)])
						noDtlsTxDropCount.Add(1)
						turnLog("[STREAM %d] WRAP TX error: %v", s.id, wrapErr)
						reportErr(fmt.Errorf("WRAP TX: %w", wrapErr))
						return
					}
					payload = txBuf[:n]
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
		peerStr := peer.String()
		for {
			n, from, err := relayConn.ReadFrom(wire)
			if err != nil {
				noDtlsRxErrorCount.Add(1)
				reportErr(fmt.Errorf("relay RX: %w", err))
				return
			}
			if !sameRelayPeer(from, peer, peerStr) {
				continue
			}
			if hasWrap {
				m, unwrapErr := unwrapPacket(s.wrapKey, wire[:n], plain)
				if unwrapErr != nil {
					turnLog("[STREAM %d] WRAP RX skip: %v", s.id, unwrapErr)
					continue
				}
				// Only a successfully parsed WRAP packet is inbound liveness
				// evidence. A valid cover packet has no WG payload but still proves
				// that the relay path works in both directions.
				activity.noteRx(time.Now())
				markNetworkPathProven(s.networkGeneration)
				proven()
				if m == 0 {
					continue
				}
				if isStunKeepalive(plain[:m]) {
					continue
				}
				a := s.peer.Load()
				if a == nil {
					continue
				}
				if _, err := s.out.WriteTo(plain[:m], *a); err != nil {
					noDtlsRxErrorCount.Add(1)
					reportErr(fmt.Errorf("TUN write: %w", err))
					return
				}
			} else {
				if n == 0 {
					continue
				}
				activity.noteRx(time.Now())
				markNetworkPathProven(s.networkGeneration)
				proven()
				if isStunKeepalive(wire[:n]) {
					continue
				}
				a := s.peer.Load()
				if a == nil {
					continue
				}
				if _, err := s.out.WriteTo(wire[:n], *a); err != nil {
					noDtlsRxErrorCount.Add(1)
					reportErr(fmt.Errorf("TUN write: %w", err))
					return
				}
			}
		}
	}()

	// Keepalive + cover traffic + dead-stream detection (one coalesced loop; see
	// runKeepalive). Sends the STUN Indication
	// (liveness stimulus + NAT hold), paces WRAP cover traffic every 3rd tick,
	// and re-announces the 17-byte session header so a restarted server re-adopts
	// this stream within one tick without a reconnect. A send never refreshes
	// lastRx — only the server's echo (in the RX goroutine) proves the path.
	go func() {
		defer wg.Done()
		defer sCancel()
		s.runKeepalive(sCtx, activity, reportErr, func(tick int) error {
			var sendErr error
			if hasWrap {
				if enc, err := wrapPacket(s.wrapKey, stunBindingIndication, s.wrapTx); err == nil {
					_, sendErr = relayConn.WriteTo(enc, peer)
				} else {
					sendErr = err
				}
				if tick%3 == 0 {
					if cover, cErr := wrapCoverPacket(s.wrapKey, s.wrapTx); cErr == nil {
						relayConn.WriteTo(cover, peer)
					}
				}
			} else {
				_, sendErr = relayConn.WriteTo(stunBindingIndication, peer)
			}
			if sessionHS != nil {
				if hasWrap {
					if enc, wErr := wrapPacket(s.wrapKey, sessionHS, s.wrapTx); wErr == nil {
						relayConn.WriteTo(enc, peer)
					}
				} else {
					relayConn.WriteTo(sessionHS, peer)
				}
			}
			return sendErr
		})
	}()

	if sessionHS != nil {
		if err := s.awaitRelayProof(sCtx, proofCh, func() error {
			return s.probeRelay(relayConn, peer, sessionHS, hasWrap)
		}); err != nil {
			sCancel()
			wg.Wait()
			if ctx.Err() != nil {
				// Our own teardown, not the relay's silence.
				return err
			}
			// A goroutine that already failed knows better than the timeout why
			// nothing came back; either way the stream never carried traffic.
			select {
			case cause := <-firstErr:
				return fmt.Errorf("%w: %w", errDataPlaneHandshake, cause)
			default:
				return fmt.Errorf("%w: %w", errDataPlaneHandshake, err)
			}
		}
		noteServerHandshakeOK(s.serverAddr)
	} else {
		// Without a session header the server never registers this stream and so
		// never echoes: there is nothing to wait for. Keep the old optimistic
		// readiness on that path rather than failing a stream we cannot judge.
		time.Sleep(200 * time.Millisecond)
	}

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

// probeRelay sends one liveness probe: the session header first, so a server
// that lost the opening burst registers the stream before it sees the STUN it is
// meant to echo, then the STUN itself.
func (s *stream) probeRelay(relayConn net.PacketConn, peer net.Addr, sessionHS []byte, hasWrap bool) error {
	if hasWrap {
		if enc, err := wrapPacket(s.wrapKey, sessionHS, s.wrapTx); err == nil {
			relayConn.WriteTo(enc, peer)
		}
		enc, err := wrapPacket(s.wrapKey, stunBindingIndication, s.wrapTx)
		if err != nil {
			return fmt.Errorf("WRAP probe: %w", err)
		}
		_, err = relayConn.WriteTo(enc, peer)
		return err
	}
	relayConn.WriteTo(sessionHS, peer)
	_, err := relayConn.WriteTo(stunBindingIndication, peer)
	return err
}

// awaitRelayProof probes until the relay answers, the context dies, or
// relayProofTimeout runs out. Returning an error means the stream never proved
// its data path and must not be offered to the dispatcher.
func (s *stream) awaitRelayProof(ctx context.Context, proof <-chan struct{}, probe func() error) error {
	if err := probe(); err != nil {
		return err
	}
	deadline := time.NewTimer(relayProofTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(relayProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-proof:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("relay never answered in %v", relayProofTimeout)
		case <-ticker.C:
			if err := probe(); err != nil {
				return err
			}
		}
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
		// Scratch buffer for WRAP encryption, owned by this goroutine alone
		// (see runNoDTLS TX for why reuse is safe).
		var txBuf []byte
		if s.wrapKey != nil {
			txBuf = make([]byte, iPacketBuffMaxSize+wrapMaxOverhead)
		}
		for {
			n, _, err := c2.ReadFrom(buf)
			if err != nil {
				return
			}

			var payload []byte
			if s.wrapKey != nil {
				wrapped, wrapErr := wrapPacketInto(txBuf, s.wrapKey, buf[:n], s.wrapTx)
				if wrapErr != nil {
					turnLog("[STREAM %d] WRAP TX error: %v", s.id, wrapErr)
					relayTxErrorCount.Add(1)
					reportErr(fmt.Errorf("WRAP TX: %w", wrapErr))
					return
				}
				payload = txBuf[:wrapped]
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
		peerStr := peer.String()
		for {
			n, from, err := relayConn.ReadFrom(wire)
			if err != nil {
				relayRxErrorCount.Add(1)
				turnLog("[STREAM %d] relay RX error: %v", s.id, err)
				reportErr(fmt.Errorf("relay RX: %w", err))
				return
			}
			if sameRelayPeer(from, peer, peerStr) {
				var data []byte
				if s.wrapKey != nil {
					m, unwrapErr := unwrapPacket(s.wrapKey, wire[:n], plain)
					if unwrapErr != nil {
						// Corrupted or unrecognised packet — skip silently.
						turnLog("[STREAM %d] WRAP RX skip: %v", s.id, unwrapErr)
						continue
					}
					if m == 0 {
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
		return fmt.Errorf("%w: DTLS handshake failed: %w", errDataPlaneHandshake, err)
	}
	dtlsConn.SetDeadline(time.Time{})
	turnLog("[STREAM %d] DTLS handshake OK", s.id)
	noteServerHandshakeOK(s.serverAddr)
	markNetworkPathProven(s.networkGeneration)

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

	activity := newStreamActivity(time.Now(), s.kaPhase)

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
			// dtlsConn.Read only returns authenticated application data, so this
			// is valid inbound liveness evidence.
			activity.noteRx(time.Now())
			markNetworkPathProven(s.networkGeneration)
			if isStunKeepalive(buf[:n]) {
				continue
			}
			if n == 0 {
				continue
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

	// Keepalive + dead-stream detection (one coalesced loop; see runKeepalive).
	// The STUN Indication goes via dtlsConn.Write so the server
	// receives a valid DTLS ApplicationData record (refreshing server read
	// deadline) and echoes the 20 bytes straight back through this stream; the
	// echo bumps lastRx in the DTLS→WireGuard RX goroutine — the only proof of a
	// live path (a dead allocation still accepts the write). runKeepalive tears
	// the stream down when lastRx goes stale past the current dead-stream
	// threshold, replacing the former 10s TURN Binding Request probe and watchdog.
	go func() {
		defer wg.Done()
		defer sCancel()
		s.runKeepalive(sCtx, activity, reportErr, func(int) error {
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
		return fmt.Errorf("%w: SRTP handshake failed: %w", errDataPlaneHandshake, err)
	}
	defer srtpConn.Close()
	context.AfterFunc(sCtx, func() { srtpConn.Close() })
	turnLog("[STREAM %d] SRTP handshake OK", s.id)
	noteServerHandshakeOK(s.serverAddr)
	markNetworkPathProven(s.networkGeneration)

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

	activity := newStreamActivity(time.Now(), s.kaPhase)

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
			// srtpConn.Read has already authenticated and decrypted this packet.
			activity.noteRx(time.Now())
			markNetworkPathProven(s.networkGeneration)
			if isStunKeepalive(buf[:n]) {
				continue
			}
			if n == 0 {
				continue
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

	// Keepalive + dead-stream detection (one coalesced loop; see runKeepalive).
	// The STUN Indication goes through the SRTP pipe; the
	// server echoes it back through this stream and the echo bumps lastRx in the
	// SRTP→WireGuard RX goroutine — the only proof of a live path. runKeepalive
	// tears the stream down when lastRx goes stale, replacing the former 10s TURN
	// Binding Request probe and watchdog. (srtpwrap owns the relay read loop, so
	// this per-stream detector is the only dead-path signal SRTP has.)
	go func() {
		defer wg.Done()
		defer sCancel()
		s.runKeepalive(sCtx, activity, reportErr, func(int) error {
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

//export wgSetNetworkAvailable
func wgSetNetworkAvailable(available C.int) {
	setNetworkAvailable(available != 0)
	validated, proven, effective, remaining := networkAvailabilitySnapshot()
	turnLog("[PROXY] AndroidValidated=%t transportProven=%t effectiveAvailable=%t proofTTL=%v",
		validated, proven, effective, remaining.Round(time.Second))
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
	networkGeneration := beginNetworkPathGeneration()
	clearTransientState()    // flush DNS without clearing credential caches
	resetServerHealth()      // new credentials, usually a new server list
	resetWorkerFatalState(0) // re-armed with the real worker count in StartTunnelGroups

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
		// A captcha belonging to the proxy we just cancelled must not stay on
		// screen (nor keep holding captchaMutex) while this start runs.
		abortPendingCaptcha()
	}
	ctx, cancel := context.WithCancel(context.Background())
	currentTurnCancel = cancel
	turnMutex.Unlock()

	// Reset the captcha lockout and its escalation only after the previous proxy
	// has been cancelled: its workers unwind through the "solve ladder exhausted"
	// path, and each such exit arms the lockout. Resetting before the cancel let
	// a dying session hand its lockout to the session starting here.
	resetCaptchaLockout()

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
	// StreamNum (n) is the total stream count. streamsPerCred is a group's
	// capacity — the most streams one credential may carry — not its exact size.
	//   • n < total: reduce streamsPerCred so total matches n.
	//   • n > total: add groups by cycling links until they hold n streams, and
	//     let the last group take the remainder rather than rounding the total
	//     up to a multiple of streamsPerCred (n=12, streamsPerCred=9 gives 9 + 3,
	//     not 9 + 9). A short trailing group needs no special handling
	//     elsewhere: streamID/streamsPerCred — the credential cache key in
	//     credentials.go:getCacheID — already maps streams 9-11 to slot 1.
	// streamsPerCred must stay in sync with that division either way. The value is
	// computed locally and published once, at the end: the global is read by the
	// previous session's departing workers, so intermediate values must never be
	// visible to them.
	perCred := int(streamsPerCredC)
	if perCred < 1 {
		perCred = 1
	}
	totalStreams := len(links) * perCred
	if maxTotal := int(n); maxTotal > 0 {
		if maxTotal < totalStreams {
			perGroup := maxTotal / len(links)
			if perGroup < 1 {
				perGroup = 1
			}
			perCred = perGroup
			totalStreams = len(links) * perCred
		} else if maxTotal > totalStreams {
			numGroups := (maxTotal + perCred - 1) / perCred
			origLinks := links
			links = make([]string, numGroups)
			for i := range links {
				links[i] = origLinks[i%len(origLinks)]
			}
			totalStreams = maxTotal
		}
	}
	setStreamsPerCred(perCred)

	turnLog("[PROXY] Starting: listen=%s StreamNum=%d streamsPerGroup=%d links=%d actualTotal=%d mode=%s peerType=%s watchdog=%ds",
		listenAddr, int(n), perCred, len(links), totalStreams, mode, peerType, watchdogTimeout)
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
	var callUnavailable int32  // set to 1 if any group's call is dead/deleted/invalid link
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
					} else if strings.Contains(prefetchErr.Error(), "CALL_UNAVAILABLE") {
						atomic.StoreInt32(&callUnavailable, 1)
						turnLog("[PROXY] Pre-fetch group %d: CALL_UNAVAILABLE (call ended/deleted or invalid link)", groupID)
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
	if atomic.LoadInt32(&prefetchOk) == 0 && atomic.LoadInt32(&callUnavailable) == 1 {
		turnLog("[PROXY] All pre-fetches failed: call unavailable (ended/deleted or invalid link) — aborting startup")
		cancel()
		return -4 // distinct code: dead call — caller must not retry other stream counts
	}
	if atomic.LoadInt32(&prefetchOk) == 0 && atomic.LoadInt32(&prefetchLockout) == 1 {
		turnLog("[PROXY] All pre-fetches failed due to CAPTCHA_WAIT_REQUIRED — aborting startup")
		cancel()
		return -3 // distinct code: captcha lockout — caller must not retry other stream counts
	}

	// ── Launch groups ─────────────────────────────────────────────────────────
	_, okChan, done, err := StartTunnelGroups(ctx, packetLc, TunnelGroupsConfig{
		Links:             links,
		PeerAddr:          peer,
		PeerType:          peerType,
		UseUDP:            udp != 0,
		TurnIP:            turnIp,
		TurnPort:          turnPort,
		StreamsPerGroup:   perCred,
		TotalStreams:      totalStreams,
		Cert:              &cert,
		SessionID:         sessionID,
		WatchdogTimeout:   watchdogTimeout,
		WrapKey:           wrapKey,
		NetworkGeneration: networkGeneration,
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
	resetNetworkPathProof()
	turnMutex.Lock()
	cancel := currentTurnCancel
	done := currentTurnDone
	currentTurnCancel = nil
	currentTurnDone = nil
	turnMutex.Unlock()

	// Unconditional: cancelling the context does not reach a worker parked inside
	// the blocking Android captcha call, and the drain below would then wait out
	// its whole timeout. Run it even when there is no cancel func left to call —
	// a captcha can outlive the start that triggered it, and dismissing nothing
	// costs one no-op JNI call.
	abortPendingCaptcha()

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
