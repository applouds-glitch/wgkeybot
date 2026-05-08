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
	invalidateAllCaches()
	turnHTTPClient.CloseIdleConnections()
	turnLog("[NETWORK] Network change: DNS cache + credential caches cleared, HTTP connections reset")
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

const iPacketBuffMaxSize = 2048

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

	turnLog("[STREAM %d] NoDTLS mode — %s", s.id, peer)

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
				_, err := relayConn.WriteTo(b, peer)
				packetPool.Put(b[:cap(b)])
				if err != nil {
					noDtlsTxDropCount.Add(1)
					turnLog("[STREAM %d] TX error: %v", s.id, err)
					return
				}
			}
		}
	}()

	// RX: relay → WireGuard
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, from, err := relayConn.ReadFrom(buf)
			if err != nil {
				noDtlsRxErrorCount.Add(1)
				return
			}
			if from.String() == peer.String() {
				if a := s.peer.Load(); a != nil {
					if _, err := s.out.WriteTo(buf[:n], *a); err != nil {
						noDtlsRxErrorCount.Add(1)
						return
					}
				}
			}
		}
	}()

	// Keepalive: send STUN Binding Indication every 25s to keep relay and NAT alive.
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		relayConn.SetDeadline(time.Now().Add(60 * time.Second))
		for {
			select {
			case <-sCtx.Done():
				return
			case <-ticker.C:
				relayConn.WriteTo(stunBindingIndication, peer)
				relayConn.SetDeadline(time.Now().Add(60 * time.Second))
			}
		}
	}()

	s.ready.Store(true)
	s.okFunc()
	wg.Wait()
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// runDTLS — DTLS-obfuscated relay (optionally with WRAP layer)
// ─────────────────────────────────────────────────────────────────────────────

func (s *stream) runDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, sendHandshake bool) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()

	c1, c2 := connutil.AsyncPacketPipe()
	defer c1.Close()
	defer c2.Close()

	dtlsConn, err := dtls.Client(c1, peer, &dtls.Config{
		Certificates:          []tls.Certificate{*s.cert},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
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
					return
				}
			} else {
				payload = buf[:n]
			}

			if _, err := relayConn.WriteTo(payload, peer); err != nil {
				relayTxErrorCount.Add(1)
				turnLog("[STREAM %d] relay TX error: %v", s.id, err)
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

	// Session + stream ID handshake (proxy_v2 only)
	if sendHandshake {
		dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 17)
		copy(buf[:16], s.sessionID)
		buf[16] = byte(s.id)
		if _, err := dtlsConn.Write(buf); err != nil {
			return fmt.Errorf("session handshake failed: %w", err)
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
				if s.watchdogTimeout > 0 && time.Since(time.Unix(lastRx.Load(), 0)) > time.Duration(s.watchdogTimeout)*time.Second {
					packetPool.Put(b[:cap(b)])
					dtlsTxDropCount.Add(1)
					turnLog("[STREAM %d] TX watchdog (%ds)", s.id, s.watchdogTimeout)
					return
				}
				_, err := dtlsConn.Write(b)
				packetPool.Put(b[:cap(b)])
				if err != nil {
					dtlsTxDropCount.Add(1)
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
				return
			}
			lastRx.Store(time.Now().Unix())
			if a := s.peer.Load(); a != nil {
				if _, err := s.out.WriteTo(buf[:n], *a); err != nil {
					dtlsRxErrorCount.Add(1)
					return
				}
			}
		}
	}()

	// Keepalive: send STUN Binding Indication through DTLS every 25s.
	// Going via dtlsConn.Write (not raw relayConn.WriteTo) means the server
	// receives a valid DTLS ApplicationData record → its 5-min read deadline
	// is refreshed. Raw STUN sent via relayConn would arrive as a non-DTLS UDP
	// datagram and be silently discarded by pion/dtls, leaving the deadline stale.
	// The server forwards the 20 bytes to WireGuard, which drops unknown types (0x00).
	// relayConn deadline is also refreshed so ReadFrom doesn't time out client-side.
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		relayConn.SetDeadline(time.Now().Add(60 * time.Second))
		for {
			select {
			case <-sCtx.Done():
				return
			case <-ticker.C:
				if _, err := dtlsConn.Write(stunBindingIndication); err == nil {
					// Successful write proves the DTLS path is alive; update lastRx so
					// the RX watchdog doesn't close streams that receive infrequent data.
					// With many streams the server round-robins responses, so a single
					// stream may wait 750 s+ between real RX packets.
					lastRx.Store(time.Now().Unix())
				}
				relayConn.SetDeadline(time.Now().Add(60 * time.Second))
			}
		}
	}()

	// Timer watchdog: closes the stream if no data has been received for watchdogTimeout seconds,
	// even when there is no outgoing WireGuard traffic (idle connection broken detection).
	if s.watchdogTimeout > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer sCancel()
			interval := time.Duration(s.watchdogTimeout) * time.Second
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-sCtx.Done():
					return
				case <-ticker.C:
					if time.Since(time.Unix(lastRx.Load(), 0)) > interval {
						turnLog("[STREAM %d] RX watchdog: no data for %ds — closing", s.id, s.watchdogTimeout)
						return
					}
				}
			}
		}()
	}

	wg.Wait()
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Global state
// ─────────────────────────────────────────────────────────────────────────────

var currentTurnCancel context.CancelFunc
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
	clearTransientState() // flush DNS + HTTP without clearing credential caches
	atomic.StoreInt32(&globalPauseFlag, 0) // reset on each new tunnel start

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
	globalGetCreds = func(ctx context.Context, lk string, streamID int) (string, string, string, error) {
		return getCredsCached(ctx, lk, streamID, fetchVkCreds)
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
lc, err := net.ListenPacket("udp", listenAddr)
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
	for i, lk := range links {
		prefetchWg.Add(1)
		go func(groupID int, link string) {
			defer prefetchWg.Done()
			select {
			case vkSemaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			_, _, _, _, prefetchErr := fetchCredsWithLifetime(ctx, link, groupID)
			<-vkSemaphore
			if prefetchErr != nil {
				if ctx.Err() == nil {
					turnLog("[PROXY] Pre-fetch group %d failed: %v (WorkerGroup will retry)", groupID, prefetchErr)
				}
			} else {
				turnLog("[PROXY] Pre-fetch group %d OK", groupID)
			}
		}(i, lk)
	}
	prefetchWg.Wait()

	// ── Launch groups ─────────────────────────────────────────────────────────
	_, okChan, err := StartTunnelGroups(ctx, packetLc, TunnelGroupsConfig{
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

	select {
	case <-okChan:
		turnLog("[PROXY] First stream ready — tunnel is up")
		return 0
	case <-ctx.Done():
		turnLog("[PROXY] Startup cancelled")
		return -1
	}
}

//export wgTurnProxyStop
func wgTurnProxyStop() {
	turnMutex.Lock()
	defer turnMutex.Unlock()
	if currentTurnCancel != nil {
		turnLog("[PROXY] Stopping TURN proxy")
		currentTurnCancel()
		currentTurnCancel = nil
	}
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
