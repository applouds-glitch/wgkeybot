/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

// #cgo android LDFLAGS: -llog
// #include <android/log.h>
// extern int wgProtectSocket(int fd);
import "C"

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DnsCache stores cached IP addresses.
//
// inflight collapses concurrent lookups of the same name into one. Credential
// fetches run two at a time (vkSemaphore) over the same handful of VK hosts,
// and on a dead uplink both used to walk the entire server list independently:
// twice the queries to resolvers that were already timing out, for one answer.
type DnsCache struct {
	mu       sync.RWMutex
	ips      map[string]string
	inflight map[string]*dnsLookup
}

// dnsLookup is one resolution in progress, shared by every caller that asked
// for the same name while it was running.
type dnsLookup struct {
	done chan struct{}
	ip   string
	err  error
}

const (
	dnsTimeout   = 2 * time.Second
	dohTimeout   = 2 * time.Second
	dotTimeout   = 2 * time.Second
	yandexIP     = "77.88.8.8"
	yandexDomain = "common.dot.dns.yandex.net"
	googleIP     = "8.8.8.8"
	googleDomain = "dns.google"

	// dnsHedgeDelay is how long one server keeps the query to itself before the
	// next one joins in.
	//
	// Walking the list strictly in order cost up to len(dnsServers) × timeout —
	// six servers × 2s = 12s of pure waiting whenever the uplink was simply
	// gone, paid again by every concurrent lookup. Hedging leaves the healthy
	// case exactly as it was (the first server answers in tens of milliseconds
	// and nothing else is ever dialled) while bounding the bad case to about one
	// timeout plus the stagger.
	//
	// Set well above a normal LAN resolver's answer (single-digit milliseconds)
	// so a working server is never raced against for no reason, and well below
	// dnsTimeout so a hung one does not hold the whole list up.
	dnsHedgeDelay = 400 * time.Millisecond
)

// DNSServerType represents the type of DNS server
type DNSServerType int

const (
	DNSPlain DNSServerType = iota
	DNSDoH
	DNSDoT
)

// DNSServer represents a DNS server configuration
type DNSServer struct {
	Type   DNSServerType
	IP     string
	Domain string
}

// Predefined ordered list of DNS servers (Yandex + Google: plain, doh, dot)
var dnsServersPredefined = []DNSServer{
	{Type: DNSPlain, IP: yandexIP, Domain: ""},
	{Type: DNSDoH, IP: yandexIP, Domain: yandexDomain},
	{Type: DNSPlain, IP: googleIP, Domain: ""},
	{Type: DNSDoT, IP: yandexIP, Domain: yandexDomain},
	{Type: DNSDoH, IP: googleIP, Domain: googleDomain},
	//{Type: DNSDoT, IP: googleIP, Domain: googleDomain},
}

// dnsServers is the active list used during resolution.
// It is initialized in init() to dnsServersPredefined,
// or replaced by InitSystemDns() with system DNS prepended.
var dnsServers []DNSServer

// lastSuccessfulIndex stores the index of the last successful DNS server
var (
	lastSuccessfulIndex int
	lastSuccessfulMu    sync.RWMutex
)

var (
	hostCache = &DnsCache{
		ips:      make(map[string]string),
		inflight: make(map[string]*dnsLookup),
	}
)

// Resolve resolves DNS name using cache and ordered server list. Callers asking
// for the same name at the same time share one lookup: the first becomes its
// leader and the rest wait on its answer.
func (c *DnsCache) Resolve(ctx context.Context, domain string) (string, error) {
	for {
		c.mu.Lock()
		if cached, ok := c.ips[domain]; ok {
			c.mu.Unlock()
			return cached, nil
		}
		if call, ok := c.inflight[domain]; ok {
			c.mu.Unlock()
			select {
			case <-call.done:
			case <-ctx.Done():
				return "", ctx.Err()
			}
			if call.err == nil {
				return call.ip, nil
			}
			// The leader may have failed only because ITS caller went away — a
			// worker torn down while we are still very much alive. That says
			// nothing about the name, so take the lookup over instead of
			// inheriting a cancellation that was never ours.
			if isContextErr(call.err) && ctx.Err() == nil {
				continue
			}
			return "", call.err
		}
		call := &dnsLookup{done: make(chan struct{})}
		if c.inflight == nil {
			c.inflight = make(map[string]*dnsLookup)
		}
		c.inflight[domain] = call
		c.mu.Unlock()

		call.ip, call.err = resolveWithOrderedServers(ctx, domain)

		// Only successes are cached; a failure must not pin a name to an error.
		// The entry leaves inflight under the same lock that publishes the
		// answer, so a caller arriving now reads the cache instead of waiting.
		c.mu.Lock()
		if call.err == nil {
			c.ips[domain] = call.ip
		}
		delete(c.inflight, domain)
		c.mu.Unlock()
		close(call.done)

		return call.ip, call.err
	}
}

func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// resolveAnyFn is the seam tests replace to drive the hedged race without
// touching the network.
var resolveAnyFn = resolveAny

type dnsRaceResult struct {
	idx int
	ip  string
	err error
}

// resolveWithOrderedServers resolves domain against the server list, starting
// with the last one that worked and hedging: each further server joins the race
// after dnsHedgeDelay, or immediately once one of the running queries has
// failed. The first answer wins and cancels the rest.
//
// Order still matters — the last successful server gets a head start measured
// in hedge delays, so the common case is one query to one server — but a server
// that has stopped answering no longer costs its full timeout before the next
// one is even tried.
func resolveWithOrderedServers(ctx context.Context, domain string) (string, error) {
	// Snapshot both, so the whole race runs against one list and one resolver
	// even if InitSystemDns swaps the slice — or a test restores the seam — while
	// a straggler is still in flight.
	servers, resolve := dnsServers, resolveAnyFn
	if len(servers) == 0 {
		return "", fmt.Errorf("no DNS servers configured for %s", domain)
	}

	lastSuccessfulMu.RLock()
	startIndex := lastSuccessfulIndex
	lastSuccessfulMu.RUnlock()
	if startIndex < 0 || startIndex >= len(servers) {
		startIndex = 0
	}

	// Cancelled on every exit path, which is what stops the stragglers the
	// moment one server has answered.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dnsRaceResult, len(servers))
	// Fires immediately: the first server starts without waiting a hedge.
	hedge := time.NewTimer(0)
	defer hedge.Stop()

	var (
		started  int
		finished int
		firstErr error
	)
	for finished < len(servers) {
		// Once every server is running there is nothing left to start, and the
		// nil channel takes the hedge out of the select.
		var nextServer <-chan time.Time
		if started < len(servers) {
			nextServer = hedge.C
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()

		case <-nextServer:
			idx := (startIndex + started) % len(servers)
			server := servers[idx]
			started++
			turnLog("[DNS] Trying server %d (%v, %s) for %s", idx, server.Type, server.IP, domain)
			go func() {
				ip, err := resolve(ctx, domain, server)
				// Buffered for every server, so a straggler losing the race
				// still delivers and exits instead of leaking.
				results <- dnsRaceResult{idx: idx, ip: ip, err: err}
			}()
			if started < len(servers) {
				hedge.Reset(dnsHedgeDelay)
			}

		case res := <-results:
			finished++
			if res.err == nil {
				turnLog("[DNS] Success with server %d: %s -> %s", res.idx, domain, res.ip)
				lastSuccessfulMu.Lock()
				lastSuccessfulIndex = res.idx
				lastSuccessfulMu.Unlock()
				return res.ip, nil
			}
			turnLog("[DNS] Server %d failed: %v", res.idx, res.err)
			if firstErr == nil {
				firstErr = res.err
			}
			// A server that already said no is not worth waiting the stagger
			// out for: bring the next one forward.
			if started < len(servers) {
				hedge.Stop()
				hedge.Reset(0)
			}
		}
	}

	return "", fmt.Errorf("all DNS servers failed for %s: %w", domain, firstErr)
}

// resolveAny resolves DNS using the specified server
func resolveAny(ctx context.Context, domain string, server DNSServer) (string, error) {
	switch server.Type {
	case DNSPlain:
		return resolveUDPWithServer(ctx, domain, server.IP)
	case DNSDoH:
		return resolveDoHWithServer(ctx, domain, server.IP, server.Domain)
	case DNSDoT:
		return resolveDoTWithServer(ctx, domain, server.IP, server.Domain)
	default:
		return "", fmt.Errorf("unknown DNS server type: %v", server.Type)
	}
}

// resolveUDPWithServer resolves DNS via standard UDP query to specified server
func resolveUDPWithServer(ctx context.Context, domain string, serverIP string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	// Build DNS query (A record)
	query, err := buildDNSQuery(domain)
	if err != nil {
		return "", err
	}

	// Use DialContext with protectControl (same as old protectedResolver).
	// JoinHostPort brackets IPv6 (incl. link-local with a %zone, e.g. a
	// hotspot-supplied fe80::…%wlan0), avoiding "too many colons in address".
	addr := net.JoinHostPort(serverIP, "53")
	dialer := &net.Dialer{
		Timeout: dnsTimeout,
		Control: protectControl,
	}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	// The read below blocks on its deadline, not on ctx, so a query that lost
	// the hedged race would otherwise sit on a protected fd for the rest of its
	// timeout. Closing on cancellation makes it return at once. The goroutine
	// always ends: this function's own deadline fires the ctx if nothing else
	// does, and cancel() runs on return.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	// Send query
	conn.SetDeadline(time.Now().Add(dnsTimeout))
	_, err = conn.Write(query)
	if err != nil {
		return "", fmt.Errorf("failed to send DNS query: %w", err)
	}

	// Read response
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("failed to read DNS response: %w", err)
	}

	// Parse response
	ip, err := parseDNSResponse(response[:n], domain)
	if err != nil {
		return "", err
	}

	return ip, nil
}

// resolveDoHWithServer resolves DNS via DNS-over-HTTPS to specified server
func resolveDoHWithServer(ctx context.Context, domain string, serverIP string, serverName string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dohTimeout)
	defer cancel()

	query, err := buildDNSQuery(domain)
	if err != nil {
		return "", err
	}

	// Build HTTP request with IP directly (no DNS resolution needed)
	// DoH uses port 443. JoinHostPort brackets IPv6 hosts for the URL.
	addr := net.JoinHostPort(serverIP, "443")
	ipURL := "https://" + addr + "/dns-query"
	req, err := http.NewRequestWithContext(ctx, "POST", ipURL, bytes.NewReader(query))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Host = serverName

	// DoH requires HTTP/2 per RFC 8484
	client := &http.Client{
		Timeout: dohTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return protectAndDial(ctx, network, net.JoinHostPort(serverIP, "443"))
			},
			TLSClientConfig: &tls.Config{
				ServerName: serverName,
				NextProtos: []string{"h2", "http/1.1"},
			},
			ForceAttemptHTTP2: true,
		},
	}
	// The client is per-request; without this the pooled TLS connection (and
	// its read/write goroutines) would linger until the server hangs up —
	// there is no IdleConnTimeout on this throwaway transport.
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	ip, err := parseDNSResponse(body, domain)
	if err != nil {
		return "", err
	}

	return ip, nil
}

// resolveDoTWithServer resolves DNS via DNS-over-TLS to specified server
func resolveDoTWithServer(ctx context.Context, domain string, serverIP string, serverName string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dotTimeout)
	defer cancel()

	query, err := buildDNSQuery(domain)
	if err != nil {
		return "", err
	}

	tlsConfig := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}

	// DoT uses port 853
	tcpConn, err := protectAndDial(ctx, "tcp", net.JoinHostPort(serverIP, "853"))
	if err != nil {
		return "", fmt.Errorf("failed to connect to DoT server: %w", err)
	}
	defer tcpConn.Close()

	// Same reason as the UDP path: the handshake and reads below run on
	// deadlines, so a loser of the hedged race needs the socket pulled out from
	// under it to stop early.
	go func() {
		<-ctx.Done()
		tcpConn.Close()
	}()

	tlsConn := tls.Client(tcpConn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(dotTimeout))

	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		return "", fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Send DNS query with 2-byte length prefix (DoT protocol)
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(query)))

	_, err = tlsConn.Write(append(lengthPrefix, query...))
	if err != nil {
		return "", fmt.Errorf("failed to send DoT query: %w", err)
	}

	// Read response length
	lengthBuf := make([]byte, 2)
	_, err = io.ReadFull(tlsConn, lengthBuf)
	if err != nil {
		return "", fmt.Errorf("failed to read DoT response length: %w", err)
	}

	responseLen := binary.BigEndian.Uint16(lengthBuf)
	response := make([]byte, responseLen)
	_, err = io.ReadFull(tlsConn, response)
	if err != nil {
		return "", fmt.Errorf("failed to read DoT response: %w", err)
	}

	ip, err := parseDNSResponse(response, domain)
	if err != nil {
		return "", err
	}

	return ip, nil
}

// buildDNSQuery builds DNS query for A record
func buildDNSQuery(domain string) ([]byte, error) {
	query := make([]byte, 12)

	// Random ID
	binary.BigEndian.PutUint16(query[0:2], uint16(time.Now().UnixNano()&0xFFFF))

	// Flags: standard recursive query
	binary.BigEndian.PutUint16(query[2:4], 0x0100)

	// QDCOUNT = 1
	binary.BigEndian.PutUint16(query[4:6], 1)

	// Encode domain name
	var nameBuf bytes.Buffer
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for _, part := range parts {
		nameBuf.WriteByte(byte(len(part)))
		nameBuf.WriteString(part)
	}
	nameBuf.WriteByte(0) // End of domain

	// QTYPE = A (1), QCLASS = IN (1)
	nameBuf.WriteByte(0)
	nameBuf.WriteByte(1)
	nameBuf.WriteByte(0)
	nameBuf.WriteByte(1)

	return append(query, nameBuf.Bytes()...), nil
}

// parseDNSResponse parses DNS response and extracts A record
func parseDNSResponse(response []byte, domain string) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("DNS response too short")
	}

	// Check response flag
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 {
		return "", fmt.Errorf("not a DNS response")
	}

	// Check response code
	rcode := flags & 0x000F
	if rcode != 0 {
		return "", fmt.Errorf("DNS error: rcode=%d", rcode)
	}

	// Get answer count
	ansCount := binary.BigEndian.Uint16(response[6:8])
	if ansCount == 0 {
		return "", fmt.Errorf("no answers in DNS response")
	}

	// Skip question section
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		labelLen := int(response[offset])
		if labelLen == 0 || labelLen > 63 {
			break
		}
		offset += labelLen + 1
	}
	offset += 5 // Null byte + QTYPE (2) + QCLASS (2)

	// Read answers
	for i := 0; i < int(ansCount) && offset < len(response); i++ {
		// Skip name (may have compression pointer)
		nameSkipped := false
		for offset < len(response) && response[offset] != 0 {
			labelLen := int(response[offset])
			if labelLen > 63 {
				offset += 2 // Compression pointer (2 bytes)
				nameSkipped = true
				break
			}
			offset += labelLen + 1
		}
		// Skip null terminator only if name wasn't a compression pointer
		if !nameSkipped && offset < len(response) && response[offset] == 0 {
			offset++
		}
		if offset >= len(response)-10 {
			break
		}

		qtype := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2 // TYPE
		offset += 2 // CLASS
		offset += 4 // TTL
		rdLength := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2

		// Check if this is A record (TYPE=1, length=4)
		if qtype == 1 && rdLength == 4 && offset+4 <= len(response) {
			ip := fmt.Sprintf("%d.%d.%d.%d",
				response[offset],
				response[offset+1],
				response[offset+2],
				response[offset+3])
			return ip, nil
		}

		offset += int(rdLength)
	}

	return "", fmt.Errorf("no A record found in DNS response")
}

// protectAndDial creates TCP connection and protects it via Control callback
func protectAndDial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   protectControl, // Protects socket before connect()
	}

	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// ClearCache clears DNS cache and resets last successful server index
func ClearCache() {
	hostCache.mu.Lock()
	defer hostCache.mu.Unlock()
	hostCache.ips = make(map[string]string)
	lastSuccessfulMu.Lock()
	lastSuccessfulIndex = 0
	lastSuccessfulMu.Unlock()
	turnLog("[DNS] Cache cleared")
}

// init initializes dnsServers to predefined list if InitSystemDns was not called
func init() {
	dnsServers = dnsServersPredefined
}

// InitSystemDns sets up the active DNS server list by prepending the given
// system DNS servers to the predefined list (Yandex + Google).
// It should be called once at proxy startup.
func InitSystemDns(servers []string) {
	var systemDns []DNSServer
	for _, ip := range servers {
		systemDns = append(systemDns, DNSServer{
			Type: DNSPlain,
			IP:   ip,
		})
	}
	dnsServers = append(systemDns, dnsServersPredefined...)
	turnLog("[DNS] Initialized: %d system + %d predefined = %d total",
		len(systemDns), len(dnsServersPredefined), len(dnsServers))
}
