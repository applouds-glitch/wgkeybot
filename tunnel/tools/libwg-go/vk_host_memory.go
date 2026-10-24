/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// VK's API addresses from the last time they connected, for a network whose DNS
// answers nobody.
//
// Field log 23.10 (Pixel, Wi-Fi): the network carried the relays — a tunnel on
// cached credentials came up in 1.4s — but no resolver answered, not over plain
// DNS, DoH or DoT, at 21:41 and again at 22:47 (DoH to Yandex had at 21:52).
// Without a credential nothing could start: every fetch spent its 30s on DNS and
// the start ended "VK unreachable". The addresses the captcha-free flow had
// connected to an hour earlier would have done; the DNS cache that held them is
// emptied on every start (clearTransientState) and every move to another
// network.
//
// So the flow's hosts keep the addresses that connected, in memory and in a file
// beside turn_creds.json, and dialVKHost dials them when a lookup reached no
// resolver at all (dialRememberedVKHost). Only then: a name a resolver answered
// for, even with an error, is the answer's. Only the captcha-free flow's hosts:
// login.vk.ru and api.vk.ru open the legacy chain and its captcha, and a DNS that
// answers nobody stays a reason not to go there (vkLegacyHostResolves). And when
// none of the addresses connects, the caller gets the lookup's failure as it was
// — our own network (ownNetworkFailure) — so on a network that carries nothing
// the early -5 and the legacy fallback stay what they were. The same holds for an
// address that takes the connection and then says nothing: silence is VK's only
// on a network that answers DNS (ownNetworkFailure), and this one does not
// (silentOverRemembered).

// vkCallsOKHostName is the host of vkCallsOKHost.
const vkCallsOKHostName = "calls.okcdn.ru"

// vkRememberedHosts are the hosts whose addresses are kept: the captcha-free
// flow's, and nothing that leads to a captcha.
var vkRememberedHosts = map[string]bool{
	vkCallsAPIHost:    true,
	vkCallsOKHostName: true,
}

const (
	vkHostMemoryFileName    = "vk_hosts.json"
	vkHostMemoryFileVersion = 1

	// vkRememberedAddrsMax bounds what is kept per host, and with it the walk
	// over a network that carries nothing: at vkDialHeadStart apart, four
	// addresses have all been started 3.6s in.
	vkRememberedAddrsMax = 4

	// vkRememberedMaxAge: addresses that have not connected for this long are
	// not dialled. VK's API addresses hold for far longer; the bound is for a
	// phone that has been somewhere else for a month.
	vkRememberedMaxAge = 30 * 24 * time.Hour

	// vkRememberedRewriteAfter: an unchanged list is written again only to move
	// its date, at most this often.
	vkRememberedRewriteAfter = 24 * time.Hour
)

// vkRememberedDialTimeout bounds the whole walk over the remembered addresses,
// a var so that a test can shrink it. VK took a connect in ~0.4s over the Wi-Fi
// of the field log; on a network that carries nothing every attempt of the flow
// pays this on top of the lookup's ~4s, instead of the 20s of a VK connect
// (getCustomNetDialer), which would have stretched the own-network verdict.
var vkRememberedDialTimeout = 5 * time.Second

type vkRememberedAddrs struct {
	IPs         []string `json:"ips"`
	ConnectedMs int64    `json:"connected_ms"` // Unix milliseconds of the last connect
}

type vkHostMemoryFile struct {
	Version int                          `json:"v"`
	Hosts   map[string]vkRememberedAddrs `json:"hosts"`
}

// vkHostMemory holds the remembered addresses. loadedFrom is the file they were
// read from: empty until a state dir is known (wgSetStateDir), so a dial before
// that reads the file at the next one. written is when this process last wrote
// it — not the date of the newest connect, which moves on every one.
var vkHostMemory = struct {
	sync.Mutex
	loadedFrom string
	written    time.Time
	hosts      map[string]vkRememberedAddrs
}{hosts: map[string]vkRememberedAddrs{}}

func vkHostMemoryPath() string {
	dir := stateDirPath()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, vkHostMemoryFileName)
}

// loadVKHostMemoryLocked takes in the file the first time its path is known. An
// address remembered in this process before that wins over the file's when it
// is the newer. Nothing in the file can stop a dial: missing or unreadable, it
// leaves the memory as it is.
func loadVKHostMemoryLocked(path string) {
	if path == "" || vkHostMemory.loadedFrom == path {
		return
	}
	vkHostMemory.loadedFrom = path
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var f vkHostMemoryFile
	if json.Unmarshal(data, &f) != nil || f.Version != vkHostMemoryFileVersion {
		return
	}
	for host, entry := range f.Hosts {
		if !vkRememberedHosts[host] || len(entry.IPs) == 0 {
			continue
		}
		if cur, ok := vkHostMemory.hosts[host]; !ok || entry.ConnectedMs > cur.ConnectedMs {
			vkHostMemory.hosts[host] = vkRememberedAddrs{IPs: limitVKAddrs(entry.IPs), ConnectedMs: entry.ConnectedMs}
		}
	}
}

func limitVKAddrs(ips []string) []string {
	if len(ips) > vkRememberedAddrsMax {
		ips = ips[:vkRememberedAddrsMax]
	}
	return append([]string(nil), ips...)
}

// rememberedVKAddrs is what host last connected on, or nil when it never did or
// not for vkRememberedMaxAge.
func rememberedVKAddrs(host string, now time.Time) []string {
	if !vkRememberedHosts[host] {
		return nil
	}
	vkHostMemory.Lock()
	defer vkHostMemory.Unlock()
	loadVKHostMemoryLocked(vkHostMemoryPath())
	entry, ok := vkHostMemory.hosts[host]
	if !ok || now.Sub(time.UnixMilli(entry.ConnectedMs)) > vkRememberedMaxAge {
		return nil
	}
	return append([]string(nil), entry.IPs...)
}

// rememberVKAddrs records that host has just connected on ips[0], the rest of
// ips being its other addresses in the order to try them. The file is written
// when the list changed, or to move the dates once a vkRememberedRewriteAfter
// since this process last wrote it.
func rememberVKAddrs(host string, ips []string, now time.Time) {
	if !vkRememberedHosts[host] || len(ips) == 0 {
		return
	}
	ips = limitVKAddrs(ips)
	vkHostMemory.Lock()
	defer vkHostMemory.Unlock()
	path := vkHostMemoryPath()
	loadVKHostMemoryLocked(path)
	prev, had := vkHostMemory.hosts[host]
	vkHostMemory.hosts[host] = vkRememberedAddrs{IPs: ips, ConnectedMs: now.UnixMilli()}
	if had && slices.Equal(prev.IPs, ips) && now.Sub(vkHostMemory.written) < vkRememberedRewriteAfter {
		return
	}
	saveVKHostMemoryLocked(path, now)
}

// saveVKHostMemoryLocked writes the memory to path. Under the lock: a handful of
// bytes, a few times per credential fetch, and the last write is then also the
// newest.
func saveVKHostMemoryLocked(path string, now time.Time) {
	if path == "" {
		return
	}
	data, err := json.Marshal(vkHostMemoryFile{Version: vkHostMemoryFileVersion, Hosts: vkHostMemory.hosts})
	if err == nil {
		err = replaceFile(path, data)
	}
	if err != nil {
		turnLog("[VK Dial] remembered addresses not saved: %v", err)
		return
	}
	vkHostMemory.written = now
}

// connectedFirst is the order to remember a host's addresses in after a connect
// on ip: ip, then the others the dial did not set aside, then those it did.
func connectedFirst(ip string, ips, setAside []string) []string {
	out := []string{ip}
	for _, other := range ips {
		if other != ip && !slices.Contains(setAside, other) {
			out = append(out, other)
		}
	}
	for _, other := range setAside {
		if other != ip && !slices.Contains(out, other) {
			out = append(out, other)
		}
	}
	return out
}

// rememberedDialsOf reads the count of connections client made on addresses
// from memory (vkAPIClient). Per client, not per process: the HTTP/2 dial of
// the VK client carries none of the request's context, so the count rides on
// the client, and another fetch's or the link check's connections are not this
// flow's — a process-wide count let them cut this flow's counted attempts short
// (Codex review 23.10). A client that keeps no count reads as none.
func rememberedDialsOf(client any) func() uint64 {
	if c, ok := client.(interface{ rememberedDials() uint64 }); ok {
		return c.rememberedDials
	}
	return func() uint64 { return 0 }
}

// silentOverRemembered reports whether an attempt that got no response at all
// (errVKCallsNoResponse) belongs to a flow that has, since its snapshot, gone
// out over an address from memory — the snapshot is the flow's, since the
// client pools connections across attempts. Then the network answered no resolver, and the silence after the
// connect is no more VK's than the lookup's failure would have been: the attempt
// is our network's, as it was before there were addresses to dial — retried
// within the own-network budget, ending in errVKCallsOwnNetwork, which keeps the
// early -5 and the guard on the legacy chain (Codex review 23.10). An attempt VK
// answered, even with an error, stays VK's.
func silentOverRemembered(err error, rememberedAtStart, rememberedNow uint64) bool {
	return errors.Is(err, errVKCallsNoResponse) && rememberedNow != rememberedAtStart
}

// setAsideRememberedVKAddr moves ip to the tail of host's remembered addresses:
// it took a connection and never answered. Written at once: the next connect,
// on the address now first, brings the same order and would see nothing to
// write, and the next process would open with the silent address again (Codex
// review 23.10).
func setAsideRememberedVKAddr(host, ip string) {
	vkHostMemory.Lock()
	defer vkHostMemory.Unlock()
	path := vkHostMemoryPath()
	loadVKHostMemoryLocked(path)
	entry, ok := vkHostMemory.hosts[host]
	if !ok || !slices.Contains(entry.IPs, ip) {
		return
	}
	out := make([]string, 0, len(entry.IPs))
	for _, other := range entry.IPs {
		if other != ip {
			out = append(out, other)
		}
	}
	entry.IPs = append(out, ip)
	vkHostMemory.hosts[host] = entry
	saveVKHostMemoryLocked(path, time.Now())
}
