/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Dialling VK's API hosts over every address they resolve to.
//
// The dial used to take the one address the DNS cache held — the first A record
// of whichever answer came first — and give it 20s. api.vk.ru answers with nine
// addresses in rotating order, and a mobile whitelist is a list of subnets that
// does not cover all of them: of the nine seen on 2026-09-19, 87.240.129.140
// sits in a /24 the public copies of the whitelist do not carry, while its
// neighbours do. An operator filtering at L3 drops the SYN without a word, so
// every request to VK — credentials, captcha — hung for 20s and failed, on an
// address the cache then kept until the proxy restarted. Other clients of the
// same relays broke the same way on a DNS detail (WDTT 1.1.8: "lookup
// login.vk.ru" behind a hard-coded resolver).
//
// Two kinds of filter have to be survived, and they fail differently:
//
//   - L3 (MTS, MegaFon): the SYN is dropped. The connect never completes, so the
//     addresses are raced — see vkDialHeadStart.
//   - L7 (Beeline, 2025): the SYN passes and the ClientHello is cut. The connect
//     succeeds and proves nothing, so an address whose connection closes
//     without a single byte read is set aside as well — see heardConn.
//
// Neither filter is told apart from a slow address, and neither needs to be:
// all this code ever does to an address is move it within the list.

// vkDialHeadStart is how long an address keeps the dial to itself before the
// next one joins. A blackholed SYN gives no error to react to, only silence;
// the kernel retransmits it after 1s, so 1.2s leaves a healthy address room to
// lose one SYN and still win, and costs a dead one little more than a second —
// once, because the address that outruns it moves ahead of it. Racing costs
// nothing here, unlike TURN Allocate (relayHeadStart): an abandoned TCP connect
// leaves nothing behind on the server.
const vkDialHeadStart = 1200 * time.Millisecond

type vkDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type vkDialResult struct {
	ip   string
	conn net.Conn
	err  error
}

// dialFirstReachable connects to the first of ips that answers, giving each a
// head start over the next and bringing the next forward at once when one
// fails outright. It returns the connection, the address it is on, and the
// addresses to set aside: those that failed, and those started before the
// winner that it outran. A dial cut short by ctx is evidence of nothing and is
// never set aside.
func dialFirstReachable(ctx context.Context, network, port string, ips []string, dial vkDialFunc) (net.Conn, string, []string, error) {
	if len(ips) == 0 {
		return nil, "", nil, errors.New("no addresses to dial")
	}

	ctx, cancel := context.WithCancel(ctx)
	results := make(chan vkDialResult, len(ips))
	// Fires immediately: the first address starts without waiting a head start.
	next := time.NewTimer(0)
	defer next.Stop()

	var (
		started  int
		finished int
		pending  = make(map[string]bool, len(ips))
		failed   []string
		firstErr error
	)
	// Whatever is still dialling when this returns must not leak a connection:
	// cancel aborts the dials, and a connect that completed in the meantime is
	// closed here.
	defer func() {
		cancel()
		if left := started - finished; left > 0 {
			go func() {
				for ; left > 0; left-- {
					if res := <-results; res.conn != nil {
						res.conn.Close()
					}
				}
			}()
		}
	}()

	for finished < len(ips) {
		var nextAddr <-chan time.Time
		if started < len(ips) {
			nextAddr = next.C
		}

		select {
		case <-ctx.Done():
			return nil, "", failed, ctx.Err()

		case <-nextAddr:
			ip := ips[started]
			started++
			pending[ip] = true
			go func() {
				conn, err := dial(ctx, network, net.JoinHostPort(ip, port))
				results <- vkDialResult{ip: ip, conn: conn, err: err}
			}()
			if started < len(ips) {
				next.Reset(vkDialHeadStart)
			}

		case res := <-results:
			finished++
			delete(pending, res.ip)
			if res.err == nil {
				// What is still pending and was started before the winner had its
				// head start and lost anyway. An address started after the winner
				// has simply had less time, and keeps its place.
				outrun := failed
				for _, ip := range ips[:started] {
					if ip == res.ip {
						break
					}
					if pending[ip] {
						outrun = append(outrun, ip)
					}
				}
				return res.conn, res.ip, outrun, nil
			}
			if ctx.Err() != nil {
				return nil, "", failed, ctx.Err()
			}
			failed = append(failed, res.ip)
			if firstErr == nil {
				firstErr = res.err
			}
			// An address that already said no is not worth waiting the head
			// start out for: bring the next one forward.
			if started < len(ips) {
				next.Stop()
				next.Reset(0)
			}
		}
	}

	return nil, "", failed, firstErr
}

// heardConn notices a connection that is closed without a single byte having
// come back over it, and reports that once. A TCP connect that completes says
// the address is routable and nothing about whether the path carries a TLS
// session — behind an L7 filter it does not.
type heardConn struct {
	net.Conn
	heard    atomic.Bool
	closed   sync.Once
	onSilent func()
}

func (c *heardConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.heard.Store(true)
	}
	return n, err
}

func (c *heardConn) Close() error {
	c.closed.Do(func() {
		if !c.heard.Load() {
			c.onSilent()
		}
	})
	return c.Conn.Close()
}

// dialVKHost is the VK HTTP client's DialContext: host resolved through cache,
// every address tried, and the cache reordered by the outcome.
func dialVKHost(ctx context.Context, cache *DnsCache, network, addr string, dial vkDialFunc) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}
	if net.ParseIP(host) != nil {
		return dial(ctx, network, net.JoinHostPort(host, port))
	}

	ips, err := cache.ResolveAll(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	conn, ip, setAside, err := dialFirstReachable(ctx, network, port, ips, dial)
	for _, bad := range setAside {
		cache.SetAside(host, bad)
	}
	if err != nil {
		// Not one address connected. Unless that was our own cancellation, drop
		// the answer: the next dial asks again instead of walking a list that
		// has just failed whole.
		if ctx.Err() == nil {
			cache.Forget(host)
			turnLog("[VK Dial] %s: none of %s connected (%v) — will resolve again", host, strings.Join(ips, ", "), err)
		}
		return nil, err
	}
	if len(setAside) > 0 {
		turnLog("[VK Dial] %s: connected to %s; set aside %s", host, ip, strings.Join(setAside, ", "))
	}

	// The winner needs no promoting: everything dialled ahead of it has just
	// been set aside, so it already heads the list.
	return &heardConn{
		Conn: conn,
		onSilent: func() {
			cache.SetAside(host, ip)
			turnLog("[VK Dial] %s: %s took the connection and never answered — set aside", host, ip)
		},
	}, nil
}
