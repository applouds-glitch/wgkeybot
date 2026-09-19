/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// dnsAnswerWithCNAME builds a response to an A query for name: a CNAME first, the way
// internal.api.vk.ru answers, then the A records.
func dnsAnswerWithCNAME(name string, addrs ...[4]byte) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(addrs)+1))

	q, _ := buildDNSQuery(name)
	msg = append(msg, q[12:]...)

	rr := func(rtype uint16, rdata []byte) {
		msg = append(msg, 0xC0, 0x0C) // pointer to the question name
		var fixed [10]byte
		binary.BigEndian.PutUint16(fixed[0:2], rtype)
		binary.BigEndian.PutUint16(fixed[2:4], 1)
		binary.BigEndian.PutUint32(fixed[4:8], 60)
		binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rdata)))
		msg = append(msg, fixed[:]...)
		msg = append(msg, rdata...)
	}
	rr(5, []byte{3, 'a', 'p', 'i', 0xC0, 0x0C})
	for _, a := range addrs {
		rr(1, a[:])
	}
	return msg
}

// The whole point of the change: the second and later A records used to be
// thrown away at the parser.
func TestParseDNSResponseReturnsEveryARecord(t *testing.T) {
	resp := dnsAnswerWithCNAME("api.vk.ru",
		[4]byte{87, 240, 129, 140}, [4]byte{87, 240, 137, 206}, [4]byte{93, 186, 225, 205})

	got, err := parseDNSResponse(resp, "api.vk.ru")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := []string{"87.240.129.140", "87.240.137.206", "93.186.225.205"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// fakeDialer answers per address: a connection, an error, or silence until the
// dial is cancelled — what a blackholed SYN looks like from here.
type fakeDialer struct {
	mu      sync.Mutex
	dialled []string
	refuse  map[string]error
	silent  map[string]bool
	delay   map[string]time.Duration
	// ignoreCancel makes an address finish its connect even after the dial was
	// cancelled, the way a SYN-ACK already on the wire does.
	ignoreCancel map[string]bool
	conns        map[string]*recordingConn
}

type recordingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *recordingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (d *fakeDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	ip, _, _ := net.SplitHostPort(addr)
	d.mu.Lock()
	d.dialled = append(d.dialled, ip)
	d.mu.Unlock()

	if err := d.refuse[ip]; err != nil {
		return nil, err
	}
	if d.silent[ip] {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if wait := d.delay[ip]; wait > 0 {
		if d.ignoreCancel[ip] {
			time.Sleep(wait)
		} else {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	local, remote := net.Pipe()
	go func() { // the far end: says one word when spoken to
		buf := make([]byte, 1)
		if _, err := remote.Read(buf); err == nil {
			remote.Write([]byte{1})
		}
		remote.Close()
	}()
	conn := &recordingConn{Conn: local}
	d.mu.Lock()
	if d.conns == nil {
		d.conns = map[string]*recordingConn{}
	}
	d.conns[ip] = conn
	d.mu.Unlock()
	return conn, nil
}

func (d *fakeDialer) dialledAddrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialled...)
}

func cacheWith(host string, ips ...string) *DnsCache {
	return &DnsCache{
		ips:      map[string][]string{host: ips},
		inflight: make(map[string]*dnsLookup),
	}
}

func (c *DnsCache) snapshot(host string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.ips[host]...)
}

// The healthy case must cost what it always did: one connect to one address.
func TestDialLeavesAnAnsweringAddressAlone(t *testing.T) {
	d := &fakeDialer{}
	conn, ip, setAside, err := dialFirstReachable(context.Background(), "tcp", "443",
		[]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, d.dial)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if ip != "10.0.0.1" || len(setAside) != 0 {
		t.Fatalf("won on %s, set aside %v; want 10.0.0.1 and nothing", ip, setAside)
	}
	if got := d.dialledAddrs(); len(got) != 1 {
		t.Fatalf("an answering first address was raced: dialled %v", got)
	}
}

// A blackholed address gives no error to react to. The next one must join after
// the head start — not before it, and not after the 20s the dial used to spend.
func TestDialRacesPastASilentAddress(t *testing.T) {
	d := &fakeDialer{silent: map[string]bool{"10.0.0.1": true}}

	start := time.Now()
	conn, ip, setAside, err := dialFirstReachable(context.Background(), "tcp", "443",
		[]string{"10.0.0.1", "10.0.0.2"}, d.dial)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if ip != "10.0.0.2" {
		t.Fatalf("won on %s, want the address that answers", ip)
	}
	if !reflect.DeepEqual(setAside, []string{"10.0.0.1"}) {
		t.Fatalf("set aside %v, want the address that was outrun", setAside)
	}
	if elapsed+time.Millisecond < vkDialHeadStart {
		t.Fatalf("second address joined after %v, before the %v head start", elapsed, vkDialHeadStart)
	}
	if elapsed > 2*vkDialHeadStart {
		t.Fatalf("the silent address held the dial for %v", elapsed)
	}
}

// An address that refuses has answered; the head start is for silence only.
func TestDialBringsTheNextAddressForwardOnRefusal(t *testing.T) {
	d := &fakeDialer{refuse: map[string]error{
		"10.0.0.1": errors.New("connection refused"),
		"10.0.0.2": errors.New("network is unreachable"),
	}}

	start := time.Now()
	conn, ip, setAside, err := dialFirstReachable(context.Background(), "tcp", "443",
		[]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, d.dial)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if ip != "10.0.0.3" {
		t.Fatalf("won on %s, want the third address", ip)
	}
	if !reflect.DeepEqual(setAside, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("set aside %v, want both refusals", setAside)
	}
	if elapsed >= vkDialHeadStart {
		t.Fatalf("two instant refusals took %v — the next address waited out the head start", elapsed)
	}
}

func TestDialReportsTotalFailure(t *testing.T) {
	refused := errors.New("connection refused")
	d := &fakeDialer{refuse: map[string]error{"10.0.0.1": refused, "10.0.0.2": refused}}

	_, _, setAside, err := dialFirstReachable(context.Background(), "tcp", "443",
		[]string{"10.0.0.1", "10.0.0.2"}, d.dial)
	if !errors.Is(err, refused) {
		t.Fatalf("got %v, want the cause", err)
	}
	if len(setAside) != 2 {
		t.Fatalf("set aside %v, want both", setAside)
	}
}

// A connect that completes after the race is decided must not leak: nobody is
// left to use it, so it is closed.
func TestDialClosesAConnectionThatLostTheRace(t *testing.T) {
	late := vkDialHeadStart + 150*time.Millisecond
	d := &fakeDialer{
		// The first address wins just after the second has started; the second
		// completes its connect regardless, a little later.
		delay:        map[string]time.Duration{"10.0.0.1": vkDialHeadStart + 50*time.Millisecond, "10.0.0.2": 150 * time.Millisecond},
		ignoreCancel: map[string]bool{"10.0.0.2": true},
	}

	conn, ip, setAside, err := dialFirstReachable(context.Background(), "tcp", "443",
		[]string{"10.0.0.1", "10.0.0.2"}, d.dial)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	if ip != "10.0.0.1" {
		t.Fatalf("won on %s, want the first address", ip)
	}
	// The second address started after the winner: it has had less time, not
	// lost a head start, so it keeps its place.
	if len(setAside) != 0 {
		t.Fatalf("set aside %v, want nothing", setAside)
	}

	deadline := time.Now().Add(late + time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		loser := d.conns["10.0.0.2"]
		d.mu.Unlock()
		if loser != nil && loser.closed.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the connection that lost the race was never closed")
}

// Our own cancellation says nothing about the addresses: none is set aside, and
// the cached answer stays.
func TestCancelledDialBlamesNoAddress(t *testing.T) {
	d := &fakeDialer{silent: map[string]bool{"10.0.0.1": true, "10.0.0.2": true}}
	cache := cacheWith("api.vk.ru", "10.0.0.1", "10.0.0.2")

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	if _, err := dialVKHost(ctx, cache, "tcp", "api.vk.ru:443", d.dial); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want the cancellation", err)
	}
	if got := cache.snapshot("api.vk.ru"); !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("a cancelled dial reordered the cache: %v", got)
	}
}

// What the session looked like behind an L3 whitelist: the address that opens
// the answer never answers. The first dial pays one head start for it; the
// second must not pay again.
func TestVKDialSetsASilentAddressAsideForTheNextDial(t *testing.T) {
	d := &fakeDialer{silent: map[string]bool{"87.240.129.140": true}}
	cache := cacheWith("api.vk.ru", "87.240.129.140", "87.240.137.206", "93.186.225.205")

	conn, err := dialVKHost(context.Background(), cache, "tcp", "api.vk.ru:443", d.dial)
	if err != nil {
		t.Fatalf("first dial failed: %v", err)
	}
	conn.Write([]byte{0})
	conn.Read(make([]byte, 1))
	conn.Close()

	want := []string{"87.240.137.206", "93.186.225.205", "87.240.129.140"}
	if got := cache.snapshot("api.vk.ru"); !reflect.DeepEqual(got, want) {
		t.Fatalf("cache order %v, want %v", got, want)
	}

	start := time.Now()
	conn, err = dialVKHost(context.Background(), cache, "tcp", "api.vk.ru:443", d.dial)
	if err != nil {
		t.Fatalf("second dial failed: %v", err)
	}
	conn.Write([]byte{0})
	conn.Read(make([]byte, 1))
	conn.Close()
	if elapsed := time.Since(start); elapsed >= vkDialHeadStart {
		t.Fatalf("the second dial took %v — it opened with the silent address again", elapsed)
	}
	if got := cache.snapshot("api.vk.ru"); !reflect.DeepEqual(got, want) {
		t.Fatalf("a connection that answered was reordered: %v", got)
	}
}

// Behind an L7 filter the connect succeeds and the ClientHello is cut: the
// address "wins" every race and never carries a byte. Closing such a connection
// is what moves it out of the way.
func TestVKDialSetsAsideAnAddressThatConnectsAndNeverAnswers(t *testing.T) {
	d := &fakeDialer{}
	cache := cacheWith("api.vk.ru", "10.0.0.1", "10.0.0.2")

	conn, err := dialVKHost(context.Background(), cache, "tcp", "api.vk.ru:443", d.dial)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	conn.Close() // the request timed out with nothing read
	conn.Close() // and a second Close must not count twice

	if got := cache.snapshot("api.vk.ru"); !reflect.DeepEqual(got, []string{"10.0.0.2", "10.0.0.1"}) {
		t.Fatalf("cache order %v, want the mute address last", got)
	}
}

// Every address failing means the answer is no use as it stands: the next dial
// has to ask DNS again rather than walk the same list.
func TestVKDialForgetsAnAnswerNoneOfWhichConnects(t *testing.T) {
	refused := errors.New("connection refused")
	d := &fakeDialer{refuse: map[string]error{"10.0.0.1": refused, "10.0.0.2": refused}}
	cache := cacheWith("api.vk.ru", "10.0.0.1", "10.0.0.2")

	if _, err := dialVKHost(context.Background(), cache, "tcp", "api.vk.ru:443", d.dial); err == nil {
		t.Fatal("expected an error")
	}
	if got := cache.snapshot("api.vk.ru"); len(got) != 0 {
		t.Fatalf("a wholly failed answer stayed cached: %v", got)
	}
}

// Resolve is what the TURN side uses; it follows the same order.
func TestResolveReturnsThePreferredAddress(t *testing.T) {
	cache := cacheWith("relay.example", "10.0.0.1", "10.0.0.2")
	cache.SetAside("relay.example", "10.0.0.1")
	cache.SetAside("relay.example", "10.9.9.9") // not in the answer: ignored

	ip, err := cache.Resolve(context.Background(), "relay.example")
	if err != nil || ip != "10.0.0.2" {
		t.Fatalf("got %q, %v; want 10.0.0.2", ip, err)
	}
	if got := cache.snapshot("relay.example"); len(got) != 2 {
		t.Fatalf("an unknown address was added: %v", got)
	}
}
