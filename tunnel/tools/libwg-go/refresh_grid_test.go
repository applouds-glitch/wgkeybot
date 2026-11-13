/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// The three transactions on the stream's own ticks: each goes out at the last
// tick inside its interval, whatever the phase of the session's start against
// the grid — never past the interval, never a whole tick early.
func TestRefreshDueOnGridPicksTheLastTickInsideTheInterval(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval time.Duration
		at       time.Duration // from a tick: the tick it goes out at
	}{
		{"allocation, half of VK's 600 s", 300 * time.Second, 275 * time.Second},
		{"permissions", 240 * time.Second, 225 * time.Second},
		{"binding check", 30 * time.Second, 25 * time.Second},
		{"shorter than the grid: every tick", 10 * time.Second, 25 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for age := keepaliveInterval; ; age += keepaliveInterval {
				if refreshDueOnGrid(age, tc.interval, keepaliveInterval) {
					if age != tc.at {
						t.Fatalf("goes out %v after the last, want %v", age, tc.at)
					}
					break
				}
				if age > tc.interval {
					t.Fatalf("not out by %v, past the interval", age)
				}
			}
			if tc.interval < keepaliveInterval {
				return
			}
			// The first one of a session is counted from the Allocate, which
			// falls anywhere between two ticks.
			for first := time.Duration(0); first < keepaliveInterval; first += 500 * time.Millisecond {
				age := first
				for !refreshDueOnGrid(age, tc.interval, keepaliveInterval) {
					age += keepaliveInterval
				}
				if age > tc.interval {
					t.Fatalf("first tick %v after the Allocate: out at %v, past pion's %v", first, age, tc.interval)
				}
				if early := tc.interval - age; early > keepaliveInterval+keepaliveSpread {
					t.Fatalf("first tick %v after the Allocate: out %v early, more than a tick", first, early)
				}
			}
		})
	}
}

// fakeRefresh is a transaction that counts its runs; hold makes each run wait
// for a release, as pion's handler waits for its answer.
type fakeRefresh struct {
	runs atomic.Int32
	hold chan struct{}
}

func (f *fakeRefresh) refresh(name string, interval time.Duration) *gridRefresh {
	return &gridRefresh{name: name, interval: interval, run: func() {
		f.runs.Add(1)
		if f.hold != nil {
			<-f.hold
		}
	}}
}

func TestRefreshGridSendsOnTheTickWhatIsDue(t *testing.T) {
	var alloc, perms fakeRefresh
	start := time.Now()
	g := newRefreshGrid(1, start, []*gridRefresh{
		alloc.refresh("the allocation", 300*time.Second),
		perms.refresh("the permissions", 240*time.Second),
	})
	defer g.stop()

	ran := func(a, p int32) {
		t.Helper()
		waitFor(t, "the refreshes due", time.Second, func() bool { return alloc.runs.Load() == a && perms.runs.Load() == p })
		time.Sleep(20 * time.Millisecond)
		if alloc.runs.Load() != a || perms.runs.Load() != p {
			t.Fatalf("allocation ran %d times, permissions %d; want %d and %d", alloc.runs.Load(), perms.runs.Load(), a, p)
		}
	}
	for tick := 1; tick <= 8; tick++ {
		g.tick(start.Add(time.Duration(tick) * keepaliveInterval))
	}
	ran(0, 0)
	g.tick(start.Add(9 * keepaliveInterval)) // 225 s
	ran(0, 1)
	g.tick(start.Add(10 * keepaliveInterval))
	ran(0, 1)
	g.tick(start.Add(11 * keepaliveInterval)) // 275 s
	ran(1, 1)
	// Each counted from its own last run.
	for tick := 12; tick <= 17; tick++ {
		g.tick(start.Add(time.Duration(tick) * keepaliveInterval))
	}
	ran(1, 1)
	g.tick(start.Add(18 * keepaliveInterval)) // 225 s after the 9th
	ran(1, 2)
	g.tick(start.Add(22 * keepaliveInterval)) // 275 s after the 11th
	ran(2, 2)
}

// A thaw's tick after a sleep longer than the interval: overdue by the wall
// clock, whatever a monotonic reading that stood still through the sleep says.
func TestRefreshGridCountsAgeByTheWallClock(t *testing.T) {
	var alloc fakeRefresh
	start := time.Now()
	g := newRefreshGrid(1, start, []*gridRefresh{alloc.refresh("the allocation", 300*time.Second)})
	defer g.stop()

	// Round(0) strips the monotonic reading: only the wall clock moved.
	g.tick(start.Round(0).Add(8 * time.Minute))
	waitFor(t, "the overdue refresh", time.Second, func() bool { return alloc.runs.Load() == 1 })
}

// No tick — the keepalive loop held in a probe, a session that never got to
// its keepalive: the backstop sends at pion's own interval, again and again.
func TestRefreshGridBackstopKeepsPionsCadenceWithoutTicks(t *testing.T) {
	var perms fakeRefresh
	g := newRefreshGrid(1, time.Now(), []*gridRefresh{perms.refresh("the permissions", 40*time.Millisecond)})
	waitFor(t, "three runs by the backstop", 2*time.Second, func() bool { return perms.runs.Load() >= 3 })

	g.stop()
	time.Sleep(60 * time.Millisecond) // one already on its way
	stopped := perms.runs.Load()
	time.Sleep(200 * time.Millisecond)
	if got := perms.runs.Load(); got != stopped {
		t.Fatalf("%d runs after the stop", got-stopped)
	}
	g.tick(time.Now().Add(time.Hour))
	time.Sleep(50 * time.Millisecond)
	if got := perms.runs.Load(); got != stopped {
		t.Fatalf("a tick after the stop ran the refresh")
	}
}

// With the grid coming round, the backstop stays out of it: every run counts
// it anew.
func TestRefreshGridTickHoldsTheBackstopOff(t *testing.T) {
	var binds fakeRefresh
	// Shorter than the grid's interval, so due at every tick.
	g := newRefreshGrid(1, time.Now(), []*gridRefresh{binds.refresh("the channel bindings", 400*time.Millisecond)})
	defer g.stop()
	const ticks = 8
	for i := 0; i < ticks; i++ {
		time.Sleep(100 * time.Millisecond)
		g.tick(time.Now())
	}
	time.Sleep(50 * time.Millisecond)
	if got := binds.runs.Load(); got != ticks {
		t.Fatalf("%d runs for %d ticks: the backstop fired between them", got, ticks)
	}
}

// A transaction still waiting for its answer is not sent again, by a tick or
// by the backstop — and the backstop is not lost with it.
func TestRefreshGridDoesNotDoubleOneInFlight(t *testing.T) {
	alloc := fakeRefresh{hold: make(chan struct{})}
	g := newRefreshGrid(1, time.Now(), []*gridRefresh{alloc.refresh("the allocation", 60*time.Millisecond)})
	defer g.stop()

	g.tick(time.Now())
	waitFor(t, "the first run", time.Second, func() bool { return alloc.runs.Load() == 1 })
	g.tick(time.Now())
	time.Sleep(200 * time.Millisecond) // three backstops' worth
	if got := alloc.runs.Load(); got != 1 {
		t.Fatalf("%d runs with the first still out", got)
	}
	alloc.hold <- struct{}{}
	waitFor(t, "the backstop after the answer", time.Second, func() bool { return alloc.runs.Load() == 2 })
	close(alloc.hold)
}

// turnRequestCount is a TURN server's socket that counts what clients ask.
type turnRequestCount struct {
	net.PacketConn
	refresh, permission, bind atomic.Int32
}

func (c *turnRequestCount) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		m := &stun.Message{Raw: append([]byte(nil), b[:n]...)}
		if m.Decode() == nil && m.Type.Class == stun.ClassRequest {
			switch m.Type.Method {
			case stun.MethodRefresh:
				c.refresh.Add(1)
			case stun.MethodCreatePermission:
				c.permission.Add(1)
			case stun.MethodChannelBind:
				c.bind.Add(1)
			}
		}
	}
	return n, addr, err
}

// pionField reaches a private field of the conn pion's Allocate returned.
func pionField(t *testing.T, relay net.PacketConn, name string) reflect.Value {
	t.Helper()
	f := reflect.ValueOf(relay).Elem().FieldByName(name)
	if !f.IsValid() {
		t.Fatalf("%T has no field %s", relay, name)
	}
	return readable(f)
}

// The whole of it against pion itself, through the session's own dial: the
// allocation comes back with pion's three timers stopped — which pins their
// private names and layout to the module version — and a keepalive tick sends
// Refresh, CreatePermission and ChannelBind to the relay through pion's own
// handlers.
func TestSessionRefreshesRideTheKeepaliveTick(t *testing.T) {
	requests := &turnRequestCount{PacketConn: listenFakeRelay(t)}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "refresh-grid-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "refresh-grid-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: requests,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer resetServerHealth()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, raw, relay, _, perm, err := dialAndAllocate(ctx, &stream{}, t.Name(), "pass", requests.LocalAddr().String(), WorkerGroupConfig{UseUDP: true}, dialOpts{})
	if err != nil {
		t.Fatalf("dialAndAllocate: %v", err)
	}
	defer raw.Close()
	defer client.Close()
	defer relay.Close()

	grid := relayRefreshGrid(relay)
	if grid == nil {
		t.Fatal("the allocation kept pion's own timers: its relay conn no longer matches refresh_grid.go")
	}
	if beneath := relayRefreshGrid(boundRelayClose(relay, raw)); beneath != grid {
		t.Fatal("the grid is not found beneath the close budget of a TCP relay")
	}
	pion := trackedAllocation(relay).PacketConn.(*gridRefreshedRelay).PacketConn
	want := map[string]time.Duration{
		"refreshAllocTimer":  5 * time.Minute, // half the server's default lifetime
		"refreshPermsTimer":  240 * time.Second,
		"checkBindingsTimer": 30 * time.Second,
	}
	if len(grid.refreshes) != len(want) || len(pionRefreshTimers) != len(want) {
		t.Fatalf("%d refreshes taken over, want %d", len(grid.refreshes), len(want))
	}
	for i, timer := range pionRefreshTimers {
		if pionField(t, pion, timer.field).Interface().(pionTimer).IsRunning() {
			t.Errorf("pion's %s is still running", timer.field)
		}
		if got := grid.refreshes[i].interval; got != want[timer.field] {
			t.Errorf("%s: interval %v, want pion's %v", timer.field, got, want[timer.field])
		}
	}

	// The first write is what creates the permission and binds the channel.
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err := relay.WriteTo([]byte("first"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first permission and binding", 2*time.Second, func() bool {
		return requests.permission.Load() == 1 && requests.bind.Load() == 1
	})
	if got := requests.refresh.Load(); got != 0 {
		t.Fatalf("%d Refresh before any tick", got)
	}

	// A tick too soon for anything sends nothing.
	now := time.Now()
	grid.tick(now.Add(2 * time.Second))
	time.Sleep(100 * time.Millisecond)
	if r, p, b := requests.refresh.Load(), requests.permission.Load(), requests.bind.Load(); r != 0 || p != 1 || b != 1 {
		t.Fatalf("a tick 2 s into the session sent Refresh %d, CreatePermission %d, ChannelBind %d", r, p, b-1)
	}

	// pion renews a binding five minutes old, which no test can wait for: make
	// every ready binding old. The ticks below come at instants no tick is due
	// before, each an interval past the last.
	pionField(t, pion, "bindingRefreshInterval").SetInt(0)
	for tick := 1; requests.bind.Load() < 2; tick++ {
		if tick > 30 {
			t.Fatalf("no ChannelBind in %d ticks (Refresh %d, CreatePermission %d)", tick, requests.refresh.Load(), requests.permission.Load())
		}
		grid.tick(now.Add(time.Duration(tick) * 10 * time.Minute))
		time.Sleep(100 * time.Millisecond)
	}
	if r, p := requests.refresh.Load(), requests.permission.Load(); r < 1 || p < 2 {
		t.Fatalf("the ticks sent Refresh %d times and CreatePermission %d, want both", r, p-1)
	}
	if perm.fired() {
		t.Fatalf("refreshes on the grid read as a blackhole: %s", *perm.reason.Load())
	}

	// Closed, the allocation is released and nothing is asked of it again: a
	// refresh after the close would fail and read as a blackhole.
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	// pion does not wait for the answer to its release.
	waitFor(t, "the release", 2*time.Second, func() bool { return server.AllocationCount() == 0 })
	released := requests.refresh.Load()
	permissions := requests.permission.Load()
	grid.tick(now.Add(24 * time.Hour))
	time.Sleep(200 * time.Millisecond)
	if r, p := requests.refresh.Load(), requests.permission.Load(); r != released || p != permissions {
		t.Fatalf("a tick after the close sent Refresh %d times, CreatePermission %d", r-released, p-permissions)
	}
	if perm.fired() {
		t.Fatalf("the close read as a blackhole: %s", *perm.reason.Load())
	}
}

// A conn that is not pion's, or not laid out as this pion's, is left as it is.
func TestRefreshGridLeavesAnUnknownConnAlone(t *testing.T) {
	plain := listenFakeRelay(t)
	if got := refreshOnGrid(plain, 1); got != plain {
		t.Fatalf("a plain socket came back wrapped as %T", got)
	}
	if relayRefreshGrid(plain) != nil {
		t.Fatal("a grid under a plain socket")
	}

	// The names are there, the kind is not.
	type lookalikeTimer struct {
		id       int
		interval string
	}
	type lookalike struct {
		net.PacketConn
		refreshAllocTimer, refreshPermsTimer, checkBindingsTimer *lookalikeTimer
	}
	timer := &lookalikeTimer{}
	conn := &lookalike{PacketConn: plain, refreshAllocTimer: timer, refreshPermsTimer: timer, checkBindingsTimer: timer}
	if _, err := takeOverPionRefreshes(conn, 1, time.Now()); err == nil {
		t.Fatal("a lookalike was taken over")
	}
	if _, err := takeOverPionRefreshes(nil, 1, time.Now()); err == nil {
		t.Fatal("no conn was taken over")
	}
	var s stream
	s.refreshOnGridTick(time.Now()) // between sessions: nothing to tick
}
