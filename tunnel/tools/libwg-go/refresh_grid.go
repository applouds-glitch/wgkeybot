/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// TURN's periodic transactions on the keepalive grid.
//
// A stream's allocation lives on three periodic transactions, which pion sends
// from timers of its own started at the Allocate: Refresh every half lifetime
// (300 s on VK's 600), CreatePermission every PermissionRefreshInterval
// (240 s), and a check every 30 s that sends ChannelBind once the binding is
// five minutes old. Their phase is the instant the stream was allocated, which
// has nothing to do with the 25 s grid the keepalives share
// (keepalive_policy.go). Streams connected together refresh together, 2-3
// radio wakes per five minutes beside the grid's twelve. Streams redialed one
// by one — a relay rested and its sessions moved, the return to the extras,
// the probe under load — each refresh at an instant of their own: with ten
// streams, up to ~22 wakes per five minutes, each holding the radio up for its
// 5-10 s tail (battery look of 2026-11-10; counted from the timers, not
// traced).
//
// pion has no call that sends them on request, and the binding's intervals are
// not in its config. So the session takes the three timers over: stops them and
// calls their own handlers — pion's code and pion's log lines, so permWatch
// reads the outcome as it always did — from the stream's keepalive tick, at the
// last tick still inside the timer's interval (refreshDueOnGrid). Nothing goes
// out later than pion would have sent it: a backstop per transaction fires at
// pion's own interval when the grid did not come round — the loop held in a
// probe, the session not carrying a keepalive yet. (One exception, on the wide
// grid: the binding check, see backstopAfter.)
//
// The timers are private to pion (internal/client), so they are reached by
// field name through reflection; refresh_grid_test.go pins the names against
// the module. A conn that does not match is left alone, its timers running as
// they were, with one line in the log.

// refreshDueOnGrid says whether a transaction pion would send every interval
// goes out at this keepalive tick, age after the last one, on a grid of every:
// it does when the next tick, one grid interval away, would come past the
// interval. keepaliveSpread is the slack for a tick that comes a little early
// or late (the jitter after a thaw is of that order, wakeProbeSpread).
//
// So on the 25 s grid the allocation is refreshed every 275 s instead of 300,
// the permission every 225 s instead of 240, and the bindings are checked at
// every tick, 25 s instead of 30: a little more often, never more seldom. On
// the wide grid (keepalive_economy.go) it is 250 s and 200 s, and the bindings
// are checked every 50 s — see backstopAfter.
func refreshDueOnGrid(age, interval, every time.Duration) bool {
	return age >= interval-every-keepaliveSpread
}

// refreshBackstopSlack is how far behind a grid tick the backstop of a
// transaction more frequent than the grid waits for it.
const refreshBackstopSlack = 5 * time.Second

// backstopAfter is how long after a transaction its backstop fires: pion's own
// interval — except where the grid is wider than that, which only the binding
// check's 30 s is, on the wide grid. Left at 30 s there, the backstop would run
// the check between two ticks of every period, and three times in five that is
// the check that finds the binding five minutes old and sends its ChannelBind:
// a burst of the radio's own per stream, off the grid — what the grid is for.
// So the check waits for the tick, and the backstop stands behind the tick. The
// ChannelBind then goes out up to 50 s after the binding turns five minutes
// old instead of up to 30; VK's bindings live ten.
//
// On the narrow grid nothing changes, whatever the interval: the binding
// check's backstop is pion's 30 s there, five seconds behind the tick.
func backstopAfter(interval, every time.Duration) time.Duration {
	if every > keepaliveInterval && interval <= every {
		return every + keepaliveSpread + refreshBackstopSlack
	}
	return interval
}

// gridRefresh is one of pion's periodic transactions.
type gridRefresh struct {
	name     string
	interval time.Duration // pion's own period: the backstop's
	run      func()        // pion's handler; blocks while its transaction is out
	quiet    bool          // not worth a debug line: runs at every tick

	// last is when it was last started, by the wall clock (UnixNano). Not a
	// monotonic reading: that one stops while the device sleeps, and after a
	// long sleep the thaw's tick must see the transaction as overdue.
	last     atomic.Int64
	inFlight atomic.Bool
	backstop *time.Timer // guarded by refreshGrid.mu
}

// refreshGrid runs one allocation's periodic transactions. It lives from the
// Allocate to the relay conn's Close (gridRefreshedRelay).
type refreshGrid struct {
	streamID  int
	refreshes []*gridRefresh

	mu      sync.Mutex
	stopped bool
}

func newRefreshGrid(streamID int, now time.Time, refreshes []*gridRefresh) *refreshGrid {
	g := &refreshGrid{streamID: streamID, refreshes: refreshes}
	// Under the lock: a backstop that fires at once waits for its timer to be
	// in place.
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range refreshes {
		r.last.Store(now.UnixNano())
		r.backstop = time.AfterFunc(backstopAfter(r.interval, keepaliveEvery(now)), func() { g.start(r, time.Now(), true) })
	}
	return g
}

// tick is the keepalive loop's call at a grid point: what is due goes out in
// the same burst as the keepalive.
func (g *refreshGrid) tick(now time.Time) {
	if g == nil {
		return
	}
	every := keepaliveEvery(now)
	for _, r := range g.refreshes {
		if refreshDueOnGrid(time.Duration(now.UnixNano()-r.last.Load()), r.interval, every) {
			g.start(r, now, false)
		}
	}
}

// start runs one transaction off the caller's goroutine — pion waits for the
// answer, retransmitting for up to ~50 s — and counts the backstop anew from
// now. One still out is not doubled.
func (g *refreshGrid) start(r *gridRefresh, now time.Time, backstop bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return
	}
	if !r.inFlight.CompareAndSwap(false, true) {
		if backstop {
			// The timer has fired and nothing else arms it again.
			r.backstop.Reset(backstopAfter(r.interval, keepaliveEvery(now)))
		}
		return
	}
	age := time.Duration(now.UnixNano() - r.last.Load())
	r.last.Store(now.UnixNano())
	r.backstop.Reset(backstopAfter(r.interval, keepaliveEvery(now)))
	if refreshGridLog && !r.quiet {
		by := "on the keepalive grid"
		if backstop {
			by = "by the backstop, no grid tick came"
		}
		turnLog("[STREAM %d] TURN refresh of %s %v after the last, %s", g.streamID, r.name, age.Round(time.Second), by)
	}
	go func() {
		defer r.inFlight.Store(false)
		r.run()
	}()
}

// stop ends it before the allocation is released: a handler started after
// pion's Close would log a failed refresh, which permWatch reads as a
// blackhole. One already out is pion's to fail, as with its own timers.
func (g *refreshGrid) stop() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopped = true
	for _, r := range g.refreshes {
		r.backstop.Stop()
	}
}

// pionRefreshTimers are the three timers by their field names in pion v5's
// internal/client: allocation.refreshAllocTimer and .refreshPermsTimer (the
// allocation is embedded in UDPConn) and UDPConn.checkBindingsTimer.
var pionRefreshTimers = [...]struct {
	field, name string
	quiet       bool
}{
	{field: "refreshAllocTimer", name: "the allocation"},
	{field: "refreshPermsTimer", name: "the permissions"},
	{field: "checkBindingsTimer", name: "the channel bindings", quiet: true},
}

// pionTimer is what a *client.PeriodicTimer can be asked without naming it.
type pionTimer interface {
	Stop()
	IsRunning() bool
}

// takeOverPionRefreshes stops the three timers of a relay conn that came from
// pion's Allocate and returns the grid that runs their handlers instead. All
// or nothing: on an error no timer has been touched.
func takeOverPionRefreshes(relay net.PacketConn, streamID int, now time.Time) (g *refreshGrid, err error) {
	defer func() {
		if p := recover(); p != nil {
			g, err = nil, fmt.Errorf("%T is not laid out as pion v5's relay conn: %v", relay, p)
		}
	}()
	conn := reflect.ValueOf(relay)
	if conn.Kind() != reflect.Pointer || conn.IsNil() || conn.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("%T is not pion's relay conn", relay)
	}
	var timers []pionTimer
	var refreshes []*gridRefresh
	for _, t := range pionRefreshTimers {
		field := conn.Elem().FieldByName(t.field)
		if !field.IsValid() || field.Kind() != reflect.Pointer || field.IsNil() || field.Elem().Kind() != reflect.Struct {
			return nil, fmt.Errorf("%T has no timer %s", relay, t.field)
		}
		timer, ok := readable(field).Interface().(pionTimer)
		if !ok {
			return nil, fmt.Errorf("%T.%s is a %s, which cannot be stopped", relay, t.field, field.Type())
		}
		id := field.Elem().FieldByName("id")
		interval := field.Elem().FieldByName("interval")
		handler := field.Elem().FieldByName("timeoutHandler")
		if !id.IsValid() || !id.CanInt() ||
			!interval.IsValid() || interval.Type() != reflect.TypeFor[time.Duration]() ||
			!handler.IsValid() || handler.Kind() != reflect.Func || handler.IsNil() ||
			!handler.Type().ConvertibleTo(reflect.TypeFor[func(int)]()) {
			return nil, fmt.Errorf("%s of %T.%s has no id, interval and handler of the kind expected", field.Type(), relay, t.field)
		}
		run, ok := readable(handler).Convert(reflect.TypeFor[func(int)]()).Interface().(func(int))
		every := time.Duration(interval.Int())
		if !ok || every <= 0 {
			return nil, fmt.Errorf("%T.%s: interval %v", relay, t.field, every)
		}
		if !timer.IsRunning() {
			return nil, fmt.Errorf("%T.%s is not running", relay, t.field)
		}
		timerID := int(id.Int())
		timers = append(timers, timer)
		refreshes = append(refreshes, &gridRefresh{
			name: t.name, interval: every, quiet: t.quiet,
			run: func() { run(timerID) },
		})
	}
	for _, timer := range timers {
		timer.Stop()
	}
	return newRefreshGrid(streamID, now, refreshes), nil
}

// readable gives a private field as a value that may be handed out of reflect.
// The field must be addressable, as everything reached through the conn's
// pointer is.
func readable(v reflect.Value) reflect.Value {
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}

// gridRefreshedRelay is a relay allocation whose periodic transactions the
// keepalive grid drives. Every Close of the allocation goes through it — the
// session's, the watchdog's, a losing candidate's — and ends them first.
type gridRefreshedRelay struct {
	net.PacketConn
	grid *refreshGrid
}

func (r *gridRefreshedRelay) Close() error {
	r.grid.stop()
	return r.PacketConn.Close()
}

var refreshGridUnavailable sync.Once

// refreshOnGrid takes a fresh allocation's periodic transactions over
// (dialAndAllocate). Until a session's keepalive loop ticks for it, and
// whenever that loop is busy, the backstops keep pion's own cadence.
func refreshOnGrid(relay net.PacketConn, streamID int) net.PacketConn {
	grid, err := takeOverPionRefreshes(relay, streamID, time.Now())
	if err != nil {
		refreshGridUnavailable.Do(func() {
			turnLog("[TURN] refreshes stay on pion's own timers, off the keepalive grid: %v", err)
		})
		return relay
	}
	return &gridRefreshedRelay{PacketConn: relay, grid: grid}
}

// relayRefreshGrid finds the grid under a session's relay conn, beneath the
// allocation count and the close budget (trackAllocation, boundRelayClose);
// nil if pion kept its timers.
func relayRefreshGrid(pc net.PacketConn) *refreshGrid {
	for {
		switch c := pc.(type) {
		case *gridRefreshedRelay:
			return c.grid
		case *trackedRelay:
			pc = c.PacketConn
		case *boundedCloseRelay:
			pc = c.PacketConn
		default:
			return nil
		}
	}
}

// refreshOnGridTick is the keepalive loop's call at a grid point and at a
// thaw: the session installs its grid on the stream for as long as it runs
// (runSession).
func (s *stream) refreshOnGridTick(now time.Time) {
	s.refreshGrid.Load().tick(now)
}
