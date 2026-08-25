/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The whole detector rests on pion's log wording. If a version bump rephrases a
// marker the watcher degrades silently to "never fires" — the one failure mode
// that would look exactly like "the bug is fixed". Pin every marker against the
// module actually being compiled against, so the rename is caught here.
func TestMarkersExistInVendoredPion(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/pion/turn/v5").Output()
	if err != nil {
		t.Skipf("cannot locate pion/turn module (no toolchain or no network): %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Skip("pion/turn module dir is empty")
	}

	sources := map[string]string{}
	for _, name := range []string{"udp_conn.go", "allocation.go"} {
		b, readErr := os.ReadFile(filepath.Join(dir, "internal", "client", name))
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		sources[name] = string(b)
	}

	markers := map[string]string{
		bindFailMarker:    "udp_conn.go",
		bindOKMarker:      "udp_conn.go",
		allocClosedMarker: "udp_conn.go",
		allocFailMarker:   "allocation.go",
		allocOKMarker:     "allocation.go",
		permFailMarker:    "allocation.go",
		permOKMarker:      "allocation.go",
	}
	for marker, file := range markers {
		if !strings.Contains(sources[file], marker) {
			t.Errorf("marker %q no longer present in pion %s — permWatch is dead code", marker, file)
		}
	}
}

// Exact log lines pion emits, with the format verbs already substituted the way
// pionLogger.Warnf hands them to note().
const (
	logBindFail   = "Failed to bind channel 16384: channel bind transaction failed: all retransmissions failed"
	logBindOK     = "Channel binding successful: 1.2.3.4:56000 16384"
	logAllocFail  = "Failed to refresh allocation: error 437: Allocation Mismatch"
	logAllocOK    = "Updated lifetime: 600 seconds"
	logPermFail   = "Failed to refresh permissions: error 403: Forbidden"
	logPermOK     = "Refresh permissions successful"
	logAllocClose = "ChannelBind rejected with 400 for 1.2.3.4:56000 on channel 16384; closing TURN allocation"
)

func TestChannelBindNeedsTwoConsecutiveFailures(t *testing.T) {
	w := newPermWatch(3)

	w.note(logBindFail)
	if w.fired() {
		t.Fatal("fired after a single ChannelBind failure")
	}

	w.note(logBindFail)
	if !w.fired() {
		t.Fatal("did not fire after two consecutive ChannelBind failures")
	}
	if !strings.Contains(w.why(), "Allocation") && !strings.Contains(w.why(), "channel") {
		t.Errorf("reason lost pion's wording: %q", w.why())
	}
}

func TestChannelBindSuccessResetsCounter(t *testing.T) {
	w := newPermWatch(0)

	w.note(logBindFail)
	w.note(logBindOK)
	w.note(logBindFail)

	if w.fired() {
		t.Fatal("a successful rebind between two failures must reset the streak")
	}
}

// A failed allocation refresh is already seven retransmits deep and the next
// attempt only comes at lifetime/2 — by then the allocation is gone. One is enough.
func TestAllocationRefreshFailureFiresImmediately(t *testing.T) {
	w := newPermWatch(0)

	w.note(logAllocFail)

	if !w.fired() {
		t.Fatal("a single allocation-refresh failure must recycle the stream")
	}
	if !strings.Contains(w.why(), "437") {
		t.Errorf("reason must carry pion's error text for classifyCredError, got %q", w.why())
	}
}

func TestAllocationRefreshSuccessResetsCounter(t *testing.T) {
	w := newPermWatch(0)

	w.note(logAllocOK)
	if w.fired() {
		t.Fatal("a successful refresh must not fire")
	}
}

func TestPermissionRefreshNeedsTwoFailures(t *testing.T) {
	w := newPermWatch(0)

	w.note(logPermFail)
	if w.fired() {
		t.Fatal("fired after a single permission-refresh failure")
	}

	w.note(logPermFail)
	if !w.fired() {
		t.Fatal("did not fire after two consecutive permission-refresh failures")
	}
}

func TestPermissionRefreshSuccessResetsCounter(t *testing.T) {
	w := newPermWatch(0)

	w.note(logPermFail)
	w.note(logPermOK)
	w.note(logPermFail)

	if w.fired() {
		t.Fatal("a successful permission refresh between failures must reset the streak")
	}
}

func TestBadRequestCloseFiresImmediately(t *testing.T) {
	w := newPermWatch(0)

	w.note(logAllocClose)

	if !w.fired() {
		t.Fatal("pion closing the allocation itself must be reported as a blackhole")
	}
}

// Counters are per failure class: interleaved failures of different kinds must
// not add up into a verdict none of them earned on its own.
func TestFailureClassesAreCountedSeparately(t *testing.T) {
	w := newPermWatch(0)

	w.note(logBindFail)
	w.note(logPermFail)

	if w.fired() {
		t.Fatal("one ChannelBind failure plus one permission failure is not two of either")
	}
}

func TestReasonKeepsRootCause(t *testing.T) {
	w := newPermWatch(0)

	w.note(logAllocFail) // fires
	first := w.why()
	w.note(logAllocClose)
	w.note(logBindFail)
	w.note(logBindFail)

	if w.why() != first {
		t.Errorf("later failures overwrote the root cause: %q → %q", first, w.why())
	}
}

func TestUnrelatedLinesAreIgnored(t *testing.T) {
	w := newPermWatch(0)

	// Real pion lines that must never be mistaken for a failure — note the
	// third one mentions the allocation and a failure, but is emitted *after*
	// pion already closed it, so counting it would double-report.
	w.note("Receive buffer full")
	w.note("Initial lifetime: 600 seconds")
	w.note("Failed to close TURN allocation after ChannelBind 400: already closed")
	w.note("Refresh timer 1 expired")

	if w.fired() {
		t.Fatalf("unrelated pion log line tripped the detector: %q", w.why())
	}
}

// A nil watcher is the "detector disabled" configuration and must stay inert
// rather than panic — deadCh must yield a nil channel, which blocks forever in
// a select instead of firing immediately like a closed one would.
func TestNilWatchIsInert(t *testing.T) {
	var w *permWatch

	w.note(logAllocFail)

	if w.fired() {
		t.Fatal("nil watcher reported a blackhole")
	}
	if w.why() != "" {
		t.Fatal("nil watcher produced a reason")
	}
	if ch := w.deadCh(); ch != nil {
		t.Fatal("nil watcher must yield a nil (never-ready) channel")
	}
}

func TestDeadChannelClosesOnFire(t *testing.T) {
	w := newPermWatch(0)

	select {
	case <-w.deadCh():
		t.Fatal("dead channel was ready before any failure")
	default:
	}

	w.note(logAllocFail)

	select {
	case <-w.deadCh():
	default:
		t.Fatal("dead channel not closed after the detector fired")
	}
}

// pion refreshes bindings from its own timer goroutines, so note() is called
// concurrently. Run under -race.
func TestConcurrentNotesFireOnce(t *testing.T) {
	w := newPermWatch(0)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				w.note(logBindFail)
				w.note(logBindOK)
			}
		}()
	}
	wg.Wait()

	// The verdict itself is racy by construction (interleaving decides whether
	// two failures land back to back); what must hold is that close() ran at
	// most once — a second one would panic — and that a fired watcher has a reason.
	if w.fired() && w.why() == "" {
		t.Fatal("fired without recording a reason")
	}
}

// The factory must only arm the watcher for pion/turn's own client scope.
func TestFactoryArmsOnlyTurnClientScope(t *testing.T) {
	w := newPermWatch(0)
	f := pionLogFactory{streamID: 0, watch: w}

	other := f.NewLogger("ice").(pionLogger)
	if other.watch != nil {
		t.Fatal("watcher armed for a foreign scope")
	}

	turnc := f.NewLogger(permWatchScope).(pionLogger)
	if turnc.watch != w {
		t.Fatal("watcher not armed for the turnc scope")
	}
}

// Debugf must be matched against its *unsubstituted* format string: that is the
// only way pion's success markers reach the watcher without paying for
// formatting, and getting it wrong silently disables every reset path.
func TestDebugfMatchesUnformattedMarker(t *testing.T) {
	w := newPermWatch(0)
	l := pionLogFactory{streamID: 0, watch: w}.NewLogger(permWatchScope)

	w.note(logBindFail)
	l.Debugf("Channel binding successful: %s %d", "1.2.3.4:56000", 16384)
	w.note(logBindFail)

	if w.fired() {
		t.Fatal("Debugf success marker did not reset the ChannelBind streak")
	}
}

func TestWarnfReasonCarriesFormattedError(t *testing.T) {
	w := newPermWatch(0)
	l := pionLogFactory{streamID: 0, watch: w}.NewLogger(permWatchScope)

	l.Warnf("Failed to refresh allocation: %s", "error 401: Unauthorized")

	if !w.fired() {
		t.Fatal("Warnf failure marker did not trip the detector")
	}
	if !strings.Contains(w.why(), "401") {
		t.Errorf("Warnf must hand note() the formatted message, got %q", w.why())
	}
}
