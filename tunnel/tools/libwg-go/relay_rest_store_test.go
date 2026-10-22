/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withRelayRestFile gives the test a state directory of its own and no marks,
// and returns the path of the rest file in it.
func withRelayRestFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	clearRelayRest()
	setStateDir(dir)
	setRelayRestPeer("server:1")
	t.Cleanup(func() {
		setStateDir("")
		clearRelayRest()
	})
	return filepath.Join(dir, relayRestFileName)
}

// restartRelayRest is the process dying and the next one starting a proxy for
// peer: the marks in memory are gone, the file is not.
func restartRelayRest(peer string, now time.Time) {
	clearRelayRest()
	setRelayRestPeer(peer)
	loadRelayRest(now)
}

func peekRelayRest(relay, server string) (relayRestMark, bool) {
	relayRest.Lock()
	defer relayRest.Unlock()
	m, ok := relayRest.marks[relay+"→"+server]
	return m, ok
}

// The field log of 2026-10-20: the process died within a minute or two of each
// disconnect, and the next connect put its streams straight back on the relay
// rested in the session before.
func TestRelayRestSurvivesARestart(t *testing.T) {
	withRelayRestFile(t)
	const bad, other = "90.156.234.252:3478", "95.163.34.168:3478"
	now := time.Now()
	noteRelayResting(bad, now)
	// Another server's verdict is kept beside it, not over it.
	setRelayRestPeer("server:2")
	noteRelayResting(other, now)

	at := now.Add(95 * time.Second)
	restartRelayRest("server:1", at)
	if !relayResting(bad, at) {
		t.Fatal("the rest did not survive the restart")
	}
	if relayResting(other, at) {
		t.Fatal("another server's mark rests the relay for this one")
	}
	if relayResting(bad, now.Add(relayRestFor)) {
		t.Fatal("the rest outlived its length across the restart")
	}

	restartRelayRest("server:2", at)
	if !relayResting(other, at) {
		t.Fatal("the other server's mark was lost")
	}
}

// The relapse rule across restarts: a relay judged bad again soon after its
// return rests twice as long however many processes the history spans.
func TestRelayRestEscalatesAcrossRestarts(t *testing.T) {
	withRelayRestFile(t)
	const relay = "90.156.234.252:3478"
	now := time.Now()
	want := []time.Duration{30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 4 * time.Hour}
	for i, w := range want {
		if got := noteRelayResting(relay, now); got != w {
			t.Fatalf("verdict %d: rest %v, want %v", i+1, got, w)
		}
		restartRelayRest("server:1", now.Add(time.Minute))
		if !relayResting(relay, now.Add(w-time.Second)) || relayResting(relay, now.Add(w)) {
			t.Fatalf("verdict %d: the rest does not end at %v after a restart", i+1, w)
		}
		now = now.Add(w + 10*time.Minute) // back for ten minutes, then bad again
		restartRelayRest("server:1", now)
		if m, ok := peekRelayRest(relay, "server:1"); !ok || !m.returned {
			t.Fatalf("verdict %d: the return was not kept (%+v, %v)", i+1, m, ok)
		}
	}
}

// A mark whose relapse window has passed is not read back, and not written
// out again either: the next verdict starts over.
func TestRelayRestDropsMarksPastTheirRelapseWindow(t *testing.T) {
	path := withRelayRestFile(t)
	const old, recent = "10.0.0.1:3478", "10.0.0.2:3478"
	now := time.Now()
	noteRelayResting(old, now)
	noteRelayResting(recent, now.Add(2*time.Hour))

	later := now.Add(relayRestFor + relayRestRelapse)
	restartRelayRest("server:1", later)
	if _, ok := peekRelayRest(old, "server:1"); ok {
		t.Fatal("a mark past its relapse window was read back")
	}
	if _, ok := peekRelayRest(recent, "server:1"); !ok {
		t.Fatal("a mark within its relapse window was not read back")
	}
	if got := noteRelayResting(old, later); got != relayRestFor {
		t.Fatalf("verdict after the window: rest %v, want a fresh %v", got, relayRestFor)
	}

	// Held in memory past its window, a mark is still left out of the file.
	clearRelayRest()
	noteRelayResting(old, now)
	noteRelayResting(recent, later)
	var f relayRestFile
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Marks) != 1 || f.Marks[0].Relay != recent {
		t.Fatalf("file holds %+v, want only %s", f.Marks, recent)
	}
}

// Whatever is in the file, the start goes on, and the next verdict writes it
// over for the process after.
func TestRelayRestIgnoresACorruptFile(t *testing.T) {
	const relay = "10.0.0.1:3478"
	for name, content := range map[string]string{
		"empty":          "",
		"garbage":        "\x00\x01not json",
		"truncated":      `{"v":1,"marks":[{"relay":"10.0.0.1:3478","server":"server:1","until_ms":`,
		"an array":       `[]`,
		"null":           `null`,
		"marks not list": `{"v":1,"marks":{"relay":"10.0.0.1:3478"}}`,
		"other version":  `{"v":2,"marks":[{"relay":"10.0.0.1:3478","server":"server:1","until_ms":9999999999999,"rest_ms":1800000}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := withRelayRestFile(t)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			loadRelayRest(now)
			if relayResting(relay, now) {
				t.Fatal("a mark read from a corrupt file")
			}
			if got := noteRelayResting(relay, now); got != relayRestFor {
				t.Fatalf("verdict: rest %v, want %v", got, relayRestFor)
			}
			restartRelayRest("server:1", now.Add(time.Minute))
			if !relayResting(relay, now.Add(time.Minute)) {
				t.Fatal("the verdict after a corrupt file did not reach the next process")
			}
		})
	}
}

// A file that can be neither read nor written costs the memory of earlier
// processes and nothing else: this one still rests the relay.
func TestRelayRestWithoutAUsableFile(t *testing.T) {
	path := withRelayRestFile(t)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	const relay = "10.0.0.1:3478"
	now := time.Now()
	loadRelayRest(now)
	if got := noteRelayResting(relay, now); got != relayRestFor || !relayResting(relay, now) {
		t.Fatalf("verdict without a usable file: rest %v, resting %v", got, relayResting(relay, now))
	}
}

// One bad entry does not cost the good ones beside it.
func TestRelayRestSkipsBadEntries(t *testing.T) {
	path := withRelayRestFile(t)
	now := time.Now()
	until := now.Add(10 * time.Minute).UnixMilli()
	rest := relayRestFor.Milliseconds()
	f := relayRestFile{Version: relayRestFileVersion, Marks: []relayRestFileMark{
		{Relay: "10.0.0.1:3478", Server: "server:1", UntilMs: until, RestMs: rest},
		{Relay: "", Server: "server:1", UntilMs: until, RestMs: rest},
		{Relay: "10.0.0.3:3478", Server: "", UntilMs: until, RestMs: rest},
		{Relay: "10.0.0.4:3478", Server: "server:1", UntilMs: until, RestMs: -rest},
		{Relay: "10.0.0.5:3478", Server: "server:1", UntilMs: until, RestMs: 2 * relayRestMax.Milliseconds()},
		{Relay: "10.0.0.6:3478", Server: "server:1", UntilMs: until, RestMs: 1 << 62},
	}}
	raw, _ := json.Marshal(f)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loadRelayRest(now)
	relayRest.Lock()
	n := len(relayRest.marks)
	relayRest.Unlock()
	if !relayResting("10.0.0.1:3478", now) || n != 1 {
		t.Fatalf("%d marks read, want the one good entry resting", n)
	}
}

// A wall clock moved back since the write would stretch the rest by as much:
// it is cut back to its own length, and a relay that already came back stays
// back.
func TestRelayRestClockMovedBack(t *testing.T) {
	path := withRelayRestFile(t)
	now := time.Now()
	far := now.Add(10 * time.Hour).UnixMilli()
	rest := relayRestFor.Milliseconds()
	f := relayRestFile{Version: relayRestFileVersion, Marks: []relayRestFileMark{
		{Relay: "10.0.0.1:3478", Server: "server:1", UntilMs: far, RestMs: rest},
		{Relay: "10.0.0.2:3478", Server: "server:1", UntilMs: far, RestMs: rest, Returned: true},
	}}
	raw, _ := json.Marshal(f)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loadRelayRest(now)
	if !relayResting("10.0.0.1:3478", now.Add(relayRestFor-time.Second)) || relayResting("10.0.0.1:3478", now.Add(relayRestFor)) {
		t.Fatal("a rest from a clock moved back does not end after its own length")
	}
	if relayResting("10.0.0.2:3478", now) {
		t.Fatal("a relay that had come back rests again after the clock moved back")
	}
	// Still its history, though: judged bad again, it rests twice as long.
	if got := noteRelayResting("10.0.0.2:3478", now); got != 2*relayRestFor {
		t.Fatalf("relapse after the clock moved back: rest %v, want %v", got, 2*relayRestFor)
	}
}

// What this process knows is as new as the file or newer — the file may have
// missed a write — so reading the file at the next start keeps it.
func TestRelayRestLoadKeepsThisProcessMarks(t *testing.T) {
	path := withRelayRestFile(t)
	const relay = "10.0.0.1:3478"
	now := time.Now()
	noteRelayResting(relay, now)
	stale, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	relayResting(relay, now.Add(relayRestFor))
	noteRelayResting(relay, now.Add(relayRestFor+time.Minute)) // a relapse: 1h
	if err := os.WriteFile(path, stale, 0o600); err != nil {
		t.Fatal(err)
	}

	loadRelayRest(now.Add(relayRestFor + 2*time.Minute))
	if m, _ := peekRelayRest(relay, "server:1"); m.rest != 2*relayRestFor {
		t.Fatalf("rest after reading a stale file: %v, want this process's %v", m.rest, 2*relayRestFor)
	}
}
