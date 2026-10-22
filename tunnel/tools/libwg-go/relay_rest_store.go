/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// The rest marks on disk (relay_rest.go). The process dies between sessions;
// the path from our server to a relay does not get any better for it.
//
// The file is written on every verdict and every return, and read at every
// proxy start. What this process already knows wins over it — it is as new or
// newer — so the file only matters after a restart. A mark whose relapse window
// has passed is left out both ways: the next verdict starts over without it.
//
// The times are wall-clock milliseconds, since a monotonic reading does not
// outlive the process. A clock moved back after the write would stretch a rest
// by as much, so a rest that ends further off than its own length is cut back
// to it, and one that already came back stays back.
//
// Nothing in the file can stop a start. Missing, unreadable or corrupt, it costs
// the memory of earlier verdicts and nothing else, and the next verdict writes
// it over.

const (
	relayRestFileName    = "relay_rest.json"
	relayRestFileVersion = 1
)

type relayRestFile struct {
	Version int                 `json:"v"`
	Marks   []relayRestFileMark `json:"marks"`
}

type relayRestFileMark struct {
	Relay    string `json:"relay"`
	Server   string `json:"server"`
	UntilMs  int64  `json:"until_ms"` // Unix milliseconds
	RestMs   int64  `json:"rest_ms"`
	Returned bool   `json:"returned,omitempty"`
}

// relayRestSaving runs one write at a time, each with a snapshot taken inside it,
// so the last write is also the newest.
var relayRestSaving sync.Mutex

func relayRestPath() string {
	dir := stateDirPath()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, relayRestFileName)
}

// saveRelayRest writes every server's marks. Outside the relayRest lock: every
// dial reads the marks, and a write can stall on busy flash.
func saveRelayRest(now time.Time) {
	path := relayRestPath()
	if path == "" {
		return
	}
	relayRestSaving.Lock()
	defer relayRestSaving.Unlock()
	relayRest.Lock()
	data, err := encodeRelayRest(relayRest.marks, now)
	relayRest.Unlock()
	if err == nil {
		err = replaceFile(path, data)
	}
	if err != nil {
		turnLog("[RELAY LOSS] rest marks not saved: %v", err)
	}
}

// loadRelayRest takes in the marks an earlier process left, after
// setRelayRestPeer at each proxy start, and logs the current server's: whether
// the verdicts of earlier sessions held is the first question about how a
// session spread its streams.
func loadRelayRest(now time.Time) {
	var disk map[string]relayRestMark
	if path := relayRestPath(); path != "" {
		var err error
		if disk, err = readRelayRest(path, now); err != nil {
			turnLog("[RELAY LOSS] rest marks of earlier sessions ignored: %v", err)
		}
	}
	relayRest.Lock()
	kept := map[string]bool{}
	for key, m := range disk {
		if _, ok := relayRest.marks[key]; !ok {
			relayRest.marks[key] = m
			kept[key] = true
		}
	}
	lines := relayRestReportLocked(kept, now)
	relayRest.Unlock()
	for _, line := range lines {
		turnLog("%s", line)
	}
}

func relayRestReportLocked(kept map[string]bool, now time.Time) []string {
	suffix := "→" + relayRest.peer
	var lines []string
	for key, m := range relayRest.marks {
		relay, ok := strings.CutSuffix(key, suffix)
		if !ok || now.Sub(m.until) >= relayRestRelapse {
			continue
		}
		origin := ""
		if kept[key] {
			origin = " (kept from an earlier process)"
		}
		if left := m.until.Sub(now); left > 0 {
			lines = append(lines, fmt.Sprintf("[RELAY LOSS] %s rests from this server: %v left of %v%s",
				relay, left.Round(time.Second), m.rest, origin))
		} else {
			lines = append(lines, fmt.Sprintf("[RELAY LOSS] %s came back from a %v rest %v ago; judged bad again within %v of that, it rests %v%s",
				relay, m.rest, (-left).Round(time.Second), relayRestRelapse, min(2*m.rest, relayRestMax), origin))
		}
	}
	sort.Strings(lines)
	return lines
}

func readRelayRest(path string, now time.Time) (map[string]relayRestMark, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeRelayRest(raw, now)
}

func decodeRelayRest(raw []byte, now time.Time) (map[string]relayRestMark, error) {
	var f relayRestFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", relayRestFileName, err)
	}
	if f.Version != relayRestFileVersion {
		return nil, fmt.Errorf("%s: version %d, not %d", relayRestFileName, f.Version, relayRestFileVersion)
	}
	marks := make(map[string]relayRestMark, len(f.Marks))
	for _, e := range f.Marks {
		if e.Relay == "" || e.Server == "" || e.RestMs <= 0 || e.RestMs > relayRestMax.Milliseconds() {
			continue
		}
		rest := time.Duration(e.RestMs) * time.Millisecond
		until := time.UnixMilli(e.UntilMs)
		if now.Sub(until) >= relayRestRelapse {
			continue
		}
		switch {
		case e.Returned && until.After(now):
			until = now
		case until.Sub(now) > rest:
			until = now.Add(rest)
		}
		marks[e.Relay+"→"+e.Server] = relayRestMark{until: until, rest: rest, returned: e.Returned}
	}
	return marks, nil
}

func encodeRelayRest(marks map[string]relayRestMark, now time.Time) ([]byte, error) {
	f := relayRestFile{Version: relayRestFileVersion, Marks: []relayRestFileMark{}}
	for key, m := range marks {
		relay, server, ok := strings.Cut(key, "→")
		if !ok || now.Sub(m.until) >= relayRestRelapse {
			continue
		}
		f.Marks = append(f.Marks, relayRestFileMark{
			Relay:    relay,
			Server:   server,
			UntilMs:  m.until.UnixMilli(),
			RestMs:   m.rest.Milliseconds(),
			Returned: m.returned,
		})
	}
	sort.Slice(f.Marks, func(i, j int) bool {
		a, b := f.Marks[i], f.Marks[j]
		return a.Relay < b.Relay || a.Relay == b.Relay && a.Server < b.Server
	})
	return json.Marshal(f)
}

// replaceFile swaps data in under path whole, so a process killed mid-write
// leaves the old file and not half of the new one. No fsync: a process dying
// is what the file is for, and the page cache outlives that; a power cut that
// loses the file costs what a corrupt one does.
func replaceFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
