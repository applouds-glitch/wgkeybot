/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// The TURN credentials on disk (credentials.go). The process dies between
// sessions; the credential VK handed out does not expire for it.
//
// WHY. Field log of 2026-10-20/21 (POCO, HyperOS 3, v2.2.0): the system killed
// the process after every disconnect, and 6 of the day's 9 connects opened with
// "Cache miss (cache=0), fetching..." — a new anonymous VK user (vk_calls.go), a
// new captcha persona, 1-1.8 s more before the first stream — while the line
// "Credentials … cached for 7h44m59s" of each fetch said the credential had
// hours to live (its expiry is stamped into the username, see
// credentialExpiryFromUsername). Within one process the reconnects did take the
// cached one ("Transient state cleared (DNS; creds preserved)"); only the memory
// died with the process. So the slots are kept on disk as well, the way the rest
// marks are (relay_rest_store.go): written whenever a slot changes, read at every
// proxy start.
//
// WHAT. One entry per slot (credential group): user, password, VK's relays, when
// it was fetched and when the slot expires, in wall-clock milliseconds, and the
// link it was fetched for — as a digest. The link a slot is keyed by in memory is
// the join hash, the invite token itself (joinHash), which the log never prints
// (369b1d3b) and the file does not hold either; the digest is enough to tell
// whether a slot was fetched for the link a start joins with.
//
// MERGE. What this process already knows wins over the file: an entry is taken
// only into a slot that cannot serve its link now (empty, expired, or holding
// another link's credential), and only if the entry can — fetched for that link
// and not expired. Expired entries are left out both ways. The username's own
// expiry stamp caps the expiry read back, so a wall clock that was ahead at the
// write cannot stretch a credential past what VK gave it.
//
// GHOSTS. The allocation book (orphaned_allocations.go) lives in memory, and a
// process killed with its streams up leaves their allocations on the relays,
// still counting against this credential's quota of about ten per relay for the
// allocation lifetime. The next process cannot know how many, where, or when the
// kill was, so a credential read from disk is taken as one with ghosts: its
// relays are marked crowded for orphanedAllocationLifetime under the rules a
// lost network applies to live allocations (noteCredsFromEarlierProcess), and
// the credential counts as one allocations were accepted on, so that a 486 on it
// is read as its own quota and not as a relay refusing fresh credentials
// (quota_breaker.go). A 486 then takes the ordinary path — the slot is rotated
// and the file rewritten with the credential that replaces it.
//
// SECRET. The credential is kept in the app's private files directory
// (TurnProxyManager passes it through wgSetStateDir), mode 0600, and not through
// SecureFileStorage, which guards the tunnel's own secrets (the WireGuard private
// key, the VK link and the WRAP key in the TURN settings). This credential is an
// anonymous VK identity's TURN password, good for hours and for nothing but relay
// allocations under that identity's quota — what any anonymous participant of
// the call gets by joining the link, and what this process holds in cleartext in
// memory for as long. The directory is private to the app's uid (SELinux
// app_data_file), the manifest has allowBackup="false", the entry is dropped as
// soon as it expires, and the link it was fetched for is on disk only as a
// digest. Writing it from Kotlin would cost a JNI round trip for every fetch and
// rotation, and a start that waits for Kotlin to hand the credentials over, for
// no secret the directory does not already keep in clear.
//
// Nothing in the file can stop a start. Missing, unreadable or corrupt, it costs
// one VK round trip per group and nothing else, and the next fetch writes it
// over.

const (
	turnCredsFileName    = "turn_creds.json"
	turnCredsFileVersion = 1
)

type turnCredsFile struct {
	Version int                 `json:"v"`
	Mode    string              `json:"mode"` // the credential mode of the start that wrote it
	Slots   []turnCredsFileSlot `json:"slots"`
}

type turnCredsFileSlot struct {
	Slot      int      `json:"slot"`
	Link      string   `json:"link"` // linkDigest of the group's link, never the link
	User      string   `json:"user"`
	Pass      string   `json:"pass"`
	Relays    []string `json:"relays"`
	FetchedMs int64    `json:"fetched_ms"` // Unix milliseconds
	ExpiresMs int64    `json:"expires_ms"`
}

// turnCredsMirror is the persisted view of the credential slots: what each
// slot holds, kept in step by the functions of credentials.go that change a
// slot (noteSlotCreds, under that slot's lock), and the credential mode, which
// every proxy start names before any fetch can run (loadTurnCreds from
// wgTurnProxyStart; a file written with no mode is not read back). The file is
// written from here, so the writer never takes a slot's lock — getCredsCached
// holds its own across the write.
type turnCredsMirror struct {
	mu    sync.Mutex
	mode  string
	slots map[int]TurnCredentials
}

var turnCredsOnDisk = turnCredsMirror{slots: map[int]TurnCredentials{}}

// turnCredsSaving runs one write at a time, each with a snapshot taken inside
// it, so the last write is also the newest.
var turnCredsSaving sync.Mutex

// noteSlotCreds records what slot holds now. Called under the slot's lock, so
// the mirror changes in the order the slots do.
func noteSlotCreds(slot int, c TurnCredentials) {
	c.ServerAddrs = append([]string(nil), c.ServerAddrs...)
	turnCredsOnDisk.mu.Lock()
	turnCredsOnDisk.slots[slot] = c
	turnCredsOnDisk.mu.Unlock()
}

// clearSlotCreds forgets every slot, as invalidateAllCaches does in memory.
func clearSlotCreds() {
	turnCredsOnDisk.mu.Lock()
	turnCredsOnDisk.slots = map[int]TurnCredentials{}
	turnCredsOnDisk.mu.Unlock()
}

func (m *turnCredsMirror) snapshot() (string, map[int]TurnCredentials) {
	m.mu.Lock()
	defer m.mu.Unlock()
	slots := make(map[int]TurnCredentials, len(m.slots))
	for k, v := range m.slots {
		slots[k] = v
	}
	return m.mode, slots
}

func turnCredsPath() string {
	dir := stateDirPath()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, turnCredsFileName)
}

// saveTurnCreds writes every slot's credential that has not expired.
func saveTurnCreds(now time.Time) {
	path := turnCredsPath()
	if path == "" {
		return
	}
	turnCredsSaving.Lock()
	defer turnCredsSaving.Unlock()
	mode, slots := turnCredsOnDisk.snapshot()
	data, err := encodeTurnCreds(mode, slots, now)
	if err == nil {
		err = replaceFile(path, data)
	}
	if err != nil {
		turnLog("[Auth] creds not saved: %v", err)
	}
}

// loadTurnCreds takes in the credentials an earlier process left, at each proxy
// start, into the slots of links — group i's link is links[i] — that cannot
// serve their link themselves. mode is the start's credential mode; extraRelays
// the relays the config adds to every link's own (relay_extra.go), which the
// earlier process dialed as well.
func loadTurnCreds(links []string, mode string, extraRelays []string, now time.Time) {
	turnCredsOnDisk.mu.Lock()
	turnCredsOnDisk.mode = mode
	turnCredsOnDisk.mu.Unlock()

	var disk map[int]TurnCredentials
	if path := turnCredsPath(); path != "" {
		var err error
		if disk, err = readTurnCreds(path, mode, now); err != nil {
			turnLog("[Auth] creds of earlier processes ignored: %v", err)
		}
	}
	if len(disk) == 0 {
		return
	}
	perCred := streamsPerCredValue()
	for slot, link := range links {
		entry, ok := disk[slot]
		if !ok {
			continue
		}
		cache := getStreamCache(slot * perCred)
		cache.mutex.Lock()
		adopt := adoptStoredCreds(cache.creds, entry, link, now)
		if adopt {
			cache.creds = entry
			cache.creds.Link = link
			noteSlotCreds(slot, cache.creds)
		}
		mem := cache.creds
		cache.mutex.Unlock()

		if !adopt {
			// Only the reasons that explain the "Cache miss" to follow; a slot
			// this process already serves is not news.
			if !credsServe(mem, link, now) {
				turnLog("[Auth] Group %d: creds %s on disk not used — %s", slot, credsTag(entry.Username), storedCredsMissReason(entry, link, now))
			}
			continue
		}
		relays := withExtraRelays(entry.ServerAddrs, WorkerGroupConfig{ExtraRelays: extraRelays})
		noteCredsFromEarlierProcess(entry.Username, relays, now)
		turnLog("[Auth] Group %d: creds %s loaded from disk, %v left, %d relay(s) crowded for %v",
			slot, credsTag(entry.Username), entry.ExpiresAt.Sub(now).Round(time.Second), len(relays), orphanedAllocationLifetime)
	}
}

// credsServe reports whether c can serve link at now: fetched for it and not
// expired — the cache hit of getCredsCached.
func credsServe(c TurnCredentials, link string, now time.Time) bool {
	return c.Username != "" && c.Link == link && now.Before(c.ExpiresAt)
}

// adoptStoredCreds reports whether disk — a slot's entry read from the file,
// its Link a digest — is to take the place of mem, what the slot holds now, for
// link at now. What this process knows wins: it is as new as the file or newer,
// so the file only matters for a slot that cannot serve the link itself. Nor
// is an entry under a username this process has dropped taken (wasDropped):
// the drop was for that identity.
func adoptStoredCreds(mem, disk TurnCredentials, link string, now time.Time) bool {
	return !credsServe(mem, link, now) && credsServe(disk, linkDigest(link), now) && !wasDropped(disk)
}

// storedCredsMissReason says, for the log, why an entry of the file could not
// serve link.
func storedCredsMissReason(disk TurnCredentials, link string, now time.Time) string {
	if wasDropped(disk) {
		return "dropped by this process"
	}
	if disk.Link != linkDigest(link) {
		return "fetched for another link"
	}
	return fmt.Sprintf("expired %v ago", now.Sub(disk.ExpiresAt).Round(time.Second))
}

// linkDigest is what the file holds in place of a group's link: the first 16
// hex digits of a salted SHA-256 of it. One-way, so the invite token is not on
// disk; enough to tell one link from another.
func linkDigest(link string) string {
	sum := sha256.Sum256([]byte("wgkeybot turn creds link\x00" + link))
	return hex.EncodeToString(sum[:8])
}

func readTurnCreds(path, mode string, now time.Time) (map[int]TurnCredentials, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeTurnCreds(raw, mode, now)
}

// decodeTurnCreds reads the file's entries that can still serve at now, by
// slot, with Link the digest the file holds. A file of another version, or of
// another credential mode with entries in it, is nothing; a bad entry costs
// only itself; of two entries for one slot the first is kept.
func decodeTurnCreds(raw []byte, mode string, now time.Time) (map[int]TurnCredentials, error) {
	var f turnCredsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", turnCredsFileName, err)
	}
	if f.Version != turnCredsFileVersion {
		return nil, fmt.Errorf("%s: version %d, not %d", turnCredsFileName, f.Version, turnCredsFileVersion)
	}
	if f.Mode != mode && len(f.Slots) > 0 {
		return nil, fmt.Errorf("%s: credentials of mode %q, not %q", turnCredsFileName, f.Mode, mode)
	}
	slots := make(map[int]TurnCredentials, len(f.Slots))
	for _, e := range f.Slots {
		c, ok := storedSlotCreds(e, now)
		if !ok {
			continue
		}
		if _, dup := slots[e.Slot]; dup {
			continue
		}
		slots[e.Slot] = c
	}
	return slots, nil
}

// storedSlotCreds turns one entry into the credential it holds, or reports
// that it holds none worth having: a field missing, a relay that is not
// host:port, or an expiry already past.
//
// The expiry is read back no further off than a fresh fetch would set it
// (defaultCycleSecs), and no further than the stamp in the username less
// credentialExpiryBuffer, the deadline getCredsCached derives from that stamp:
// a wall clock that stood ahead at the write would otherwise stretch the
// credential past what VK gave it, and a 401 on every attempt until the slot is
// force-expired is the costly mistake here. A credential whose stamp is already
// inside the buffer is not read back, though getCredsCached would have cached
// it for the fallback lifetime: it is minutes from a 401 and the trip to VK is
// the cheaper outcome.
func storedSlotCreds(e turnCredsFileSlot, now time.Time) (TurnCredentials, bool) {
	if e.Slot < 0 || e.Link == "" || e.User == "" || e.Pass == "" || len(e.Relays) == 0 || e.FetchedMs <= 0 {
		return TurnCredentials{}, false
	}
	relays := make([]string, 0, len(e.Relays))
	for _, r := range e.Relays {
		if host, _, err := net.SplitHostPort(r); err != nil || host == "" {
			return TurnCredentials{}, false
		}
		relays = append(relays, r)
	}
	expires := time.UnixMilli(e.ExpiresMs)
	if cap := now.Add(time.Duration(defaultCycleSecs) * time.Second); expires.After(cap) {
		expires = cap
	}
	if until, ok := credentialExpiryFromUsername(e.User); ok {
		if stamped := until.Add(-credentialExpiryBuffer); expires.After(stamped) {
			expires = stamped
		}
	}
	if !expires.After(now) {
		return TurnCredentials{}, false
	}
	fetched := time.UnixMilli(e.FetchedMs)
	if fetched.After(now) {
		fetched = now
	}
	return TurnCredentials{
		Username:    e.User,
		Password:    e.Pass,
		ServerAddrs: relays,
		ExpiresAt:   expires,
		FetchedAt:   fetched,
		Link:        e.Link,
	}, true
}

// encodeTurnCreds writes the slots that hold a credential not expired at now,
// each link as its digest.
func encodeTurnCreds(mode string, slots map[int]TurnCredentials, now time.Time) ([]byte, error) {
	f := turnCredsFile{Version: turnCredsFileVersion, Mode: mode, Slots: []turnCredsFileSlot{}}
	for slot, c := range slots {
		if c.Username == "" || !now.Before(c.ExpiresAt) {
			continue
		}
		f.Slots = append(f.Slots, turnCredsFileSlot{
			Slot:      slot,
			Link:      linkDigest(c.Link),
			User:      c.Username,
			Pass:      c.Password,
			Relays:    append([]string{}, c.ServerAddrs...),
			FetchedMs: c.FetchedAt.UnixMilli(),
			ExpiresMs: c.ExpiresAt.UnixMilli(),
		})
	}
	sort.Slice(f.Slots, func(i, j int) bool { return f.Slots[i].Slot < f.Slots[j].Slot })
	return json.Marshal(f)
}
