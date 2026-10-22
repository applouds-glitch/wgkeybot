/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	credsLinkA = "AbCdEfGhIjKlMnOp" // join hashes, as wgTurnProxyStart reduces the links to
	credsLinkB = "QrStUvWxYz012345"
	credsMode  = "vk_link"
)

var credsRelays = []string{"95.163.34.168:3478", "90.156.234.252:3478"}

// withTurnCredsFile gives the test a state directory of its own, no slots and
// an empty allocation book, and returns the path of the credentials file in it.
func withTurnCredsFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resetAllocationBook(t)
	forgetTurnCreds()
	setStateDir(dir)
	t.Cleanup(func() {
		setStateDir("")
		forgetTurnCreds()
	})
	return filepath.Join(dir, turnCredsFileName)
}

// forgetTurnCreds is the process dying: the slots and their mirror are gone,
// the file is not.
func forgetTurnCreds() {
	credentialsStore.mu.Lock()
	credentialsStore.caches = make(map[int]*StreamCredentialsCache)
	credentialsStore.mu.Unlock()
	clearSlotCreds()
	turnCredsOnDisk.mu.Lock()
	turnCredsOnDisk.mode = ""
	turnCredsOnDisk.mu.Unlock()
}

// startTurnCreds is a proxy start for links: as in wgTurnProxyStart, the file
// is read — and the credential mode named — before any fetch, so a fetch
// without a start before it would write a file of no mode.
func startTurnCreds(links []string, now time.Time) {
	loadTurnCreds(links, credsMode, nil, now)
}

// restartTurnCreds is the process dying and the next one starting a proxy for
// links.
func restartTurnCreds(links []string, now time.Time) {
	forgetTurnCreds()
	startTurnCreds(links, now)
}

// stampedUser is a VK-style username whose expiry stamp lies until ahead.
func stampedUser(until time.Time, id string) string {
	return strconv.FormatInt(until.Unix(), 10) + ":" + id
}

// vkCreds stands in for the VK fetch: a stamped username, its relays.
func vkCreds(user string) fetchFunc {
	return func(context.Context, string) (string, string, []string, int, error) {
		return user, "pass-" + user, credsRelays, 0, nil
	}
}

// noFetch fails the test if a worker goes to VK.
func noFetch(t *testing.T) fetchFunc {
	return func(context.Context, string) (string, string, []string, int, error) {
		t.Helper()
		t.Fatal("went to VK for a credential the file holds")
		return "", "", nil, 0, nil
	}
}

func fetchGroup(t *testing.T, group int, link string, fn fetchFunc) (string, string, []string) {
	t.Helper()
	user, pass, addrs, err := getCredsCached(context.Background(), link, group*streamsPerCredValue(), fn)
	if err != nil {
		t.Fatal(err)
	}
	return user, pass, addrs
}

func readTurnCredsFile(t *testing.T, path string) turnCredsFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f turnCredsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// The field log of 2026-10-20/21: the process died after every disconnect, and
// 6 of 9 connects fetched a new identity for a credential with hours to live.
// After a restart the groups take their credentials from the file — the same
// user, password and relays, no trip to VK — and the credential is taken as
// one with ghosts: its relays crowded, allocations counted as accepted on it.
func TestTurnCredsSurviveARestart(t *testing.T) {
	withTurnCredsFile(t)
	now := time.Now()
	userA := stampedUser(now.Add(8*time.Hour), "a")
	userB := stampedUser(now.Add(8*time.Hour), "b")
	links := []string{credsLinkA, credsLinkB}
	startTurnCreds(links, now)
	fetchGroup(t, 0, credsLinkA, vkCreds(userA))
	fetchGroup(t, 1, credsLinkB, vkCreds(userB))

	// Within quotaFreshCredWindow of the fetch: without the book's mark the
	// credential would read as fresh and untouched.
	at := now.Add(30 * time.Second)
	restartTurnCreds(links, at)
	for group, want := range []string{userA, userB} {
		user, pass, addrs := fetchGroup(t, group, links[group], noFetch(t))
		if user != want || pass != "pass-"+want || strings.Join(addrs, ",") != strings.Join(credsRelays, ",") {
			t.Fatalf("group %d after the restart: %s %s %v, want %s", group, user, pass, addrs, want)
		}
		for _, relay := range credsRelays {
			if ghosts(want, relay, at) < orphanSteerAt {
				t.Fatalf("group %d: %s is not crowded after the restart", group, relay)
			}
		}
		if credFreshAndUntouched(group, want, at) {
			t.Fatalf("group %d: a credential from disk reads as fresh and untouched — a 486 on it would trip the breaker", group)
		}
	}
	// The expiry comes back as it was, not restarted.
	if left := getStreamCache(0).creds.ExpiresAt.Sub(at); left > 8*time.Hour-credentialExpiryBuffer || left < 7*time.Hour {
		t.Fatalf("the credential's expiry did not come back: %v left", left)
	}
	// The extra relays of the config dialed by the earlier process are crowded too.
	forgetTurnCreds()
	resetAllocationBook(t)
	loadTurnCreds(links, credsMode, []string{"10.9.8.7"}, at)
	if ghosts(userA, "10.9.8.7:3478", at) < orphanSteerAt {
		t.Fatal("an extra relay was not crowded after the restart")
	}
}

// A credential that has expired in the file is not read back; the username's
// own stamp is the last word on that, whatever expiry the file carries.
func TestTurnCredsExpiredAreNotLoaded(t *testing.T) {
	path := withTurnCredsFile(t)
	now := time.Now()
	user := stampedUser(now.Add(2*time.Hour), "a")
	startTurnCreds([]string{credsLinkA}, now)
	fetchGroup(t, 0, credsLinkA, vkCreds(user))

	late := now.Add(2 * time.Hour)
	restartTurnCreds([]string{credsLinkA}, late)
	if got, _, _ := fetchGroup(t, 0, credsLinkA, vkCreds("fresh")); got != "fresh" {
		t.Fatalf("an expired credential was read back: %s", got)
	}

	// The file says the slot lives for hours; the username says it is over.
	f := readTurnCredsFile(t, path)
	f.Slots[0].User = user
	f.Slots[0].ExpiresMs = late.Add(5 * time.Hour).UnixMilli()
	raw, _ := json.Marshal(f)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	restartTurnCreds([]string{credsLinkA}, late)
	if got, _, _ := fetchGroup(t, 0, credsLinkA, vkCreds("fresh2")); got != "fresh2" {
		t.Fatalf("a credential past its username's stamp was read back: %s", got)
	}
}

// A slot's credential is for one link: a start with another link in that
// slot, or in another credential mode, fetches its own. The slot of a link
// that did not change is still served.
func TestTurnCredsForAnotherLinkAreNotLoaded(t *testing.T) {
	withTurnCredsFile(t)
	now := time.Now()
	userA := stampedUser(now.Add(8*time.Hour), "a")
	userB := stampedUser(now.Add(8*time.Hour), "b")
	startTurnCreds([]string{credsLinkA, credsLinkB}, now)
	fetchGroup(t, 0, credsLinkA, vkCreds(userA))
	fetchGroup(t, 1, credsLinkB, vkCreds(userB))

	at := now.Add(time.Minute)
	restartTurnCreds([]string{credsLinkB, credsLinkB}, at)
	if got, _, _ := fetchGroup(t, 0, credsLinkB, vkCreds("fresh")); got != "fresh" {
		t.Fatalf("link A's credential served link B: %s", got)
	}
	if got, _, _ := fetchGroup(t, 1, credsLinkB, noFetch(t)); got != userB {
		t.Fatalf("link B's slot was not served from the file: %s", got)
	}

	forgetTurnCreds()
	loadTurnCreds([]string{credsLinkA, credsLinkB}, "other_mode", nil, at)
	if got, _, _ := fetchGroup(t, 1, credsLinkB, vkCreds("fresh3")); got != "fresh3" {
		t.Fatalf("a credential of another mode was read back: %s", got)
	}
}

// What this process knows is as new as the file or newer — the file may have
// missed a write — so a slot that serves its link keeps its credential; one
// that cannot takes the file's.
func TestTurnCredsLoadKeepsThisProcessCreds(t *testing.T) {
	path := withTurnCredsFile(t)
	now := time.Now()
	old := stampedUser(now.Add(8*time.Hour), "old")
	startTurnCreds([]string{credsLinkA}, now)
	fetchGroup(t, 0, credsLinkA, vkCreds(old))
	stale, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fresh := stampedUser(now.Add(8*time.Hour), "new")
	invalidateGroupCreds(0)
	fetchGroup(t, 0, credsLinkA, vkCreds(fresh))
	if err := os.WriteFile(path, stale, 0o600); err != nil {
		t.Fatal(err)
	}

	startTurnCreds([]string{credsLinkA}, now)
	if got, _, _ := fetchGroup(t, 0, credsLinkA, noFetch(t)); got != fresh {
		t.Fatalf("a stale file replaced this process's credential: %s", got)
	}
	if n := ghosts(fresh, credsRelays[0], now); n != 0 {
		t.Fatalf("this process's own credential got %d ghosts from the file", n)
	}

	// Force-expired, the slot takes what the file offers.
	invalidateGroupCreds(0)
	if err := os.WriteFile(path, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	startTurnCreds([]string{credsLinkA}, now)
	if got, _, _ := fetchGroup(t, 0, credsLinkA, noFetch(t)); got != old {
		t.Fatalf("an expired slot did not take the file's credential: %s", got)
	}
}

// The file follows the slot: a credential the relay rejected (486, 401) is
// rotated out of the file with the slot, and its replacement written in — so a
// process that dies between the rotation and the re-fetch does not start on
// the rejected one. The one way to a new identity on purpose
// (wgTurnDropCredentials) clears the file as well.
func TestTurnCredsFollowTheSlot(t *testing.T) {
	path := withTurnCredsFile(t)
	now := time.Now()
	rejected := stampedUser(now.Add(8*time.Hour), "rejected")
	startTurnCreds([]string{credsLinkA}, now)
	fetchGroup(t, 0, credsLinkA, vkCreds(rejected))
	refreshGroupCreds(0, rejected)
	if f := readTurnCredsFile(t, path); len(f.Slots) != 0 {
		t.Fatalf("the rejected credential is still on disk: %+v", f.Slots)
	}
	restartTurnCreds([]string{credsLinkA}, now)
	replacement := stampedUser(now.Add(8*time.Hour), "replacement")
	if got, _, _ := fetchGroup(t, 0, credsLinkA, vkCreds(replacement)); got != replacement {
		t.Fatalf("the rejected credential came back: %s", got)
	}
	restartTurnCreds([]string{credsLinkA}, now)
	if got, _, _ := fetchGroup(t, 0, credsLinkA, noFetch(t)); got != replacement {
		t.Fatalf("the replacement was not written: %s", got)
	}

	invalidateAllCaches()
	if f := readTurnCredsFile(t, path); len(f.Slots) != 0 {
		t.Fatalf("dropped credentials are still on disk: %+v", f.Slots)
	}
	restartTurnCreds([]string{credsLinkA}, now)
	if got, _, _ := fetchGroup(t, 0, credsLinkA, vkCreds("after-drop")); got != "after-drop" {
		t.Fatalf("a dropped credential came back from disk: %s", got)
	}
}

// Whatever is in the file, the start goes on, and the next fetch writes it
// over for the process after.
func TestTurnCredsIgnoresACorruptFile(t *testing.T) {
	for name, content := range map[string]string{
		"empty":          "",
		"garbage":        "\x00\x01not json",
		"truncated":      `{"v":1,"mode":"vk_link","slots":[{"slot":0,"link":"abc","user":"u","pass":"p","relays":["1.2.3.4:3478"],"fetched_ms":`,
		"an array":       `[]`,
		"null":           `null`,
		"slots not list": `{"v":1,"mode":"vk_link","slots":{"slot":0}}`,
		"other version":  `{"v":2,"mode":"vk_link","slots":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := withTurnCredsFile(t)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			startTurnCreds([]string{credsLinkA}, now)
			user := stampedUser(now.Add(8*time.Hour), "a")
			if got, _, _ := fetchGroup(t, 0, credsLinkA, vkCreds(user)); got != user {
				t.Fatalf("fetched %s after a corrupt file", got)
			}
			restartTurnCreds([]string{credsLinkA}, now.Add(time.Minute))
			if got, _, _ := fetchGroup(t, 0, credsLinkA, noFetch(t)); got != user {
				t.Fatalf("the fetch after a corrupt file did not reach the next process: %s", got)
			}
		})
	}
}

// A file that can be neither read nor written costs the memory of earlier
// processes and nothing else: the fetch still serves the group.
func TestTurnCredsWithoutAUsableFile(t *testing.T) {
	path := withTurnCredsFile(t)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	startTurnCreds([]string{credsLinkA}, now)
	user := stampedUser(now.Add(8*time.Hour), "a")
	if got, _, _ := fetchGroup(t, 0, credsLinkA, vkCreds(user)); got != user {
		t.Fatalf("fetched %s without a usable file", got)
	}
	if got, _, _ := fetchGroup(t, 0, credsLinkA, noFetch(t)); got != user {
		t.Fatalf("the slot did not keep its credential: %s", got)
	}
}

// One bad entry does not cost the good ones beside it; of two entries for one
// slot the first is kept.
func TestTurnCredsSkipsBadEntries(t *testing.T) {
	path := withTurnCredsFile(t)
	now := time.Now()
	good := stampedUser(now.Add(8*time.Hour), "good")
	first := stampedUser(now.Add(8*time.Hour), "first")
	entry := func(slot int, user string) turnCredsFileSlot {
		return turnCredsFileSlot{
			Slot: slot, Link: linkDigest(credsLinkA), User: user, Pass: "p", Relays: credsRelays,
			FetchedMs: now.Add(-time.Minute).UnixMilli(), ExpiresMs: now.Add(7 * time.Hour).UnixMilli(),
		}
	}
	noPass, noRelays, badRelay, noLink, noUser, negative, notFetched := entry(1, "x"), entry(2, "x"), entry(3, "x"), entry(4, "x"), entry(5, ""), entry(-1, "x"), entry(6, "x")
	noPass.Pass = ""
	noRelays.Relays = nil
	badRelay.Relays = []string{"95.163.34.168:3478", "not a relay"}
	noLink.Link = ""
	notFetched.FetchedMs = 0
	f := turnCredsFile{Version: turnCredsFileVersion, Mode: credsMode, Slots: []turnCredsFileSlot{
		entry(0, good), noPass, noRelays, badRelay, noLink, noUser, negative, notFetched,
		entry(7, first), entry(7, "second"),
	}}
	raw, _ := json.Marshal(f)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	slots, err := decodeTurnCreds(raw, credsMode, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 2 || slots[0].Username != good || slots[7].Username != first {
		t.Fatalf("decoded %+v, want slot 0 %s and slot 7 %s only", slots, good, first)
	}
	links := make([]string, 8)
	for i := range links {
		links[i] = credsLinkA
	}
	startTurnCreds(links, now)
	if got, _, _ := fetchGroup(t, 0, credsLinkA, noFetch(t)); got != good {
		t.Fatalf("the good entry was not read: %s", got)
	}
	if got, _, _ := fetchGroup(t, 3, credsLinkA, vkCreds("fetched")); got != "fetched" {
		t.Fatalf("an entry with a bad relay was read: %s", got)
	}
}

// A wall clock that stood ahead at the write would stretch the credential: the
// expiry read back is cut to what a fresh fetch would set, and to the stamp in
// the username; a fetch time in the future reads as now.
func TestTurnCredsClockMovedBack(t *testing.T) {
	now := time.Now().Truncate(time.Second) // the stamp has whole seconds
	stamped := stampedUser(now.Add(3*time.Hour), "stamped")
	entry := func(user string) turnCredsFileSlot {
		return turnCredsFileSlot{
			Slot: 0, Link: linkDigest(credsLinkA), User: user, Pass: "p", Relays: credsRelays,
			FetchedMs: now.Add(time.Hour).UnixMilli(), ExpiresMs: now.Add(30 * time.Hour).UnixMilli(),
		}
	}
	c, ok := storedSlotCreds(entry(stamped), now)
	if !ok {
		t.Fatal("a stamped credential with hours to live was not read")
	}
	if want := now.Add(3*time.Hour - credentialExpiryBuffer); !c.ExpiresAt.Equal(want) {
		t.Fatalf("expiry %v, want the username's stamp less the buffer, %v", c.ExpiresAt, want)
	}
	if !c.FetchedAt.Equal(now) {
		t.Fatalf("a fetch time in the future came back as %v", c.FetchedAt)
	}
	c, ok = storedSlotCreds(entry("plain-user"), now)
	if !ok {
		t.Fatal("an unstamped credential was not read")
	}
	if want := now.Add(time.Duration(defaultCycleSecs) * time.Second); !c.ExpiresAt.Equal(want) {
		t.Fatalf("expiry %v, want the cycle cap %v", c.ExpiresAt, want)
	}
}

// The merge rule on its own.
func TestAdoptStoredCreds(t *testing.T) {
	now := time.Now()
	live := func(link string) TurnCredentials {
		return TurnCredentials{Username: "u", Link: link, ExpiresAt: now.Add(time.Hour)}
	}
	expired := func(link string) TurnCredentials {
		return TurnCredentials{Username: "u", Link: link, ExpiresAt: now.Add(-time.Second)}
	}
	disk := live(linkDigest(credsLinkA))
	cases := []struct {
		name      string
		mem, disk TurnCredentials
		want      bool
	}{
		{"empty slot", TurnCredentials{}, disk, true},
		{"expired slot", expired(credsLinkA), disk, true},
		{"slot of another link", live(credsLinkB), disk, true},
		{"slot that serves", live(credsLinkA), disk, false},
		{"file for another link", TurnCredentials{}, live(linkDigest(credsLinkB)), false},
		{"file expired", TurnCredentials{}, expired(linkDigest(credsLinkA)), false},
		{"file holds the link itself", TurnCredentials{}, live(credsLinkA), false},
	}
	for _, c := range cases {
		if got := adoptStoredCreds(c.mem, c.disk, credsLinkA, now); got != c.want {
			t.Errorf("%s: adopt %v, want %v", c.name, got, c.want)
		}
	}
}

// The link is on disk as a digest only: the join hash is the invite token.
func TestTurnCredsFileHoldsNoLink(t *testing.T) {
	path := withTurnCredsFile(t)
	now := time.Now()
	startTurnCreds([]string{credsLinkA}, now)
	user := stampedUser(now.Add(8*time.Hour), "a")
	fetchGroup(t, 0, credsLinkA, vkCreds(user))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), credsLinkA) {
		t.Fatal("the link is on disk")
	}
	if !strings.Contains(string(raw), linkDigest(credsLinkA)) {
		t.Fatal("the link's digest is not on disk")
	}
	if linkDigest(credsLinkA) == linkDigest(credsLinkB) || len(linkDigest(credsLinkA)) != 16 {
		t.Fatalf("digests %s %s", linkDigest(credsLinkA), linkDigest(credsLinkB))
	}
	f := readTurnCredsFile(t, path)
	if f.Mode != credsMode || len(f.Slots) != 1 || f.Slots[0].User != user || f.Slots[0].Pass != "pass-"+user {
		t.Fatalf("file holds %+v", f)
	}
}
