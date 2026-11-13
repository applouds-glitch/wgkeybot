package main

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestParseExtraRelays(t *testing.T) {
	relays, bad := parseExtraRelays(" 95.163.34.168, 95.163.34.190:3478;[2001:db8::1]:19302  2001:db8::2 , vk.com, 1.2.3.4:0, 1.2.3.4:x ")
	want := []string{"95.163.34.168", "95.163.34.190:3478", "[2001:db8::1]:19302", "2001:db8::2"}
	if !reflect.DeepEqual(relays, want) {
		t.Fatalf("relays = %v, want %v", relays, want)
	}
	if wantBad := []string{"vk.com", "1.2.3.4:0", "1.2.3.4:x"}; !reflect.DeepEqual(bad, wantBad) {
		t.Fatalf("bad = %v, want %v", bad, wantBad)
	}
	if relays, bad := parseExtraRelays(""); relays != nil || bad != nil {
		t.Fatalf("empty value → %v, %v", relays, bad)
	}
}

// The extra relays join the link's own, bare ones on its port, without
// duplicates and without touching the cached list.
func TestWithExtraRelays(t *testing.T) {
	link := []string{"90.156.236.90:19302", "91.231.135.138:19302"}
	cfg := WorkerGroupConfig{ExtraRelays: []string{"95.163.34.168", "95.163.34.190:3478", "91.231.135.138"}}
	got := withExtraRelays(link, cfg)
	want := []string{"90.156.236.90:19302", "91.231.135.138:19302", "95.163.34.168:19302", "95.163.34.190:3478"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if link[0] != "90.156.236.90:19302" || len(link) != 2 {
		t.Fatalf("the link's list was modified: %v", link)
	}

	// A TurnIP pin still pins.
	pinned := cfg
	pinned.TurnIP = "95.163.34.129"
	if got := withExtraRelays([]string{"95.163.34.129:19302"}, pinned); len(got) != 1 {
		t.Fatalf("extras added to a pinned list: %v", got)
	}
	// None configured: the list as is.
	if got := withExtraRelays(link, WorkerGroupConfig{}); &got[0] != &link[0] {
		t.Fatal("a fresh slice with nothing to add")
	}
}

// The link's own relays are the reserve: those of addrs that match no extra,
// when an extra is in the list at all.
func TestReserveRelays(t *testing.T) {
	extras := []string{"95.163.34.168", "95.163.34.190:3478"}
	addrs := []string{"90.156.236.90:19302", "95.163.34.168:19302", "95.163.34.190:3478", "95.163.34.190:19302"}
	got := reserveRelays(addrs, extras)
	want := map[string]bool{"90.156.236.90:19302": true, "95.163.34.190:19302": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reserve = %v, want %v", got, want)
	}
	// No extra in the list (none configured, or a pin collapsed it): nothing in reserve.
	if got := reserveRelays([]string{"90.156.236.90:19302"}, extras); got != nil {
		t.Fatalf("reserve with no extra in the list = %v", got)
	}
	if got := reserveRelays(addrs, nil); got != nil {
		t.Fatalf("reserve with no extras configured = %v", got)
	}
}

// With extras configured the streams spread over the extras alone and the
// link's own relays follow as failover; with the extras all out, the link's
// own carry the streams as before.
func TestExtraRelaysCarryTheStreams(t *testing.T) {
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	clearRelayRest()
	t.Cleanup(clearRelayRest)
	resetAllocationBook(t)
	cfg := WorkerGroupConfig{ExtraRelays: []string{"10.0.0.3", "10.0.0.4:3478"}}
	addrs := withExtraRelays([]string{"10.0.0.1:3478", "10.0.0.2:3478"}, cfg)
	now := time.Now()
	count := map[string]int{}
	for id := 0; id < 8; id++ {
		order := streamAttemptOrder("u", addrs, id, cfg, now)
		count[order[0]]++
		tail := slices.Clone(order[2:])
		slices.Sort(tail)
		if len(order) != 4 || !slices.Equal(tail, []string{"10.0.0.1:3478", "10.0.0.2:3478"}) {
			t.Fatalf("stream %d: order %v, want the extras first and the link's own behind them", id, order)
		}
	}
	if count["10.0.0.3:3478"] != 4 || count["10.0.0.4:3478"] != 4 {
		t.Fatalf("streams per relay = %v, want 4 on each extra and none on the link's own", count)
	}

	// The extras resting: the link's own carry the streams.
	relayRest.Lock()
	for _, r := range []string{"10.0.0.3:3478", "10.0.0.4:3478"} {
		relayRest.marks[relayRestKeyLocked(r)] = relayRestMark{until: now.Add(time.Hour), rest: relayRestFor}
	}
	relayRest.Unlock()
	count = map[string]int{}
	for id := 0; id < 8; id++ {
		count[streamAttemptOrder("u", addrs, id, cfg, now)[0]]++
	}
	if count["10.0.0.1:3478"] != 4 || count["10.0.0.2:3478"] != 4 {
		t.Fatalf("with the extras resting, streams per relay = %v, want 4 on each of the link's own", count)
	}
}

// A session moved off a rested relay goes to an extra while one is usable,
// even the busiest, and to the link's own only when none is.
func TestMoveHeadPrefersTheExtras(t *testing.T) {
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	clearRelayRest()
	t.Cleanup(clearRelayRest)
	resetAllocationBook(t)
	now := time.Now()
	relays := []string{"10.0.0.1:3478", "10.0.0.2:3478", "10.0.0.3:3478", "10.0.0.4:3478"}
	reserve := map[string]bool{"10.0.0.1:3478": true, "10.0.0.2:3478": true}
	load := &relayLoad{sessions: map[string]int{"10.0.0.4:3478": 3}, picked: map[relayIdentity]int{}}
	for id := 0; id < 4; id++ {
		if got, _ := moveHead(relays, "10.0.0.3:3478", id, "u", nil, reserve, load, now); got != "10.0.0.4:3478" {
			t.Fatalf("stream %d moved to %s, want the extra left, busy as it is", id, got)
		}
	}
	if got, _ := moveHead(relays[:3], "10.0.0.3:3478", 0, "u", nil, reserve, load, now); got != "10.0.0.1:3478" {
		t.Fatalf("with no extra left the session moved to %s, want the link's own", got)
	}
}
