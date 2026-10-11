package main

import (
	"reflect"
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

// The streams spread over the link's relays and the extra ones alike.
func TestExtraRelaysTakeTheirShareOfStreams(t *testing.T) {
	resetServerHealth()
	clearRelayRest()
	t.Cleanup(clearRelayRest)
	addrs := withExtraRelays([]string{"10.0.0.1:3478", "10.0.0.2:3478"},
		WorkerGroupConfig{ExtraRelays: []string{"10.0.0.3", "10.0.0.4"}})
	count := map[string]int{}
	for id := 0; id < 8; id++ {
		count[assignRelays(addrs, id, time.Now())[0]]++
	}
	for _, a := range []string{"10.0.0.1:3478", "10.0.0.2:3478", "10.0.0.3:3478", "10.0.0.4:3478"} {
		if count[a] != 2 {
			t.Fatalf("streams per relay = %v, want 2 on each", count)
		}
	}
}
