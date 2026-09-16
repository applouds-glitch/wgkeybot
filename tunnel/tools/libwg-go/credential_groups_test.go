/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

func TestPlanCredentialGroups(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		links                  []string
		total, perCred         int
		wantLinks              []string
		wantTotal, wantPerCred int
	}{
		{"ten", []string{"a"}, 10, 10, []string{"a"}, 10, 10},
		{"eleven", []string{"a"}, 11, 10, []string{"a", "a"}, 11, 10},
		{"twenty", []string{"a"}, 20, 10, []string{"a", "a"}, 20, 10},
		{"twenty-one", []string{"a"}, 21, 10, []string{"a", "a", "a"}, 21, 10},
		{"legacy-sixteen", []string{"a"}, 21, 16, []string{"a", "a", "a"}, 21, 10},
		{"smaller-preference", []string{"a"}, 9, 4, []string{"a", "a", "a"}, 9, 4},
		{"cycle-links", []string{"a", "b"}, 21, 10, []string{"a", "b", "a"}, 21, 10},
		{"keep-remainder", []string{"a", "b"}, 11, 10, []string{"a", "b"}, 11, 6},
		{"no-empty-groups", []string{"a", "b", "c"}, 2, 10, []string{"a", "b"}, 2, 1},
		{"unspecified-total", []string{"a", "b"}, 0, 16, []string{"a", "b"}, 20, 10},
		{"invalid-stride", []string{"a"}, 2, 0, []string{"a", "a"}, 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			links, perCred, total := planCredentialGroups(tc.links, tc.total, tc.perCred)
			if !reflect.DeepEqual(links, tc.wantLinks) || perCred != tc.wantPerCred || total != tc.wantTotal {
				t.Fatalf("got (%v, %d, %d), want (%v, %d, %d)", links, perCred, total, tc.wantLinks, tc.wantPerCred, tc.wantTotal)
			}
		})
	}
}

// Every supported total must retain all workers, including the short final
// group, and map each group to an independent credential cache slot even when
// all groups use the same call link.
func TestCredentialGroupsRespectQuotaAndFetchSeparately(t *testing.T) {
	previous := streamsPerCredValue()
	t.Cleanup(func() {
		setStreamsPerCred(previous)
		invalidateAllCaches()
	})
	for total := 1; total <= 128; total++ {
		links, perCred, gotTotal := planCredentialGroups([]string{"same-call"}, total, 16)
		setStreamsPerCred(perCred)
		counts := make([]int, len(links))
		for streamID := 0; streamID < gotTotal; streamID++ {
			counts[getCacheID(streamID)]++
		}
		for groupID, count := range counts {
			if count < 1 || count > 10 {
				t.Fatalf("total=%d group=%d: got %d streams", total, groupID, count)
			}
		}
		if gotTotal != total {
			t.Fatalf("lost streams: requested=%d actual=%d", total, gotTotal)
		}
	}

	invalidateAllCaches()
	setStreamsPerCred(16) // Native callers cannot bypass the ten-stream cap.
	if got := streamsPerCredValue(); got != 10 {
		t.Fatalf("native stride=%d, want 10", got)
	}
	fetches := 0
	fetch := func(context.Context, string) (string, string, []string, int, error) {
		fetches++
		return fmt.Sprintf("credential-%d", fetches), "pass", []string{"relay:3478"}, 3600, nil
	}
	for streamID := 0; streamID < 21; streamID++ {
		user, _, _, err := getCredsCached(context.Background(), "same-call", streamID, fetch)
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("credential-%d", 1+streamID/10); user != want {
			t.Fatalf("stream %d got %s, want %s", streamID, user, want)
		}
	}
	if fetches != 3 {
		t.Fatalf("21 streams fetched %d credentials, want 3", fetches)
	}
}
