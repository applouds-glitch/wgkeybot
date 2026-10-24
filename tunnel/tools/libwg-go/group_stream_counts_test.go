/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"slices"
	"testing"
)

func TestGroupStreamCounts(t *testing.T) {
	for _, tt := range []struct {
		links, perCred, requested int
		want                      []int
	}{
		{1, 4, 4, []int{4}},
		{3, 4, 4, []int{2, 1, 1}},
		{3, 4, 5, []int{2, 2, 1}},
		{3, 4, 2, []int{1, 1, 1}},
		{3, 4, 12, []int{4, 4, 4}},
		{3, 4, 0, []int{4, 4, 4}},
		{1, 9, 12, []int{9, 3}},
		{2, 4, 9, []int{4, 4, 1}},
		{3, 4, 11, []int{4, 4, 3}},
		{2, 10, 15, []int{8, 7}},
		{0, 0, 0, []int{1}},
		{-1, -2, 3, []int{1, 1, 1}},
		{2, 0, -1, []int{1, 1}},
	} {
		t.Run(fmt.Sprintf("%d_%d_%d", tt.links, tt.perCred, tt.requested), func(t *testing.T) {
			got := groupStreamCounts(tt.links, tt.perCred, tt.requested)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("groupStreamCounts(%d, %d, %d) = %v, want %v", tt.links, tt.perCred, tt.requested, got, tt.want)
			}
		})
	}
	t.Run("exact_total_and_capacity", func(t *testing.T) {
		for links := 1; links <= 12; links++ {
			for perCred := 1; perCred <= 10; perCred++ {
				for requested := links; requested <= 2*links*perCred+1; requested++ {
					counts := groupStreamCounts(links, perCred, requested)
					total := 0
					for _, count := range counts {
						if count < 1 || count > perCred {
							t.Fatalf("(%d,%d,%d): group size outside 1..%d: %v", links, perCred, requested, perCred, counts)
						}
						total += count
					}
					if total != requested || len(counts) < links {
						t.Fatalf("(%d,%d,%d): groups %v total %d; want all links and exact total", links, perCred, requested, counts, total)
					}
				}
			}
		}
	})
}
