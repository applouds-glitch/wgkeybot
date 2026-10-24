/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

// groupStreamCounts keeps at least one stream per link, splits a smaller
// request evenly, and adds full-capacity groups for a larger request. Extra
// groups reuse links cyclically at the call site, with their own credentials.
func groupStreamCounts(links, perCred, requested int) []int {
	links = max(links, 1)
	perCred = max(perCred, 1)
	if requested <= 0 || requested == links*perCred {
		counts := make([]int, links)
		for i := range counts {
			counts[i] = perCred
		}
		return counts
	}
	if requested < links*perCred {
		requested = max(requested, links)
		counts := make([]int, links)
		for i := range counts {
			counts[i] = requested / links
			if i < requested%links {
				counts[i]++
			}
		}
		return counts
	}
	counts := make([]int, (requested-1)/perCred+1)
	for i := range counts {
		counts[i] = min(perCred, requested)
		requested -= counts[i]
	}
	return counts
}
