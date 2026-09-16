/* SPDX-License-Identifier: Apache-2.0 */

package main

// planCredentialGroups keeps each group's credential within its allocation
// limit. Extra groups cycle through the call links but fetch into independent
// cache slots. All groups use the same stride for getCacheID; the last may be
// short. When fewer streams are requested, shrink groups without rounding away
// the remainder or fetching credentials for groups with no workers.
func planCredentialGroups(links []string, total, perCred int) ([]string, int, int) {
	perCred = clampStreamsPerCred(perCred)
	if len(links) == 0 {
		links = []string{""}
	}
	if total <= 0 {
		total = len(links) * perCred
	} else if total < len(links)*perCred {
		perCred = 1 + (total-1)/len(links)
	}
	groups := make([]string, 1+(total-1)/perCred)
	for i := range groups {
		groups[i] = links[i%len(links)]
	}
	return groups, perCred, total
}
