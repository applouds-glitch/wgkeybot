/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"testing"
	"time"
)

// A slot is also missed when its group's link has changed; the credential in it
// has then not expired, and its expiry is no reason to report.
func TestCacheMissReason(t *testing.T) {
	now := time.Now()
	prev := TurnCredentials{Link: "old", FetchedAt: now.Add(-40 * time.Second), ExpiresAt: now.Add(58 * time.Minute)}

	got := cacheMissReason(prev, "new", now)
	if want := "cached creds are for another link (lived 40s)"; got != want {
		t.Fatalf("link changed: %q, want %q", got, want)
	}

	prev.Link = "new"
	prev.ExpiresAt = now.Add(-5 * time.Second)
	if got, want := cacheMissReason(prev, "new", now), "previous creds lived 40s (expired 5s ago)"; got != want {
		t.Fatalf("expired: %q, want %q", got, want)
	}
}
