/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestCredentialExpiryFromUsername(t *testing.T) {
	until := time.Unix(1_800_000_000, 0)
	if got, ok := credentialExpiryFromUsername("1800000000:abcdef"); !ok || !got.Equal(until) {
		t.Fatalf("stamped username: got %v ok=%v", got, ok)
	}
	for _, bad := range []string{"", "abcdef", ":abcdef", "x:abcdef", "-5:abcdef", "0:abcdef"} {
		if _, ok := credentialExpiryFromUsername(bad); ok {
			t.Fatalf("%q must not parse", bad)
		}
	}
}

func TestCredentialCacheExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fallback := now.Add(credentialLifetime - cacheSafetyMargin)
	cap := now.Add(time.Duration(defaultCycleSecs) * time.Second)
	cases := []struct {
		name  string
		until time.Time
		want  time.Time
	}{
		{"hours away", now.Add(8 * time.Hour), now.Add(8*time.Hour - credentialExpiryBuffer)},
		{"beyond cycle cap", now.Add(20 * time.Hour), cap},
		{"inside the buffer", now.Add(credentialExpiryBuffer / 2), fallback},
		{"already expired", now.Add(-time.Hour), fallback},
	}
	for _, c := range cases {
		if got := credentialCacheExpiry(c.until, now); !got.Equal(c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// The VK API reports no lifetime; the stamp in the username decides the TTL.
func TestGetCredsCachedUsesUsernameExpiry(t *testing.T) {
	invalidateAllCaches()
	t.Cleanup(invalidateAllCaches)
	until := time.Now().Add(6 * time.Hour).Truncate(time.Second)
	user := strconv.FormatInt(until.Unix(), 10) + ":ttl-test"
	fetch := func(context.Context, string) (string, string, []string, int, error) {
		return user, "p", []string{"relay"}, 0, nil
	}
	if _, _, _, err := getCredsCached(context.Background(), "link", 0, fetch); err != nil {
		t.Fatal(err)
	}
	got := getStreamCache(0).creds.ExpiresAt
	want := until.Add(-credentialExpiryBuffer)
	if d := got.Sub(want); d < -time.Second || d > time.Second {
		t.Fatalf("ExpiresAt %v, want %v (from username stamp)", got, want)
	}

	// No stamp, no lifetime: the fallback TTL still applies.
	invalidateAllCaches()
	plain := func(context.Context, string) (string, string, []string, int, error) {
		return "plain-user", "p", []string{"relay"}, 0, nil
	}
	if _, _, _, err := getCredsCached(context.Background(), "link", 0, plain); err != nil {
		t.Fatal(err)
	}
	got = getStreamCache(0).creds.ExpiresAt
	want = time.Now().Add(credentialLifetime - cacheSafetyMargin)
	if d := got.Sub(want); d < -2*time.Second || d > 2*time.Second {
		t.Fatalf("fallback ExpiresAt %v, want ~%v", got, want)
	}
}
