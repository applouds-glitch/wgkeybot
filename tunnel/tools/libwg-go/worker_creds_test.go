/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"reflect"
	"testing"
	"time"
)

// Every worker, including workers from another credential group, must keep
// that group's VK response order. Startup must not probe a second host merely
// because another worker is already connecting to the first one.
func TestAssignServersPreservesVKOrderForEveryStream(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	groups := [][]string{
		{"3.3.3.3:3478", "1.1.1.1:3478", "2.2.2.2:3478"},
		{"2.2.2.2:3478", "3.3.3.3:3478"},
	}
	for streamID := 0; streamID < 10; streamID++ {
		for _, addrs := range groups {
			if got := assignServers(addrs); !reflect.DeepEqual(got, addrs) {
				t.Fatalf("stream %d: got %v, want VK order %v", streamID, got, addrs)
			}
		}
	}
}

// Proof from a fallback or another credential group must not replace a primary
// that has not failed. There is no startup election after the first handshake.
func TestAssignServersKeepsVKOrderAfterHandshakeProof(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478"}
	noteServerHandshakeOKAt(addrs[1], time.Now().Add(-time.Minute))
	if got := assignServers(addrs); !reflect.DeepEqual(got, addrs) {
		t.Fatalf("fallback proof changed primary: got %v, want %v", got, addrs)
	}
	noteServerHandshakeOK(addrs[0])
	if got := assignServers(addrs); !reflect.DeepEqual(got, addrs) {
		t.Fatalf("both servers proving themselves changed order: got %v, want %v", got, addrs)
	}
}

// Failed hosts are excluded entirely, including from Allocate failover; the
// remaining candidates retain the API order rather than alphabetical order.
func TestAssignServersSkipsUnavailableServers(t *testing.T) {
	for _, failure := range []string{"data-plane", "repeated-allocate"} {
		t.Run(failure, func(t *testing.T) {
			resetServerHealth()
			defer resetServerHealth()
			addrs := []string{"2.2.2.2:3478", "3.3.3.3:3478", "1.1.1.1:3478"}
			now := time.Now()
			if failure == "data-plane" {
				noteServerHandshakeFailureAt(addrs[0], now.Add(-time.Second), now)
			} else {
				for i := 0; i < serverFailThreshold; i++ {
					age := time.Duration(serverFailThreshold-1-i) * (serverFailCoalesce + time.Second)
					noteServerFailureAt(addrs[0], now.Add(-age))
				}
			}
			if got := assignServers(addrs); !reflect.DeepEqual(got, addrs[1:]) {
				t.Fatalf("got %v, want available servers %v", got, addrs[1:])
			}
		})
	}
}

// An uplink outage must not leave an empty candidate list or reintroduce
// round-robin probing. A new tunnel session must also forget old exclusions.
func TestAssignServersRetriesVKOrderAfterOutage(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478"}
	now := time.Now()
	for _, addr := range addrs {
		noteServerHandshakeFailureAt(addr, now.Add(-time.Second), now)
	}
	if got := assignServers(addrs); !reflect.DeepEqual(got, addrs) {
		t.Fatalf("outage fallback: got %v, want %v", got, addrs)
	}

	// Only the fallback recovers, so it temporarily becomes the primary.
	noteServerHandshakeOKAt(addrs[1], now.Add(time.Second))
	if got := assignServers(addrs); !reflect.DeepEqual(got, addrs[1:]) {
		t.Fatalf("got %v, want recovered server %v", got, addrs[1:])
	}
	resetServerHealth()
	if got := assignServers(addrs); !reflect.DeepEqual(got, addrs) {
		t.Fatalf("new session retained exclusions: got %v, want %v", got, addrs)
	}
}

func TestAssignServersDoesNotMutateCachedAddresses(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478", "2.2.2.2:3478"}
	orig := append([]string(nil), addrs...)
	noteServerDemotedAt(addrs[0], time.Now())
	assignServers(addrs)
	if !reflect.DeepEqual(addrs, orig) {
		t.Fatalf("cached list mutated: got %v, want %v", addrs, orig)
	}
}

// A manual TurnIP pin has no alternative. Keep retrying it even after failures.
func TestAssignServersSingleServer(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"1.1.1.1:3478"}
	noteServerDemotedAt(addrs[0], time.Now())
	if got := assignServers(addrs); !reflect.DeepEqual(got, addrs) {
		t.Fatalf("got %v, want pinned server %v", got, addrs)
	}
}
