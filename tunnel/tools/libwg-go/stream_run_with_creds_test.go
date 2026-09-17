/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func relayRefusal(code stun.ErrorCode) error {
	return fmt.Errorf("TURN allocate: %w", turnErr(code))
}

func relayTimeout() error {
	return fmt.Errorf("TURN allocate: %w", &net.OpError{Op: "read", Net: "udp", Err: errors.New("i/o timeout")})
}

// An attempt across two relays has two answers, and the rotation decision needs
// both: keeping only the last one to arrive let a timeout hide a 486, or a 486
// hide a 401, depending on which relay happened to be slower.
func TestAllocateFailedErrorKeepsEveryRelaysAnswer(t *testing.T) {
	err := &allocateFailedError{[]error{relayRefusal(stun.CodeAllocQuotaReached), relayTimeout()}}
	if !isQuotaError(err) {
		t.Fatalf("486 lost behind the other relay's timeout: %v", err)
	}
	if !strings.Contains(err.Error(), "all 2 servers failed") || !strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("message dropped a relay's answer: %v", err)
	}

	err = &allocateFailedError{[]error{relayRefusal(stun.CodeAllocQuotaReached), relayRefusal(stun.CodeUnauthorized)}}
	if !hasAuthRefusal(err) {
		t.Fatalf("401 lost behind the other relay's 486: %v", err)
	}
	if hasAuthRefusal(&allocateFailedError{[]error{relayRefusal(stun.CodeAllocQuotaReached), relayTimeout()}}) {
		t.Fatal("a 486 next to a timeout read as an authentication refusal")
	}
}

// The 2026-09-17 log: one relay in quota cooldown for the identity, the other
// silent under a dark uplink. The pair used to read as "quota" and burned a
// credential with seven hours left, for a trip to VK the same outage then
// failed twice. The identity is spent only when every relay has refused it.
func TestQuotaOnOneRelayDoesNotRotateTheCredential(t *testing.T) {
	resetCredentialQuota()
	defer resetCredentialQuota()
	now := time.Now()
	addrs := []string{"relay-a", "relay-b"}
	noteCredentialRelayQuota("u", "p", "relay-a", now)

	mixed := &allocateFailedError{[]error{relayRefusal(stun.CodeAllocQuotaReached), relayTimeout()}}
	if shouldRotateCredentials(mixed, "u", "p", addrs, now) {
		t.Fatal("486 from one relay plus a timeout from the other rotated the credential")
	}
	handshake := fmt.Errorf("%w: relay never answered in 2s", errDataPlaneHandshake)
	if shouldRotateCredentials(handshake, "u", "p", addrs, now) {
		t.Fatal("a failed data-plane handshake rotated the credential")
	}

	noteCredentialRelayQuota("u", "p", "relay-b", now)
	both := &allocateFailedError{[]error{relayRefusal(stun.CodeAllocQuotaReached), relayRefusal(stun.CodeAllocQuotaReached)}}
	if !shouldRotateCredentials(both, "u", "p", addrs, now) {
		t.Fatal("486 from every relay did not rotate the credential")
	}
	if !shouldRotateCredentials(errCredentialSaturated, "u", "p", addrs, now) {
		t.Fatal("an identity refused everywhere did not rotate without dialing")
	}
	if !isQuotaError(errCredentialSaturated) {
		t.Fatal("saturation is a quota failure: it takes the quota retry delay")
	}
}

// Authentication refusals condemn the credential wherever they come from.
func TestAuthRefusalRotatesRegardlessOfQuotaState(t *testing.T) {
	resetCredentialQuota()
	defer resetCredentialQuota()
	now := time.Now()
	addrs := []string{"relay-a", "relay-b"}
	for _, code := range []stun.ErrorCode{stun.CodeUnauthorized, stun.CodeStaleNonce, stun.CodeWrongCredentials} {
		err := &allocateFailedError{[]error{relayTimeout(), relayRefusal(code)}}
		if !shouldRotateCredentials(err, "u", "p", addrs, now) {
			t.Errorf("code %d did not rotate the credential", code)
		}
	}
	if shouldRotateCredentials(&allocateFailedError{[]error{relayTimeout(), relayTimeout()}}, "u", "p", addrs, now) {
		t.Error("two timeouts rotated the credential")
	}
	blackhole := errors.New("TURN blackhole: Failed to refresh allocation: error 401: Unauthorized (relay RX: closed)")
	if !shouldRotateCredentials(blackhole, "u", "p", addrs, now) {
		t.Error("a restated 401 blackhole did not rotate the credential")
	}
}
