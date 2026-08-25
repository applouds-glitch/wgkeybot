/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/pion/stun/v3"
)

// allocateErr wraps err the way the Allocate race does (dialAndAllocate →
// runWithCreds), so the tests see the exact chain runWorker classifies.
func allocateErr(err error) error {
	return fmt.Errorf("TURN allocate: all 2 servers failed: %w",
		fmt.Errorf("TURN allocate: %w", err))
}

// writeErr rebuilds a socket write failure to a TURN server from the given
// local port — the shape that carries digits into the error text.
func writeErr(localPort int, errno syscall.Errno) error {
	return &net.OpError{
		Op:     "write",
		Net:    "udp",
		Source: &net.UDPAddr{IP: net.IPv4(10, 69, 196, 227), Port: localPort},
		Addr:   &net.UDPAddr{IP: net.IPv4(193, 203, 43, 42), Port: 19302},
		Err:    errno,
	}
}

func turnErr(code stun.ErrorCode) error {
	return &stun.TurnError{
		StunMessageType: stun.MessageType{Method: stun.MethodAllocate, Class: stun.ClassErrorResponse},
		ErrorCodeAttr:   stun.ErrorCodeAttribute{Code: code},
	}
}

// Field regression: local port 50819 put "508" into the message of a plain
// broken-pipe write, which the old substring matcher read as Insufficient
// Capacity and force-expired a healthy pre-flight credential mid-outage.
func TestClassifyCredErrorIgnoresPortDigits(t *testing.T) {
	ports := []int{50819, 54012, 48601, 52901}
	for _, port := range ports {
		err := allocateErr(writeErr(port, syscall.EPIPE))
		if classifyCredError(err) {
			t.Errorf("port %d: transport error classified as credential error: %v", port, err)
		}
		if isQuotaError(err) {
			t.Errorf("port %d: transport error classified as quota error: %v", port, err)
		}
	}
}

func TestClassifyCredErrorTransportErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"broken pipe", allocateErr(writeErr(50819, syscall.EPIPE))},
		{"no route to host", allocateErr(writeErr(48600, syscall.EHOSTUNREACH))},
		{"connection refused", allocateErr(writeErr(54862, syscall.ECONNREFUSED))},
		{"bare errno", fmt.Errorf("TURN allocate: %w", syscall.EHOSTUNREACH)},
		{"dial timeout", allocateErr(&net.OpError{Op: "dial", Net: "udp", Err: errors.New("i/o timeout")})},
	}
	for _, tc := range cases {
		if classifyCredError(tc.err) {
			t.Errorf("%s: must not force a credential re-fetch: %v", tc.name, tc.err)
		}
	}
}

func TestClassifyCredErrorTurnCodes(t *testing.T) {
	cases := []struct {
		code      stun.ErrorCode
		wantCred  bool
		wantQuota bool
	}{
		{stun.CodeUnauthorized, true, false},         // 401
		{stun.CodeStaleNonce, true, false},           // 438
		{stun.CodeAllocMismatch, true, false},        // 437
		{stun.CodeWrongCredentials, true, false},     // 441
		{stun.CodeAllocQuotaReached, true, true},     // 486
		{stun.CodeInsufficientCapacity, true, false}, // 508
		{stun.CodeBadRequest, false, false},          // 400
		{stun.CodeServerError, false, false},         // 500
	}
	for _, tc := range cases {
		err := allocateErr(turnErr(tc.code))
		if got := classifyCredError(err); got != tc.wantCred {
			t.Errorf("code %d: classifyCredError = %v, want %v", tc.code, got, tc.wantCred)
		}
		if got := isQuotaError(err); got != tc.wantQuota {
			t.Errorf("code %d: isQuotaError = %v, want %v", tc.code, got, tc.wantQuota)
		}
	}
}

// Errors that never carry a STUN code (our own wrappers, non-pion paths) still
// have to be classified by text.
func TestClassifyCredErrorTextFallback(t *testing.T) {
	cases := []struct {
		err  string
		want bool
	}{
		{"allocate error response (error 401: Unauthorized)", true},
		{"allocate error response (error 486: Allocation Quota Reached)", true},
		{"stale nonce", true},
		{"vk: error 29 rate limit", true},
		{"dead-stream: no RX for >30s", false},
		{"session handshake wrap #1: short buffer", false},
		{"TUN write: file already closed", false},
	}
	for _, tc := range cases {
		if got := classifyCredError(errors.New(tc.err)); got != tc.want {
			t.Errorf("%q: classifyCredError = %v, want %v", tc.err, got, tc.want)
		}
	}
}
