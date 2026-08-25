/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The lockout window must grow with each consecutive unsolved captcha: a flat
// window is what let an unsolvable captcha reopen the solve ladder — dialog
// included — every minute and a half for as long as the tunnel was up.
func TestBumpCaptchaLockoutEscalates(t *testing.T) {
	resetCaptchaLockout()
	defer resetCaptchaLockout()

	want := []time.Duration{
		60 * time.Second,
		2 * time.Minute,
		4 * time.Minute,
		8 * time.Minute,
		10 * time.Minute, // capped
		10 * time.Minute,
	}
	for i, w := range want {
		if got := bumpCaptchaLockout(); got != w {
			t.Fatalf("bump %d: got %v, want %v", i+1, got, w)
		}
		if got := captchaFailureStreak(); got != i+1 {
			t.Fatalf("streak after bump %d: got %d", i+1, got)
		}
	}
	if remaining := captchaLockoutRemaining(); remaining <= 0 {
		t.Fatalf("lockout should still be armed, got %v", remaining)
	}

	resetCaptchaLockout()
	if got := captchaFailureStreak(); got != 0 {
		t.Fatalf("streak after reset: got %d, want 0", got)
	}
	if got := captchaLockoutRemaining(); got != 0 {
		t.Fatalf("remaining after reset: got %v, want 0", got)
	}
}

// A worker must reach the give-up threshold within a bounded number of ladders,
// whichever worker happened to run them: the streak is session-wide.
func TestCaptchaFailureStreakReachesGiveUpBudget(t *testing.T) {
	resetCaptchaLockout()
	defer resetCaptchaLockout()

	for i := 0; i < maxCaptchaFailStreak; i++ {
		if captchaFailureStreak() >= maxCaptchaFailStreak {
			t.Fatalf("gave up early, after %d ladders", i)
		}
		bumpCaptchaLockout()
	}
	if captchaFailureStreak() < maxCaptchaFailStreak {
		t.Fatalf("streak %d never reached the budget %d", captchaFailureStreak(), maxCaptchaFailStreak)
	}
}

func TestCredRetryDelayBacksOff(t *testing.T) {
	const jitter = 5 * time.Second
	want := []time.Duration{
		30 * time.Second,
		time.Minute,
		2 * time.Minute,
		4 * time.Minute,
		5 * time.Minute, // capped
		5 * time.Minute,
	}
	for i, base := range want {
		got := credRetryDelay(i + 1)
		if got < base || got >= base+jitter {
			t.Fatalf("streak %d: got %v, want [%v, %v)", i+1, got, base, base+jitter)
		}
	}
	if got := credRetryDelay(0); got < 30*time.Second {
		t.Fatalf("zero streak: got %v, want at least the base delay", got)
	}
}

func TestIsTerminalCredError(t *testing.T) {
	terminal := []error{
		fmt.Errorf("fetchCreds: %w", errCallRequiresAuth),
		callUnavailablef("legacy getAnonymousToken: VK call unavailable (error_code %d)", 9001),
	}
	for _, err := range terminal {
		if !isTerminalCredError(err) {
			t.Fatalf("%v should be terminal", err)
		}
	}

	retryable := []error{
		fmt.Errorf("fetchCreds: %w", errCaptchaUnsolved),
		fmt.Errorf("fetchCreds: %w", errCaptchaLockout),
		fmt.Errorf("all VK credentials failed: rate limit"),
	}
	for _, err := range retryable {
		if isTerminalCredError(err) {
			t.Fatalf("%v should not be terminal", err)
		}
	}
}

// The startup path (wgTurnProxyStart) classifies a failed pre-fetch by substring,
// so both captcha errors must keep carrying the marker it looks for.
func TestCaptchaErrorsKeepStartupMarker(t *testing.T) {
	for _, err := range []error{errCaptchaUnsolved, errCaptchaLockout} {
		if !strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") {
			t.Fatalf("%q lost the CAPTCHA_WAIT_REQUIRED marker", err)
		}
	}
}
