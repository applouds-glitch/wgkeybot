package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestCaptchaFormMatchesCapturedCheckboxOrder(t *testing.T) {
	values := url.Values{}
	values.Set("session_token", "token")
	values.Set("domain", "vk.com")
	values.Set("adFp", "")
	values.Set("accelerometer", "[]")
	values.Set("gyroscope", "[]")
	values.Set("motion", "[]")
	values.Set("cursor", "[]")
	values.Set("taps", "[]")
	values.Set("connectionRtt", "[]")
	values.Set("connectionDownlink", "[9.2,9.2]")
	values.Set("browser_fp", "fingerprint")
	values.Set("hash", "v2.hash")
	values.Set("answer", "e30=")
	values.Set("debug_info", "debug")
	values.Set("access_token", "")

	got := encodeCaptchaForm("captchaNotRobot.check", values)
	want := "session_token=token&domain=vk.com&adFp=&accelerometer=%5B%5D" +
		"&gyroscope=%5B%5D&motion=%5B%5D&cursor=%5B%5D&taps=%5B%5D" +
		"&connectionRtt=%5B%5D&connectionDownlink=%5B9.2%2C9.2%5D" +
		"&browser_fp=fingerprint&hash=v2.hash&answer=e30%3D&debug_info=debug&access_token="
	if got != want {
		t.Fatalf("unexpected encoded checkbox form:\n got: %s\nwant: %s", got, want)
	}
}

func TestNetworkSamplesMatchCapturedShape(t *testing.T) {
	// The captured browser sent one constant rtt and one constant downlink
	// value, one sample per 200ms tick of the componentDone→check window.
	for _, n := range []int{27, 28, 34} {
		rtt, downlink := generateNetworkSamples(n)
		var rttSamples, dlSamples []float64
		if err := json.Unmarshal([]byte(rtt), &rttSamples); err != nil {
			t.Fatalf("invalid rtt JSON: %v", err)
		}
		if err := json.Unmarshal([]byte(downlink), &dlSamples); err != nil {
			t.Fatalf("invalid downlink JSON: %v", err)
		}
		if len(rttSamples) != n || len(dlSamples) != n {
			t.Fatalf("sample count mismatch: rtt=%d downlink=%d want %d", len(rttSamples), len(dlSamples), n)
		}
		for _, sample := range rttSamples[1:] {
			if sample != rttSamples[0] {
				t.Fatalf("rtt must be one constant value, got %v", rttSamples)
			}
		}
		for _, sample := range dlSamples[1:] {
			if sample != dlSamples[0] {
				t.Fatalf("downlink must be one constant value, got %v", dlSamples)
			}
		}
	}
}

func TestCaptchaUsesCapturedAPIVersion(t *testing.T) {
	if captchaNotRobotAPIVersion != "5.131" {
		t.Fatalf("unexpected captcha API version: %s", captchaNotRobotAPIVersion)
	}
}

func TestParseSliderCaptchaContentResponseDistinguishesGenericError(t *testing.T) {
	_, err := parseSliderCaptchaContentResponse(map[string]interface{}{
		"response": map[string]interface{}{
			"status": "ERROR",
			"reason": "invalid state",
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, errCaptchaRateLimit) {
		t.Fatalf("generic ERROR must not be classified as rate limit: %v", err)
	}
	if !strings.Contains(err.Error(), "status: ERROR") || !strings.Contains(err.Error(), "response_keys=reason,status") {
		t.Fatalf("diagnostic detail missing: %v", err)
	}
}

func TestParseSliderCaptchaContentResponsePreservesRateLimit(t *testing.T) {
	_, err := parseSliderCaptchaContentResponse(map[string]interface{}{
		"response": map[string]interface{}{
			"status": "ERROR_LIMIT",
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errCaptchaRateLimit) {
		t.Fatalf("ERROR_LIMIT must retain rate-limit sentinel: %v", err)
	}
}

func TestCaptchaSessionExhaustedDoesNotTreatGenericGetContentErrorAsRateLimit(t *testing.T) {
	if isCaptchaSessionExhausted(errors.New("slider getContent status: ERROR")) {
		t.Fatal("generic getContent ERROR must not be treated as rate limit")
	}
	if !isCaptchaSessionExhausted(errors.New("slider getContent status: ERROR_LIMIT")) {
		t.Fatal("ERROR_LIMIT must be treated as an exhausted captcha session")
	}
}
