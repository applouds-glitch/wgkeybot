package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// One session must speak about exactly one VK family: the form's `domain`, the
// Origin/Referer, the API host and the telemetry's referrer all come from the
// redirect_uri VK issued.
func TestCaptchaEndpointsFollowRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		wantDomain  string
		wantPage    string
		wantAPI     string
	}{
		{
			name:        "vk.com session",
			redirectURI: "https://id.vk.com/captcha?domain=vk.com&session_token=abc",
			wantDomain:  "vk.com",
			wantPage:    "id.vk.com",
			wantAPI:     "api.vk.com",
		},
		{
			name:        "vk.ru session",
			redirectURI: "https://id.vk.ru/captcha?domain=vk.ru&session_token=abc",
			wantDomain:  "vk.ru",
			wantPage:    "id.vk.ru",
			wantAPI:     "api.vk.ru",
		},
		{
			name:        "no domain in query falls back to the page host family",
			redirectURI: "https://id.vk.com/captcha?session_token=abc",
			wantDomain:  "vk.com",
			wantPage:    "id.vk.com",
			wantAPI:     "api.vk.com",
		},
		{
			name:        "unparseable redirect_uri keeps the historical defaults",
			redirectURI: "://",
			wantDomain:  "vk.ru",
			wantPage:    "id.vk.ru",
			wantAPI:     "api.vk.ru",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := captchaEndpointsFromRedirectURI(tt.redirectURI)
			if ep.Domain != tt.wantDomain || ep.PageHost != tt.wantPage || ep.APIHost != tt.wantAPI {
				t.Fatalf("endpoints = %+v, want domain=%s page=%s api=%s",
					ep, tt.wantDomain, tt.wantPage, tt.wantAPI)
			}
			if got, want := ep.origin(), "https://"+tt.wantPage; got != want {
				t.Fatalf("origin = %s, want %s", got, want)
			}
			if got, want := ep.referer(), "https://"+tt.wantPage+"/"; got != want {
				t.Fatalf("referer = %s, want %s", got, want)
			}
			methodURL := ep.methodURL("captchaNotRobot.check")
			if !strings.HasPrefix(methodURL, "https://"+tt.wantAPI+"/method/captchaNotRobot.check?v=") {
				t.Fatalf("methodURL = %s, want host %s", methodURL, tt.wantAPI)
			}
		})
	}
}

// tel_hash is a digest of the telemetry's own bytes, and VK recomputes it with
// JSON.stringify. Go's default encoder escapes <, > and & where JavaScript's
// does not, so any such character reaching the telemetry would make our digest
// disagree with the one their solver produces — and the only symptom would be a
// BOT verdict with nothing in the logs.
func TestPowResultHashesTelemetryLikeJSONStringify(t *testing.T) {
	value := map[string]interface{}{
		"referrer": "https://id.vk.ru/?a=1&b=2",
		"markup":   "<script>",
	}

	encoded, err := marshalLikeJSONStringify(value)
	if err != nil {
		t.Fatalf("marshalLikeJSONStringify: %v", err)
	}
	got := string(encoded)

	for _, char := range []string{"&", "<", ">"} {
		if !strings.Contains(got, char) {
			t.Errorf("%q was escaped away; JSON.stringify would have kept it: %s", char, got)
		}
	}
	if strings.Contains(got, `\u00`) {
		t.Errorf("output carries unicode escapes JSON.stringify would not emit: %s", got)
	}
	if strings.HasSuffix(got, "\n") {
		t.Errorf("trailing newline would be hashed into tel_hash: %q", got)
	}

	// The default encoder is what this exists to avoid; if it ever stops
	// differing, the helper is no longer earning its keep.
	plain, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(plain) == got {
		t.Error("json.Marshal no longer escapes HTML — marshalLikeJSONStringify can be dropped")
	}
}

// The PoW telemetry and the componentDone device JSON describe the same
// machine, so their core/memory counts may never disagree — including on builds
// with no Android device profile, where both fall back to the same draw.
func TestDeviceJSONAndTelemetryAgreeOnHardware(t *testing.T) {
	profile := Profile{UserAgent: "ua", AcceptLanguage: "ru-RU,ru;q=0.9"}
	ep := captchaEndpointsFromRedirectURI("https://id.vk.ru/captcha?domain=vk.ru")

	var device struct {
		HardwareConcurrency int `json:"hardwareConcurrency"`
		DeviceMemory        int `json:"deviceMemory"`
	}
	raw := buildCaptchaDeviceJSON(profile, randomViewport())
	if err := json.Unmarshal([]byte(raw), &device); err != nil {
		t.Fatalf("device JSON is invalid: %v (%s)", err, raw)
	}

	telemetry := buildPowTelemetry(profile, ep)
	globals, ok := telemetry["globals"].(map[string]interface{})["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("telemetry globals missing: %+v", telemetry["globals"])
	}
	if globals["hw"] != device.HardwareConcurrency {
		t.Fatalf("telemetry hw=%v, device JSON hardwareConcurrency=%d", globals["hw"], device.HardwareConcurrency)
	}
	if globals["mem"] != device.DeviceMemory {
		t.Fatalf("telemetry mem=%v, device JSON deviceMemory=%d", globals["mem"], device.DeviceMemory)
	}

	referrer, ok := telemetry["referrer"].(map[string]interface{})["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("telemetry referrer missing: %+v", telemetry["referrer"])
	}
	if referrer["domain"] != ep.PageHost {
		t.Fatalf("telemetry referrer domain=%v, want the session's page host %s", referrer["domain"], ep.PageHost)
	}
}
