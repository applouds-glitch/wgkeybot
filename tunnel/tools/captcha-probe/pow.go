package main

// Mirror of solvePoW / encodePowResultV2 / buildPowTelemetry from
// tunnel/tools/libwg-go/vk_captcha.go.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	mathrand "math/rand"
	"strconv"
	"strings"
	"time"
)

func solvePoW(powInput string, difficulty int, v2 bool, hw, mem int) string {
	if powInput == "" || difficulty <= 0 {
		return ""
	}
	// The real browser solved difficulty 2 with nonce 76 in duration_ms=2,
	// so keep the reported solve time small and honest.
	start := time.Now()
	time.Sleep(time.Duration(2+mathrand.Intn(4)) * time.Millisecond)
	target := strings.Repeat("0", difficulty)
	for nonce := 0; nonce <= 10000000; nonce++ {
		hash := sha256.Sum256([]byte(powInput + strconv.Itoa(nonce)))
		hexHash := hex.EncodeToString(hash[:])
		if !strings.HasPrefix(hexHash, target) {
			continue
		}
		if !v2 {
			return hexHash
		}
		return encodePowResultV2(hexHash, nonce, time.Since(start), hw, mem)
	}
	return ""
}

func encodePowResultV2(hexHash string, nonce int, duration time.Duration, hw, mem int) string {
	telemetry := buildPowTelemetry(hw, mem)

	canonicalTelemetry, err := json.Marshal(telemetry)
	if err != nil {
		return ""
	}
	telHashBytes := sha256.Sum256(canonicalTelemetry)
	telHash := hex.EncodeToString(telHashBytes[:])

	payload := struct {
		Hash       string      `json:"hash"`
		Nonce      int         `json:"nonce"`
		DurationMs int64       `json:"duration_ms"`
		Telemetry  interface{} `json:"telemetry"`
		TelHash    string      `json:"tel_hash"`
	}{
		Hash:       hexHash,
		Nonce:      nonce,
		DurationMs: duration.Milliseconds(),
		Telemetry:  telemetry,
		TelHash:    telHash,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return "v2." + base64.StdEncoding.EncodeToString(raw)
}

// buildPowTelemetry replicates the reference browser capture field by
// field: desktop Chrome telemetry as the accepted captcha session reported.
func buildPowTelemetry(hw, mem int) map[string]interface{} {
	userAgent := captchaDesktopUserAgent

	ok := func(result interface{}) map[string]interface{} {
		return map[string]interface{}{"ok": true, "result": result}
	}

	return map[string]interface{}{
		"globals": ok(map[string]interface{}{
			"doc":       true,
			"win":       true,
			"nav":       true,
			"webdriver": false,
			"hw":        hw,
			"mem":       mem,
		}),
		"ua": ok(map[string]interface{}{"userAgent": userAgent}),
		"frame": ok(map[string]interface{}{
			"frameElement":       nil,
			"ancestorOriginsLen": 0,
			"parentAccessible":   true,
		}),
		"match_media": ok(map[string]interface{}{
			"prefersDark":   true,
			"prefersLight":  false,
			"reducedMotion": false,
			"pointerFine":   false,
		}),
		"plugins": ok(map[string]interface{}{
			// Desktop Chrome PDF viewer plugins, as in the reference capture.
			"length":   5,
			"names":    []string{"PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer", "Microsoft Edge PDF Viewer", "WebKit built-in PDF"},
			"isChrome": true,
		}),
		"nav_tamper": ok(map[string]interface{}{"tampered": false}),
		"referrer": ok(map[string]interface{}{
			"referrer": "",
			"inIframe": false,
			"domain":   "id.vk.ru",
		}),
		"devtools": ok(map[string]interface{}{"open": false}),
		"css":      ok(map[string]interface{}{"expectedMissing": 0}),
		"native_integrity": ok(map[string]interface{}{
			"protoMatch": true,
			"xhrNative":  true,
		}),
	}
}
