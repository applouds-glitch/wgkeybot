/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <stdlib.h>
extern const char* requestCaptcha(const char* redirect_uri);
extern const char* getCaptchaDeviceProfile();
*/
import "C"

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	neturl "net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
)

// errSliderDetected signals that the settings response advertised a slider
// captcha, so the HTTP/checkbox path cannot solve it and a slider-aware
// solver (slider POC or WebView) must run instead.
var errSliderDetected = errors.New("slider_detected")

// errCaptchaBot is returned when the VK API responds with status "bot" on a
// checkbox check, signalling the account looks automated and a harder
// challenge (slider) should be tried instead.
var errCaptchaBot = errors.New("captcha_bot")

// errCaptchaRateLimit is returned when VK throttles the captcha endpoint
// (check or getContent status ERROR_LIMIT). A generic ERROR is kept distinct:
// it may indicate an invalid captcha state or request rather than throttling. The
// session is spent: retrying or escalating to another auto solver only burns
// more requests and digs the rate-limit hole deeper, so callers must stop
// hammering and fall back to the WebView instead.
var errCaptchaRateLimit = errors.New("captcha_rate_limit")

// isCaptchaSessionExhausted reports whether err means VK has throttled the
// captcha session (so further auto attempts are pointless). It matches the
// sentinel as well as the wrapped error strings the slider/checkbox paths
// produce, since those wrap the underlying status into fmt.Errorf chains.
func isCaptchaSessionExhausted(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errCaptchaRateLimit) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "error_limit") ||
		strings.Contains(msg, "captcha_rate_limit") ||
		strings.Contains(msg, "rate limit")
}

// captchaDebugInfoCache caches debug_info strings keyed by script URL so we
// only fetch the JS once per unique script version.
var captchaDebugInfoCache sync.Map

var (
	reCaptchaScriptSrc = regexp.MustCompile(`src="(https://[^"]+not_robot_captcha[^"]+)"`)
	reCaptchaDebugInfo = regexp.MustCompile(`debug_info:(?:[^"]*\|\|)?"([a-fA-F0-9]{64})"`)
)

// captchaHeaderOrder mirrors a real Chrome HTTP/2 header order so VK's bot
// detector sees a plausible browser fingerprint.
var captchaHeaderOrder = []string{
	"host", "content-length", "sec-ch-ua-platform", "accept-language",
	"sec-ch-ua", "content-type", "sec-ch-ua-mobile", "user-agent",
	"accept", "origin", "sec-fetch-site", "sec-fetch-mode",
	"sec-fetch-dest", "referer", "accept-encoding", "priority",
}
var captchaPHeaderOrder = []string{":method", ":path", ":authority", ":scheme"}

const captchaNotRobotAPIVersion = "5.131"

var captchaFormFieldOrder = map[string][]string{
	"captchaNotRobot.settings": {
		"session_token", "domain", "adFp", "access_token",
	},
	"captchaNotRobot.componentDone": {
		"session_token", "domain", "adFp", "browser_fp", "device", "access_token",
	},
	"captchaNotRobot.check": {
		"session_token", "domain", "adFp", "accelerometer", "gyroscope", "motion",
		"cursor", "taps", "connectionRtt", "connectionDownlink", "browser_fp",
		"hash", "answer", "debug_info", "access_token",
	},
	"captchaNotRobot.getContent": {
		"session_token", "domain", "adFp", "captcha_settings", "access_token",
	},
	"captchaNotRobot.endSession": {
		"session_token", "domain", "adFp", "access_token",
	},
}

// encodeCaptchaForm preserves the field order emitted by the VK WebView.
// net/url.Values.Encode sorts keys alphabetically, which does not match the
// captured browser requests and creates an avoidable fingerprint difference.
func encodeCaptchaForm(method string, values neturl.Values) string {
	orderedKeys := captchaFormFieldOrder[method]
	seen := make(map[string]bool, len(values))
	parts := make([]string, 0, len(values))
	appendKey := func(key string) {
		for _, value := range values[key] {
			parts = append(parts, neturl.QueryEscape(key)+"="+neturl.QueryEscape(value))
		}
		seen[key] = true
	}
	for _, key := range orderedKeys {
		if _, ok := values[key]; ok {
			appendKey(key)
		}
	}
	remaining := make([]string, 0, len(values)-len(seen))
	for key := range values {
		if !seen[key] {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)
	for _, key := range remaining {
		appendKey(key)
	}
	return strings.Join(parts, "&")
}

type VkCaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	CaptchaImg              string
	RedirectURI             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string
	CaptchaAttempt          string
}

func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	// Extract error_code
	codeFloat, ok := errData["error_code"].(float64)
	if !ok {
		turnLog("missing error_code in captcha error data")
		return nil
	}
	code := int(codeFloat)

	// Extract redirect_uri
	RedirectURI, ok := errData["redirect_uri"].(string)
	if !ok {
		turnLog("missing redirect_uri in captcha error data")
		return nil
	}

	// Extract captcha_sid (legacy image-captcha field). VK's modern
	// not_robot_captcha flow (error_code:14 + redirect_uri/session_token) no
	// longer sends it, so its absence must NOT fail the parse — the solve path
	// keys off redirect_uri/session_token, not the sid.
	captchaSid, ok := errData["captcha_sid"].(string)
	if !ok {
		// try numeric, otherwise leave empty (modern flow)
		if sidNum, ok2 := errData["captcha_sid"].(float64); ok2 {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}

	// Extract captcha_img (legacy image-captcha field; optional, see above).
	captchaImg, _ := errData["captcha_img"].(string)

	// Extract error_msg
	errorMsg, ok := errData["error_msg"].(string)
	if !ok {
		turnLog("missing error_msg in captcha error data")
		return nil
	}

	// Extract session token if redirect_uri present
	var sessionToken string
	if RedirectURI != "" {
		if parsed, err := neturl.Parse(RedirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		} else {
			turnLog("failed to parse redirect_uri: %v", err)
			return nil
		}
	}

	// Extract is_sound_captcha_available
	isSound, ok := errData["is_sound_captcha_available"].(bool)
	if !ok {
		isSound = false
	}

	// Extract captcha_ts
	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	// Extract captcha_attempt
	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	// Build VkCaptchaError
	return &VkCaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		CaptchaImg:              captchaImg,
		RedirectURI:             RedirectURI,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && e.RedirectURI != "" && e.SessionToken != ""
}

// captchaMutex serializes captcha solving to avoid multiple concurrent attempts
var captchaMutex sync.Mutex

/*
// solveVkCaptcha solves the VK Not Robot Captcha and returns success_token
// First tries automatic solution, falls back to WebView if it fails
func solveVkCaptcha(ctx context.Context, streamID int, client tlsclient.HttpClient, profile Profile, captchaErr *VkCaptchaError) (string, error) {
	// Serialize captcha solving to avoid multiple concurrent attempts
	captchaMutex.Lock()
	defer captchaMutex.Unlock()

	turnLog("[Captcha] Solving Not Robot Captcha...")

	// Step 1: Try automatic solution
	turnLog("[Captcha] Attempting automatic solution...")
	successToken, err := solveVkCaptchaAutomatic(ctx, streamID, client, profile, captchaErr)
	if err == nil && successToken != "" {
		turnLog("[Captcha] Automatic solution SUCCESS!")
		return successToken, nil
	}

	turnLog("[Captcha] Automatic solution FAILED: %v", err)
	turnLog("[Captcha] Falling back to WebView...")

	// Step 2: Fall back to WebView
	turnLog("[Captcha] Opening WebView for manual solving...")
	redirectURICStr := C.CString(captchaErr.RedirectUri)
	defer C.free(unsafe.Pointer(redirectURICStr))

	cToken := C.requestCaptcha(redirectURICStr)
	if cToken == nil {
		return "", fmt.Errorf("WebView captcha solving failed: returned nil token")
	}
	defer C.free(unsafe.Pointer(cToken))

	successToken = C.GoString(cToken)
	if successToken == "" {
		return "", fmt.Errorf("WebView captcha solving failed: returned empty token")
	}

	turnLog("[Captcha] WebView solution SUCCESS! Got success_token")
	return successToken, nil
}

// solveVkCaptchaAutomatic performs the automatic captcha solving without UI
func solveVkCaptchaAutomatic(ctx context.Context, streamID int, client tlsclient.HttpClient, profile Profile, captchaErr *VkCaptchaError) (string, error) {
	sessionToken := captchaErr.SessionToken
	if sessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	// Step 1: Fetch the captcha HTML page to get powInput
	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectUri, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	turnLog("[Captcha] PoW input: %s, difficulty: %d", bootstrap.PowInput, bootstrap.Difficulty)

	// Step 2: Solve PoW
	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	turnLog("[Captcha] PoW solved: hash=%s", hash)

	// Step 3: Call captchaNotRobot API with slider POC support
	successToken, err := callCaptchaNotRobotWithSliderPOC(
		ctx,
		captchaErr.SessionToken,
		hash,
		streamID,
		client,
		profile,
		bootstrap.Settings,
	)

	if err != nil {
		return "", fmt.Errorf("callCaptchaNotRobotWithSliderPOC API failed: %w", err)
	}

	turnLog("[Captcha] Success! Got success_token")
	return successToken, nil
}
*/

func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError, streamID int, client tlsclient.HttpClient, profile Profile, useSliderPOC bool) (string, error) {
	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri for auto-solve")
	}
	if captchaErr.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri for auto-solve")
	}

	// Live diagnostics showed that a second check with the same session_token
	// immediately returns ERROR_LIMIT after the first BOT/getContent refusal.
	// A captcha session is therefore single-use for automatic solving.
	const maxAttempts = 1
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		token, err := solveVkCaptchaOnce(ctx, captchaErr, streamID, client, profile, useSliderPOC)
		if err == nil {
			return token, nil
		}
		lastErr = err
		turnLog("[STREAM %d] [Captcha] attempt %d/%d failed: %v", streamID, attempt, maxAttempts, err)
		// VK has throttled this captcha session. Stop and let the caller fall
		// back to the WebView.
		if isCaptchaSessionExhausted(err) {
			turnLog("[STREAM %d] [Captcha] Session throttled (ERROR_LIMIT) — abandoning auto solve", streamID)
			return "", err
		}
		if attempt < maxAttempts {
			backoff := time.Duration(attempt) * 500 * time.Millisecond
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("captcha attempts exhausted")
}

func solveVkCaptchaOnce(ctx context.Context, captchaErr *VkCaptchaError, streamID int, client tlsclient.HttpClient, profile Profile, useSliderPOC bool) (string, error) {
	if useSliderPOC {
		turnLog("[STREAM %d] [Captcha] Solving captcha with slider POC...", streamID)
	} else {
		turnLog("[STREAM %d] [Captcha] Solving captcha...", streamID)
	}

	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectURI, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	turnLog("[STREAM %d] [Captcha] PoW difficulty: %d", streamID, bootstrap.Difficulty)
	hash := solvePoW(ctx, bootstrap.PowInput, bootstrap.Difficulty)
	if hash == "" {
		return "", fmt.Errorf("PoW solve failed or cancelled")
	}
	turnLog("[STREAM %d] [Captcha] PoW solved", streamID)

	debugInfo, err := fetchDebugInfoFromScript(ctx, bootstrap.ScriptURL, client, profile)
	if err != nil {
		turnLog("[STREAM %d] [Captcha] Warning: could not fetch debug_info dynamically: %v — using fallback", streamID, err)
		debugInfo = captchaDebugInfo
	}

	bootstrapHasSlider := false
	if bootstrap.Settings != nil {
		_, bootstrapHasSlider = bootstrap.Settings.SettingsByType[sliderCaptchaType]
	}

	// When VK offers a slider — either this is the explicit slider-POC mode, or
	// the bootstrap already advertised one — run the unified single-session
	// solver. It does settings → componentDone → checkbox check → slider on ONE
	// session_token, escalating to the slider in-place if the checkbox is
	// rejected as a bot. The old path ran a standalone checkbox solver first and
	// then spun up a *second* session for the slider, duplicating
	// settings/componentDone/check on the same token — which tripped VK's
	// per-token rate limit (ERROR_LIMIT) before the slider image could load.
	if useSliderPOC || bootstrapHasSlider {
		successToken, err := callCaptchaNotRobotWithSliderPOC(
			ctx, captchaErr.SessionToken, hash, debugInfo, streamID, client, profile, bootstrap.Settings,
		)
		if err != nil {
			return "", fmt.Errorf("captchaNotRobot slider POC failed: %w", err)
		}
		turnLog("[STREAM %d] [Captcha] Success! Got success_token (slider POC)", streamID)
		return successToken, nil
	}

	// No slider advertised — try the plain checkbox solver. If its own live
	// settings reveal a slider it returns errSliderDetected, and the caller
	// (vk.go) re-enters this with useSliderPOC=true for the unified path above.
	successToken, err := callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, debugInfo, streamID, client, profile)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}
	turnLog("[STREAM %d] [Captcha] Success! Got success_token", streamID)
	return successToken, nil
}

func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", profileAcceptLanguage(profile))
	req.Header.Set("DNT", "1")
}

// Fallback only. Kept identical to CaptchaFingerprintProbe.USER_AGENT and the
// captcha solver WebView UA (CaptchaActivity) so a fingerprint-probe failure
// still yields the same Android mobile UA VK sees in the interactive captcha.
const captchaWebViewUserAgent = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"

// applyCaptchaBrowserProfileFhttp matches the actual Android WebView requests
// captured on-device: an Android mobile UA paired with the Android WebView
// client hints (mobile mode, Android WebView brand) that Chromium reports.
func applyCaptchaBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	applyBrowserProfileFhttp(req, profile)
	m, ok := androidCaptchaProfile()
	if !ok || m.WebViewMajor <= 0 {
		return
	}
	if m.UserAgent != "" {
		req.Header.Set("User-Agent", m.UserAgent)
	} else {
		req.Header.Set("User-Agent", captchaWebViewUserAgent)
	}
	if m.SecChUA != "" {
		req.Header.Set("sec-ch-ua", m.SecChUA)
	} else if len(m.UABrands) > 0 {
		brands := make([]string, 0, len(m.UABrands))
		for _, brand := range m.UABrands {
			brands = append(brands, fmt.Sprintf(`"%s";v="%s"`, brand.Brand, brand.Version))
		}
		req.Header.Set("sec-ch-ua", strings.Join(brands, ", "))
	} else {
		major := strconv.Itoa(m.WebViewMajor)
		req.Header.Set("sec-ch-ua", fmt.Sprintf(`"Not;A=Brand";v="8", "Chromium";v="%s", "Android WebView";v="%s"`, major, major))
	}
	if m.SecChUAMobile != "" {
		req.Header.Set("sec-ch-ua-mobile", m.SecChUAMobile)
	} else if m.UAMobile || len(m.UABrands) == 0 {
		req.Header.Set("sec-ch-ua-mobile", "?1")
	} else {
		req.Header.Set("sec-ch-ua-mobile", "?0")
	}
	if m.SecChUAPlatform != "" {
		req.Header.Set("sec-ch-ua-platform", m.SecChUAPlatform)
	} else if m.UAPlatform != "" {
		req.Header.Set("sec-ch-ua-platform", fmt.Sprintf(`"%s"`, m.UAPlatform))
	} else {
		req.Header.Set("sec-ch-ua-platform", `"Android"`)
	}
	req.Header.Del("DNT")
}

// profileAcceptLanguage returns the Accept-Language header for a profile,
// falling back to en-US when the profile predates the AcceptLanguage field.
func profileAcceptLanguage(profile Profile) string {
	if strings.TrimSpace(profile.AcceptLanguage) != "" {
		return profile.AcceptLanguage
	}
	return "en-US,en;q=0.9"
}

// captchaDeviceLanguages mirrors navigator.language / navigator.languages for
// the device fingerprint. It must stay consistent with the Accept-Language
// header (profileAcceptLanguage) — a ru-RU header paired with an en-US
// navigator.language is exactly the inconsistency VK's bot detector flags.
func captchaDeviceLanguages(profile Profile) (string, string) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(profile.AcceptLanguage)), "ru") {
		return "ru-RU", `["ru-RU","ru","en-US"]`
	}
	return "en-US", `["en-US"]`
}

type captchaViewport struct {
	Width            int
	Height           int
	DevicePixelRatio float64
}

// randomViewport returns the device's real CSS-pixel viewport when the Android
// profile is available, otherwise a randomized one matching common Android
// Chrome phones (CSS-pixel layout size paired with its devicePixelRatio).
func randomViewport() captchaViewport {
	if m, ok := androidCaptchaProfile(); ok {
		return captchaViewport{Width: m.ScreenWidth, Height: m.ScreenHeight, DevicePixelRatio: m.DevicePixelRatio}
	}
	devices := []captchaViewport{
		{Width: 412, Height: 915, DevicePixelRatio: 2.625},  // Pixel 7/8
		{Width: 360, Height: 800, DevicePixelRatio: 3.0},    // Galaxy A-series
		{Width: 393, Height: 873, DevicePixelRatio: 2.75},   // Pixel 6
		{Width: 412, Height: 892, DevicePixelRatio: 3.5},    // Galaxy S2x
		{Width: 384, Height: 854, DevicePixelRatio: 2.8125}, // common mid-range
		{Width: 360, Height: 780, DevicePixelRatio: 3.0},    // compact
	}
	return devices[rand.Intn(len(devices))]
}

func generateBrowserFp(_ Profile, _ captchaViewport) string {
	// Prefer the device's persisted fingerprint: VK's bot detector burns a
	// captcha session that presents a fresh browser_fp on every attempt, so a
	// stable per-install value (persisted on the Android side) reads as one
	// returning device instead of a bot cycling identities.
	if m, ok := androidCaptchaProfile(); ok && m.BrowserFp != "" {
		return m.BrowserFp
	}
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		return fmt.Sprintf("%x", rand.Int63())
	}
	return hex.EncodeToString(b)
}

// androidDeviceMetrics is the real device fingerprint sourced from the Android
// layer via JNI (TurnBackend.getCaptchaDeviceProfile). Feeding the captcha
// solver the device's actual screen, pixel ratio and core/memory counts — plus
// a browser_fp the Android side persists across sessions — presents a stable,
// believable device instead of freshly randomized synthetic values.
type androidDeviceMetrics struct {
	UserAgent               string           `json:"userAgent"`
	SecChUA                 string           `json:"secChUa"`
	SecChUAMobile           string           `json:"secChUaMobile"`
	SecChUAPlatform         string           `json:"secChUaPlatform"`
	UABrands                []captchaUABrand `json:"uaBrands"`
	UAMobile                bool             `json:"uaMobile"`
	UAPlatform              string           `json:"uaPlatform"`
	ScreenWidth             int              `json:"screenWidth"`
	ScreenHeight            int              `json:"screenHeight"`
	ScreenAvailWidth        int              `json:"screenAvailWidth"`
	ScreenAvailHeight       int              `json:"screenAvailHeight"`
	InnerWidth              int              `json:"innerWidth"`
	InnerHeight             int              `json:"innerHeight"`
	DevicePixelRatio        float64          `json:"devicePixelRatio"`
	Language                string           `json:"language"`
	Languages               []string         `json:"languages"`
	HardwareConcurrency     int              `json:"hardwareConcurrency"`
	DeviceMemory            int              `json:"deviceMemory"`
	MaxTouchPoints          int              `json:"maxTouchPoints"`
	ConnectionEffectiveType string           `json:"connectionEffectiveType"`
	NotificationsPermission string           `json:"notificationsPermission"`
	WebViewMajor            int              `json:"webViewMajor"`
	BrowserFp               string           `json:"browserFp"`
}

type captchaUABrand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

var (
	androidDevMu   sync.Mutex
	androidDevVal  *androidDeviceMetrics
	androidDevDone bool
)

// androidCaptchaProfile returns the real device metrics from the Android layer,
// caching the first successful fetch. An empty/invalid result is NOT cached, so
// a captcha that fires before the provider is registered still picks up the
// real profile on a later attempt. Callers fall back to synthetic values when
// ok is false (non-Android builds, or provider not yet registered).
func androidCaptchaProfile() (*androidDeviceMetrics, bool) {
	androidDevMu.Lock()
	defer androidDevMu.Unlock()
	if androidDevDone {
		return androidDevVal, androidDevVal != nil
	}
	js := fetchAndroidDeviceProfileJSON()
	if js == "" {
		return nil, false
	}
	var m androidDeviceMetrics
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		turnLog("[Captcha] device profile parse failed: %v", err)
		return nil, false
	}
	if m.ScreenWidth <= 0 || m.ScreenHeight <= 0 || m.DevicePixelRatio <= 0 {
		turnLog("[Captcha] device profile incomplete — using synthetic values")
		return nil, false
	}
	androidDevVal = &m
	androidDevDone = true
	turnLog("[Captcha] device profile loaded: %dx%d dpr=%.3f cores=%d mem=%d fp=%.8s",
		m.ScreenWidth, m.ScreenHeight, m.DevicePixelRatio, m.HardwareConcurrency, m.DeviceMemory, m.BrowserFp)
	return androidDevVal, true
}

func fetchAndroidDeviceProfileJSON() string {
	c := C.getCaptchaDeviceProfile()
	if c == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(c))
	return C.GoString(c)
}

// generateConnectionMetrics mirrors the two captured WebView requests: RTT was
// unavailable, while NetworkInformation.downlink was sampled repeatedly at a
// fixed value during the page lifetime (22 and 30 samples respectively).
func generateConnectionMetrics() (rtt string, downlink string) {
	rtt = "[]"
	dlValues := make([]string, 22+rand.Intn(9))
	value := math.Round((8.0+rand.Float64()*2.5)*10) / 10
	formatted := strconv.FormatFloat(value, 'f', -1, 64)
	for i := range dlValues {
		dlValues[i] = formatted
	}
	downlink = "[" + strings.Join(dlValues, ",") + "]"
	return
}

func fetchCaptchaBootstrap(ctx context.Context, redirectURI string, client tlsclient.HttpClient, profile Profile) (*captchaBootstrap, error) {
	parsedURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	domain := parsedURL.Hostname()

	req, err := fhttp.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return nil, err
	}

	req.Host = domain
	applyCaptchaBrowserProfileFhttp(req, profile)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseCaptchaBootstrapHTML(string(body))
}

func buildCaptchaDeviceJSON(profile Profile, vp captchaViewport) string {
	if m, ok := androidCaptchaProfile(); ok && m.InnerWidth > 0 && m.InnerHeight > 0 {
		languages := m.Languages
		if len(languages) == 0 {
			languages = []string{m.Language}
		}
		effectiveType := m.ConnectionEffectiveType
		if effectiveType == "" {
			effectiveType = "4g"
		}
		notifications := m.NotificationsPermission
		if notifications == "" {
			notifications = "denied"
		}
		payload := struct {
			ScreenWidth             int      `json:"screenWidth"`
			ScreenHeight            int      `json:"screenHeight"`
			ScreenAvailWidth        int      `json:"screenAvailWidth"`
			ScreenAvailHeight       int      `json:"screenAvailHeight"`
			InnerWidth              int      `json:"innerWidth"`
			InnerHeight             int      `json:"innerHeight"`
			DevicePixelRatio        float64  `json:"devicePixelRatio"`
			Language                string   `json:"language"`
			Languages               []string `json:"languages"`
			Webdriver               bool     `json:"webdriver"`
			HardwareConcurrency     int      `json:"hardwareConcurrency"`
			DeviceMemory            int      `json:"deviceMemory"`
			ConnectionEffectiveType string   `json:"connectionEffectiveType"`
			NotificationsPermission string   `json:"notificationsPermission"`
		}{
			ScreenWidth: m.ScreenWidth, ScreenHeight: m.ScreenHeight,
			ScreenAvailWidth: m.ScreenAvailWidth, ScreenAvailHeight: m.ScreenAvailHeight,
			InnerWidth: m.InnerWidth, InnerHeight: m.InnerHeight,
			DevicePixelRatio: m.DevicePixelRatio,
			Language:         m.Language, Languages: languages,
			Webdriver:           false,
			HardwareConcurrency: m.HardwareConcurrency, DeviceMemory: m.DeviceMemory,
			ConnectionEffectiveType: effectiveType, NotificationsPermission: notifications,
		}
		if encoded, err := json.Marshal(payload); err == nil {
			return string(encoded)
		}
	}

	// The invisible Android WebView is measured at roughly 360x382 physical
	// pixels. JavaScript exposes that viewport in CSS pixels, while screen and
	// screen.avail* retain the real device dimensions.
	innerWidth := int(math.Round(float64(356+rand.Intn(13)) / vp.DevicePixelRatio))
	innerHeight := int(math.Round(float64(376+rand.Intn(13)) / vp.DevicePixelRatio))
	language, languages := captchaDeviceLanguages(profile)

	// Prefer the device's real core/memory counts; fall back to plausible
	// randomized values off-device or before the Android profile is available.
	hardwareConcurrency := 6 + rand.Intn(3) // 6-8 cores
	memChoices := []int{4, 6, 8}
	deviceMemory := memChoices[rand.Intn(len(memChoices))]
	if m, ok := androidCaptchaProfile(); ok {
		if m.HardwareConcurrency > 0 {
			hardwareConcurrency = m.HardwareConcurrency
		}
		if m.DeviceMemory > 0 {
			deviceMemory = m.DeviceMemory
		}
	}

	return fmt.Sprintf(
		`{"screenWidth":%d,"screenHeight":%d,"screenAvailWidth":%d,"screenAvailHeight":%d,"innerWidth":%d,"innerHeight":%d,"devicePixelRatio":%s,"language":"%s","languages":%s,"webdriver":false,"hardwareConcurrency":%d,"deviceMemory":%d,"connectionEffectiveType":"4g","notificationsPermission":"denied"}`,
		vp.Width, vp.Height, vp.Width, vp.Height, innerWidth, innerHeight,
		strconv.FormatFloat(vp.DevicePixelRatio, 'f', -1, 64),
		language, languages,
		hardwareConcurrency,
		deviceMemory,
	)
}

func solvePoW(ctx context.Context, powInput string, difficulty int) string {
	if powInput == "" || difficulty <= 0 {
		return ""
	}
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10000000; nonce++ {
		if nonce%4096 == 0 {
			select {
			case <-ctx.Done():
				return ""
			default:
			}
		}
		hash := sha256.Sum256([]byte(powInput + strconv.Itoa(nonce)))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}
	return ""
}

// fetchDebugInfoFromScript downloads the captcha JS bundle and extracts the
// debug_info hash embedded in it.  Results are cached by script URL so we only
// pay the fetch cost once per unique script version.
func fetchDebugInfoFromScript(ctx context.Context, scriptURL string, client tlsclient.HttpClient, profile Profile) (string, error) {
	if scriptURL == "" {
		return "", fmt.Errorf("empty script URL")
	}
	if cached, ok := captchaDebugInfoCache.Load(scriptURL); ok {
		if v, ok := cached.(string); ok {
			return v, nil
		}
		captchaDebugInfoCache.Delete(scriptURL)
	}

	req, err := fhttp.NewRequestWithContext(ctx, "GET", scriptURL, nil)
	if err != nil {
		return "", err
	}
	applyCaptchaBrowserProfileFhttp(req, profile)
	req.Header.Set("Accept", "text/javascript,*/*")
	req.Header.Set("Referer", "https://id.vk.ru/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header[fhttp.HeaderOrderKey] = captchaHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = captchaPHeaderOrder

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	m := reCaptchaDebugInfo.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("debug_info not found in captcha script")
	}
	v := string(m[1])
	captchaDebugInfoCache.Store(scriptURL, v)
	turnLog("[Captcha] debug_info fetched from script: %.12s...", v)
	return v, nil
}

func callCaptchaNotRobot(ctx context.Context, sessionToken, hash, debugInfo string, streamID int, client tlsclient.HttpClient, profile Profile) (string, error) {
	vkReq := func(method string, values neturl.Values) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=" + captchaNotRobotAPIVersion
		req, err := fhttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(encodeCaptchaForm(method, values)))
		if err != nil {
			return nil, err
		}
		applyCaptchaBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Referer", "https://id.vk.ru/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")
		req.Header[fhttp.HeaderOrderKey] = captchaHeaderOrder
		req.Header[fhttp.PHeaderOrderKey] = captchaPHeaderOrder

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = httpResp.Body.Close() }()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	vp := randomViewport()
	baseValues := func() neturl.Values {
		values := neturl.Values{}
		values.Set("session_token", sessionToken)
		values.Set("domain", "vk.ru")
		values.Set("adFp", "")
		values.Set("access_token", "")
		return values
	}

	turnLog("[STREAM %d] [Captcha] Step 1/4: settings", streamID)
	settingsResp, err := vkReq("captchaNotRobot.settings", baseValues())
	if err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}
	if parsedSettings, perr := parseCaptchaSettingsResponse(settingsResp); perr == nil && parsedSettings != nil {
		if _, hasSlider := parsedSettings.SettingsByType[sliderCaptchaType]; hasSlider {
			turnLog("[STREAM %d] [Captcha] Slider detected in settings — aborting HTTP solve", streamID)
			return "", errSliderDetected
		}
	}

	time.Sleep(time.Duration(500+rand.Intn(300)) * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 2/4: componentDone (viewport=%dx%d)", streamID, vp.Width, vp.Height)
	browserFp := generateBrowserFp(profile, vp)
	deviceJSON := buildCaptchaDeviceJSON(profile, vp)
	componentDoneData := baseValues()
	componentDoneData.Set("browser_fp", browserFp)
	componentDoneData.Set("device", deviceJSON)

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}

	time.Sleep(time.Duration(500+rand.Intn(300)) * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 3/4: check", streamID)
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

	connRtt, connDownlink := generateConnectionMetrics()
	checkData := baseValues()
	checkData.Set("accelerometer", "[]")
	checkData.Set("gyroscope", "[]")
	checkData.Set("motion", "[]")
	checkData.Set("cursor", "[]")
	checkData.Set("taps", "[]")
	checkData.Set("connectionRtt", connRtt)
	checkData.Set("connectionDownlink", connDownlink)
	checkData.Set("browser_fp", browserFp)
	checkData.Set("hash", hash)
	checkData.Set("answer", answer)
	checkData.Set("debug_info", debugInfo)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}
	status, _ := respObj["status"].(string)
	switch strings.ToUpper(status) {
	case "OK":
		// continue below
	case "BOT":
		turnLog("[STREAM %d] [Captcha] check returned BOT status", streamID)
		return "", errCaptchaBot
	case "ERROR_LIMIT":
		turnLog("[STREAM %d] [Captcha] check returned ERROR_LIMIT — session throttled", streamID)
		return "", errCaptchaRateLimit
	default:
		return "", fmt.Errorf("check status: %s", status)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found")
	}

	time.Sleep(time.Duration(500+rand.Intn(300)) * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 4/4: endSession", streamID)
	if _, err := vkReq("captchaNotRobot.endSession", baseValues()); err != nil {
		turnLog("[STREAM %d] [Captcha] Warning: endSession failed: %v", streamID, err)
	}

	return successToken, nil
}
