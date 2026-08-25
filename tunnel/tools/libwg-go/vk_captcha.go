/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <stdlib.h>
extern const char* requestCaptcha(const char* redirect_uri, int visible);
extern void cancelCaptcha();
extern void burnCaptchaPersona(const char* reason);
extern const char* getCaptchaDeviceProfile();
*/
import "C"

import (
	"bytes"
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
	"sync/atomic"
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

// vkXHRHeaderOrder / vkPHeaderOrder are wire-verified against the reference
// Chrome 151 capture (tls.peet.ws) — VK's bot detector accepts requests in this
// exact order; the old pseudo-header order (:method, :path, :authority,
// :scheme) was one of the transport signals behind the BOT verdict. They are
// not captcha-specific: every browser-shaped request the app makes (the trigger
// chain in vk.go included) has to present the same transport, or the phase that
// hands out the captcha contradicts the phase that solves it.
var vkXHRHeaderOrder = []string{
	"host", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
	"user-agent", "accept", "content-type", "origin",
	"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
	"accept-encoding", "accept-language", "priority", "content-length",
}

// vkNavHeaderOrder is the document-navigation variant: Chrome sends
// upgrade-insecure-requests and sec-fetch-user only when loading a document,
// and orders the sec-fetch-* block differently than on XHR. The captcha
// bootstrap GET is a navigation and used to go out with fhttp's default order,
// which made the very first request of the session the odd one out.
var vkNavHeaderOrder = []string{
	"host", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
	"upgrade-insecure-requests", "user-agent", "accept",
	"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
	"accept-encoding", "accept-language", "priority",
}

var vkPHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}

const captchaNotRobotAPIVersion = "5.131"

// captchaEndpoints ties every host one captcha session talks about to the
// session VK actually handed us. The page derives all of them from its own URL:
// `domain` comes from the query string, Origin/Referer are the page's own host,
// and the captchaNotRobot calls go to api.<domain>. Hardcoding the vk.ru family
// broke sessions issued on vk.com — and, worse, mixed both families inside one
// session (domain=vk.com posted to api.vk.ru with Origin id.vk.ru), which is a
// free inconsistency for the bot detector.
type captchaEndpoints struct {
	Domain   string // `domain` form field, e.g. "vk.com"
	PageHost string // id.vk.com — Origin/Referer of every call, and telemetry referrer.domain
	APIHost  string // api.vk.com
}

func captchaEndpointsFromRedirectURI(redirectURI string) captchaEndpoints {
	ep := captchaEndpoints{Domain: "vk.ru", PageHost: "id.vk.ru", APIHost: "api.vk.ru"}
	parsed, err := neturl.Parse(redirectURI)
	if err != nil {
		return ep
	}
	if host := parsed.Hostname(); host != "" {
		ep.PageHost = host
	}
	pageApex := hostApex(ep.PageHost)

	// `domain` as the page reads it from its own query; with no query parameter
	// the page's own family is the only honest answer — falling back to a
	// hardcoded vk.ru would be the very mismatch this type exists to prevent.
	if d := parsed.Query().Get("domain"); d != "" {
		ep.Domain = d
	} else if pageApex != "" {
		ep.Domain = pageApex
	}

	// The captchaNotRobot calls go to api.<domain>; a `domain` that isn't a bare
	// apex (a subdomain, or something unexpected) falls back to the page's.
	apiBase := ep.Domain
	if strings.Count(apiBase, ".") != 1 {
		apiBase = pageApex
	}
	if apiBase != "" {
		ep.APIHost = "api." + apiBase
	}
	return ep
}

// hostApex returns the registrable part of a host: id.vk.com → vk.com.
func hostApex(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func (ep captchaEndpoints) origin() string { return "https://" + ep.PageHost }

func (ep captchaEndpoints) referer() string { return "https://" + ep.PageHost + "/" }

func (ep captchaEndpoints) methodURL(method string) string {
	return "https://" + ep.APIHost + "/method/" + method + "?v=" + captchaNotRobotAPIVersion
}

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

// captchaGeneration is bumped by abortPendingCaptcha every time the proxy is
// stopped or restarted. solveCaptchaViaUI samples it before queueing on
// captchaMutex and gives up if it moved while it waited, so a stop does not just
// interrupt the captcha that is on screen — it also cancels the ones lined up
// behind it, which would otherwise open a fresh dialog for a session that no
// longer exists.
var captchaGeneration atomic.Uint64

// abortPendingCaptcha tells the Android layer to dismiss any captcha UI and
// invalidates the queued solve attempts. Called from the proxy stop/restart
// paths: requestCaptcha blocks its worker inside the Java handler for up to 120s
// and neither ctx cancellation nor wgTurnProxyStop could reach it, so a user who
// pressed disconnect kept the dialog on screen and the next connect blocked on
// captchaMutex until the old solve timed out.
func abortPendingCaptcha() {
	captchaGeneration.Add(1)
	C.cancelCaptcha()
}

// solveCaptchaViaUI runs the blocking Android captcha UI for one caller at a
// time and reports whether the token came from the shared cache instead.
// visible picks the UI: false = invisible auto-clicking WebView, true = the
// full-screen CaptchaActivity dialog.
//
// The caller states the mode explicitly because Go owns the escalation ladder.
// The Kotlin side used to decide by itself, alternating on its own boolean, and
// the two drifted apart the moment Go deviated from the plain
// invisible-then-visible order (slider POC failure skips the invisible round) or
// resolved a captcha without calling in at all (POC success). The drift ran both
// ways: a "visible dialog" round that silently ran the invisible WebView on a
// slider it cannot solve, and a spurious full-screen dialog as the first UI of
// the next captcha.
//
// Serialization is not optional here. vkSemaphore admits two credential fetches
// at once, so two goroutines can hit a captcha simultaneously, while the Android
// side keeps exactly one pending result (CaptchaActivity.pendingResult).
// Concurrent callers therefore overwrote each other: the first blocked until its
// 120s timeout, and the loser's Activity delivered an empty token into the
// winner's future.
//
// Waiting costs little: the winner caches its success_token for the link (4 uses),
// so a waiter normally finds one here and never opens a second WebView.
func solveCaptchaViaUI(link, redirectURI string, visible bool) (token string, fromCache bool) {
	gen := captchaGeneration.Load()
	captchaMutex.Lock()
	defer captchaMutex.Unlock()

	// The proxy was stopped or restarted while this caller queued behind the
	// mutex — the session it would have served is gone.
	if captchaGeneration.Load() != gen {
		turnLog("[Captcha] Solve abandoned: proxy stopped while waiting for the captcha lock")
		return "", false
	}

	if cached := popCaptchaToken(link); cached != "" {
		return cached, true
	}

	redirectURICStr := C.CString(redirectURI)
	defer C.free(unsafe.Pointer(redirectURICStr))

	visibleFlag := C.int(0)
	if visible {
		visibleFlag = 1
	}
	cToken := C.requestCaptcha(redirectURICStr, visibleFlag)
	if cToken == nil {
		return "", false
	}
	defer C.free(unsafe.Pointer(cToken))

	return C.GoString(cToken), false
}

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
		// Both verdicts judge the identity we presented rather than this
		// particular request, so the persona is retired before anything else runs
		// — every later step of this captcha, WebView included, would otherwise
		// keep showing VK the device it has just refused.
		if errors.Is(err, errCaptchaBot) {
			burnCaptchaPersona("VK returned BOT for this device")
		}
		// VK has throttled this captcha session. Stop and let the caller fall
		// back to the WebView.
		if isCaptchaSessionExhausted(err) {
			burnCaptchaPersona("VK rate-limited the captcha session")
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

	// Every host of this session — the `domain` form field, the Origin/Referer
	// of each call, the API host and the referrer reported in the PoW telemetry
	// — comes from the redirect_uri VK issued, so a vk.com session never mixes
	// in a vk.ru host.
	endpoints := captchaEndpointsFromRedirectURI(captchaErr.RedirectURI)
	turnLog("[STREAM %d] [Captcha] Endpoints: domain=%s page=%s api=%s",
		streamID, endpoints.Domain, endpoints.PageHost, endpoints.APIHost)

	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectURI, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	turnLog("[STREAM %d] [Captcha] PoW difficulty: %d (v2=%t)", streamID, bootstrap.Difficulty, bootstrap.PowV2)
	hash := solvePoW(ctx, bootstrap.PowInput, bootstrap.Difficulty, bootstrap.PowV2, profile, endpoints)
	if hash == "" {
		return "", fmt.Errorf("PoW solve failed or cancelled")
	}
	turnLog("[STREAM %d] [Captcha] PoW solved", streamID)

	debugInfo, err := fetchDebugInfoFromScript(ctx, bootstrap.ScriptURL, client, profile, endpoints)
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
			ctx, captchaErr.SessionToken, hash, debugInfo, streamID, client, profile, bootstrap.Settings, endpoints,
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
	successToken, err := callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, debugInfo, streamID, client, profile, endpoints)
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
	// No DNT: Chrome dropped the setting, so a real Chrome 151 never sends the
	// header. The captcha path used to strip it back off; sending it anywhere
	// else was the same signal, just outside the phase we were measuring.
}

// Fallback only, for when the Android device profile is unavailable (provider
// not yet registered, or a non-Android build). Normally the UA comes from that
// profile, where it is the current CaptchaPersona's — the same one both WebViews
// set — so every step of one captcha presents a single Android mobile UA.
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

// captchaAdFpFromBrowserFp derives the adFp (window.rb_sync.id) from the
// persisted browser_fp: the same 16 random bytes in base64url. The reference
// browser sent a stable adFp in every captchaNotRobot call — an empty adFp,
// or a fresh one per solve, is an avoidable bot signal.
func captchaAdFpFromBrowserFp(browserFp string) string {
	raw, err := hex.DecodeString(browserFp)
	if err != nil || len(raw) != 16 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
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
	// PrefersDark is the device's real UI theme, reported for the PoW
	// telemetry's match_media probe. A pointer so "the Android layer said
	// nothing" stays distinguishable from "light theme": absent falls back to
	// the reference capture's dark mode.
	PrefersDark *bool `json:"prefersDark"`
}

type captchaUABrand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

var (
	androidDevMu  sync.Mutex
	androidDevVal *androidDeviceMetrics
	androidDevAt  time.Time
)

// androidProfileTTL bounds how long a fetched device profile is reused. The
// identity inside it (UA, viewport, browser_fp) belongs to a persona the Android
// side rotates on a budget, so caching the first fetch for the life of the
// process — which is what this used to do — pinned the very first persona
// forever and defeated the rotation. The TTL is comfortably shorter than the
// Android side's attempt window, so a rotation is picked up promptly, and long
// enough that every step of one solve reads the same persona.
const androidProfileTTL = 60 * time.Second

// androidCaptchaProfile returns the real device metrics from the Android layer,
// caching them for androidProfileTTL. An empty/invalid result does not overwrite
// the last good profile — a captcha that fires before the provider is registered
// still picks the real one up on a later attempt. Callers fall back to synthetic
// values when ok is false (non-Android builds, or provider not yet registered).
func androidCaptchaProfile() (*androidDeviceMetrics, bool) {
	androidDevMu.Lock()
	defer androidDevMu.Unlock()
	if androidDevVal != nil && time.Since(androidDevAt) < androidProfileTTL {
		return androidDevVal, true
	}
	js := fetchAndroidDeviceProfileJSON()
	if js == "" {
		return androidDevVal, androidDevVal != nil
	}
	var m androidDeviceMetrics
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		turnLog("[Captcha] device profile parse failed: %v", err)
		return androidDevVal, androidDevVal != nil
	}
	if m.ScreenWidth <= 0 || m.ScreenHeight <= 0 || m.DevicePixelRatio <= 0 {
		turnLog("[Captcha] device profile incomplete — using synthetic values")
		return androidDevVal, androidDevVal != nil
	}
	androidDevVal = &m
	androidDevAt = time.Now()
	turnLog("[Captcha] device profile loaded: %dx%d dpr=%.3f inner=%dx%d cores=%d mem=%d fp=%.8s",
		m.ScreenWidth, m.ScreenHeight, m.DevicePixelRatio, m.InnerWidth, m.InnerHeight,
		m.HardwareConcurrency, m.DeviceMemory, m.BrowserFp)
	return androidDevVal, true
}

// invalidateAndroidCaptchaProfile drops the cached profile so the next call
// fetches a fresh one. Used after burning a persona: the identity the cache
// holds has just been retired.
func invalidateAndroidCaptchaProfile() {
	androidDevMu.Lock()
	androidDevVal = nil
	androidDevAt = time.Time{}
	androidDevMu.Unlock()
}

// burnCaptchaPersona tells the Android side that VK rejected the identity it is
// currently presenting — a rate limit, a BOT verdict, or a solve ladder that ran
// out of modes — so the next captcha gets a freshly minted one instead of
// spending the rest of the current persona's budget on an identity VK has
// already refused. Safe to call when no persona exists; the Java side no-ops.
func burnCaptchaPersona(reason string) {
	turnLog("[Captcha] Burning device persona: %s", reason)
	cReason := C.CString(reason)
	C.burnCaptchaPersona(cReason)
	C.free(unsafe.Pointer(cReason))
	invalidateAndroidCaptchaProfile()
}

func fetchAndroidDeviceProfileJSON() string {
	c := C.getCaptchaDeviceProfile()
	if c == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(c))
	return C.GoString(c)
}

// generateNetworkSamples mirrors the browser's connectionRtt/connectionDownlink
// arrays: one constant value per session, one sample per 200ms sensors_delay
// tick. The sample count must match the componentDone→check window — a random
// count decoupled from the actual elapsed time is a bot signal VK checks.
func generateNetworkSamples(n int) (rtt string, downlink string) {
	if n < 1 {
		n = 1
	}
	rttVal := 40 + rand.Intn(61)
	downlinkVal := math.Round((1.6+rand.Float64()*8)*10) / 10

	rtts := make([]float64, 0, n)
	downlinks := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		rtts = append(rtts, float64(rttVal))
		downlinks = append(downlinks, downlinkVal)
	}

	encode := func(v interface{}) string {
		raw, err := json.Marshal(v)
		if err != nil {
			return "[]"
		}
		return string(raw)
	}
	return encode(rtts), encode(downlinks)
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
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Priority", "u=0, i")
	req.Header[fhttp.HeaderOrderKey] = vkNavHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = vkPHeaderOrder

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

	hardwareConcurrency, deviceMemory := captchaHardwareProfile()

	return fmt.Sprintf(
		`{"screenWidth":%d,"screenHeight":%d,"screenAvailWidth":%d,"screenAvailHeight":%d,"innerWidth":%d,"innerHeight":%d,"devicePixelRatio":%s,"language":"%s","languages":%s,"hardwareConcurrency":%d,"deviceMemory":%d,"connectionEffectiveType":"4g","notificationsPermission":"denied"}`,
		vp.Width, vp.Height, vp.Width, vp.Height, innerWidth, innerHeight,
		strconv.FormatFloat(vp.DevicePixelRatio, 'f', -1, 64),
		language, languages,
		hardwareConcurrency,
		deviceMemory,
	)
}

// captchaHardwareProfile returns the navigator.hardwareConcurrency /
// navigator.deviceMemory pair every part of one solve must agree on: the device
// JSON of componentDone and the globals.hw/globals.mem of the PoW telemetry.
// On-device both come from the real device. Off-device (probe builds, or before
// the Android profile is registered) the fallback is randomized once per
// process rather than per call — two random draws inside one solve is exactly
// the self-contradiction VK looks for.
func captchaHardwareProfile() (hardwareConcurrency int, deviceMemory int) {
	fallbackHardwareOnce.Do(func() {
		fallbackHardwareConcurrency = 6 + rand.Intn(3) // 6-8 cores
		memChoices := []int{4, 6, 8}
		fallbackDeviceMemory = memChoices[rand.Intn(len(memChoices))]
	})
	// A device that reports only one of the two still keeps its real value.
	hardwareConcurrency, deviceMemory = fallbackHardwareConcurrency, fallbackDeviceMemory
	if m, ok := androidCaptchaProfile(); ok {
		if m.HardwareConcurrency > 0 {
			hardwareConcurrency = m.HardwareConcurrency
		}
		if m.DeviceMemory > 0 {
			deviceMemory = m.DeviceMemory
		}
	}
	return hardwareConcurrency, deviceMemory
}

var (
	fallbackHardwareOnce        sync.Once
	fallbackHardwareConcurrency int
	fallbackDeviceMemory        int
)

func solvePoW(ctx context.Context, powInput string, difficulty int, v2 bool, profile Profile, ep captchaEndpoints) string {
	if powInput == "" || difficulty <= 0 {
		return ""
	}
	// The real browser solved difficulty 2 with nonce 76 in duration_ms=2, so
	// start from nonce 0 and keep the reported solve time small and honest —
	// a duration_ms of hundreds of ms for a trivial hash is a bot signal.
	start := time.Now()
	time.Sleep(time.Duration(2+rand.Intn(4)) * time.Millisecond)
	target := strings.Repeat("0", difficulty)
	for nonce := 0; nonce <= 10000000; nonce++ {
		if nonce%4096 == 0 {
			select {
			case <-ctx.Done():
				return ""
			default:
			}
		}
		hash := sha256.Sum256([]byte(powInput + strconv.Itoa(nonce)))
		hexHash := hex.EncodeToString(hash[:])
		if !strings.HasPrefix(hexHash, target) {
			continue
		}
		if !v2 {
			return hexHash
		}
		return encodePowResultV2(hexHash, nonce, time.Since(start), profile, ep)
	}
	return ""
}

// encodePowResultV2 mirrors the obfuscated inline PoW solver VK now ships on
// the captcha page: the check's hash param is "v2." + base64(JSON payload)
// carrying the digest, nonce, timing and a browser-environment snapshot, not
// the bare hex digest the legacy pages used.
func encodePowResultV2(hexHash string, nonce int, duration time.Duration, profile Profile, ep captchaEndpoints) string {
	telemetry := buildPowTelemetry(profile, ep)

	canonicalTelemetry, err := marshalLikeJSONStringify(telemetry)
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

	raw, err := marshalLikeJSONStringify(payload)
	if err != nil {
		return ""
	}
	return "v2." + base64.StdEncoding.EncodeToString(raw)
}

// marshalLikeJSONStringify serializes v the way the solver's JSON.stringify
// does. Go's json.Marshal rewrites <, > and & into their six-character unicode
// escapes; JavaScript's leaves them as-is. Every byte of telemetry is hashed
// into tel_hash, so one such character anywhere in it — a referrer carrying a
// query string, a page host, any field VK adds later — makes our digest
// disagree with the one their own code would have produced, and the check comes
// back BOT with nothing in the logs to point at. The escaping is off by default
// in JS and has to be turned off explicitly here; Encode also appends a newline
// json.Marshal does not, so trim it.
func marshalLikeJSONStringify(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// buildPowTelemetry reproduces the environment snapshot the v2 solver embeds
// in its result (globals/ua/frame/match_media/plugins/... from the browser).
// Every field is wrapped as {ok: bool, result: ...} — a failed probe becomes
// {ok: false, error: "exception"}. Values match a stock Android WebView; the
// canonical form hashed into tel_hash is json.Marshal of these maps, whose
// sorted key order matches the solver's sorted-key stringify.
func buildPowTelemetry(profile Profile, ep captchaEndpoints) map[string]interface{} {
	// Same source as the device JSON: telemetry claiming 8 cores while the
	// device JSON of the same session claims 6 is the contradiction this whole
	// path exists to avoid.
	hardwareConcurrency, deviceMemory := captchaHardwareProfile()

	// The UA embedded in the telemetry must match the UA the captcha-phase
	// requests send (applyCaptchaBrowserProfileFhttp): the Android WebView
	// persona's, falling back to the trigger-phase profile UA.
	userAgent := profile.UserAgent
	if m, ok := androidCaptchaProfile(); ok && m.UserAgent != "" {
		userAgent = m.UserAgent
	}
	if userAgent == "" {
		userAgent = captchaWebViewUserAgent
	}

	// The device's real theme when Android reports one; the reference capture's
	// dark mode otherwise.
	prefersDark := true
	if m, ok := androidCaptchaProfile(); ok && m.PrefersDark != nil {
		prefersDark = *m.PrefersDark
	}

	ok := func(result interface{}) map[string]interface{} {
		return map[string]interface{}{"ok": true, "result": result}
	}

	return map[string]interface{}{
		"globals": ok(map[string]interface{}{
			"doc":       true,
			"win":       true,
			"nav":       true,
			"webdriver": false,
			"hw":        hardwareConcurrency,
			"mem":       deviceMemory,
		}),
		"ua": ok(map[string]interface{}{"userAgent": userAgent}),
		"frame": ok(map[string]interface{}{
			// The solver runs in the top frame of the captcha page, so
			// parentAccessible must be true — the page itself reports it that
			// way and the reference capture confirmed it.
			"frameElement":       nil,
			"ancestorOriginsLen": 0,
			"parentAccessible":   true,
		}),
		"match_media": ok(map[string]interface{}{
			// The theme is the device's real one (the visible WebView fallback
			// runs on the same device and would report it truthfully); the
			// pointer is coarse on a phone. Reference capture: dark, coarse.
			"prefersDark":   prefersDark,
			"prefersLight":  !prefersDark,
			"reducedMotion": false,
			"pointerFine":   false,
		}),
		"plugins": ok(map[string]interface{}{
			"length":   0,
			"names":    []string{},
			"isChrome": false,
		}),
		"nav_tamper": ok(map[string]interface{}{"tampered": false}),
		"referrer": ok(map[string]interface{}{
			"referrer": "",
			"inIframe": false,
			// The page the solver runs on — id.vk.ru or id.vk.com, whichever
			// issued this session.
			"domain": ep.PageHost,
		}),
		"devtools": ok(map[string]interface{}{"open": false}),
		"css":      ok(map[string]interface{}{"expectedMissing": 0}),
		"native_integrity": ok(map[string]interface{}{
			"protoMatch": true,
			"xhrNative":  true,
		}),
	}
}

// fetchDebugInfoFromScript downloads the captcha JS bundle and extracts the
// debug_info hash embedded in it.  Results are cached by script URL so we only
// pay the fetch cost once per unique script version.
func fetchDebugInfoFromScript(ctx context.Context, scriptURL string, client tlsclient.HttpClient, profile Profile, ep captchaEndpoints) (string, error) {
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
	req.Header.Set("Referer", ep.referer())
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header[fhttp.HeaderOrderKey] = vkXHRHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = vkPHeaderOrder

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

func callCaptchaNotRobot(ctx context.Context, sessionToken, hash, debugInfo string, streamID int, client tlsclient.HttpClient, profile Profile, ep captchaEndpoints) (string, error) {
	vkReq := func(method string, values neturl.Values) (map[string]interface{}, error) {
		reqURL := ep.methodURL(method)
		req, err := fhttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(encodeCaptchaForm(method, values)))
		if err != nil {
			return nil, err
		}
		applyCaptchaBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", ep.origin())
		req.Header.Set("Referer", ep.referer())
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")
		req.Header[fhttp.HeaderOrderKey] = vkXHRHeaderOrder
		req.Header[fhttp.PHeaderOrderKey] = vkPHeaderOrder

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
	browserFp := generateBrowserFp(profile, vp)
	adFp := captchaAdFpFromBrowserFp(browserFp)
	baseValues := func() neturl.Values {
		values := neturl.Values{}
		values.Set("session_token", sessionToken)
		values.Set("domain", ep.Domain)
		values.Set("adFp", adFp)
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
	deviceJSON := buildCaptchaDeviceJSON(profile, vp)
	componentDoneData := baseValues()
	componentDoneData.Set("browser_fp", browserFp)
	componentDoneData.Set("device", deviceJSON)

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}

	// The browser collects sensor/network samples every 200ms (sensors_delay)
	// between componentDone and check; the rtt/downlink sample count must
	// match that window.
	checkWindowStart := time.Now()
	time.Sleep(time.Duration(5500+rand.Intn(1500)) * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 3/4: check", streamID)
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

	sampleCount := int(time.Since(checkWindowStart).Milliseconds() / 200)
	connRtt, connDownlink := generateNetworkSamples(sampleCount)
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
