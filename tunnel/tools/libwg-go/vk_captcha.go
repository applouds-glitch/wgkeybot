/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <stdlib.h>
extern const char* requestCaptcha(const char* redirect_uri);
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
	"strconv"
	"strings"
	"sync"
	"time"

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

	// Extract captcha_sid
	captchaSid, ok := errData["captcha_sid"].(string)
	if !ok {
		// try numeric
		if sidNum, ok2 := errData["captcha_sid"].(float64); ok2 {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		} else {
			turnLog("missing captcha_sid in captcha error data")
			return nil
		}
	}

	// Extract captcha_img
	captchaImg, ok := errData["captcha_img"].(string)
	if !ok {
		turnLog("missing captcha_img in captcha error data")
		return nil
	}

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

	const maxAttempts = 2
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		token, err := solveVkCaptchaOnce(ctx, captchaErr, streamID, client, profile, useSliderPOC)
		if err == nil {
			return token, nil
		}
		lastErr = err
		turnLog("[STREAM %d] [Captcha] attempt %d/%d failed: %v", streamID, attempt, maxAttempts, err)
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

	if useSliderPOC {
		successToken, err := callCaptchaNotRobotWithSliderPOC(
			ctx, captchaErr.SessionToken, hash, debugInfo, streamID, client, profile, bootstrap.Settings,
		)
		if err != nil {
			return "", fmt.Errorf("captchaNotRobot slider POC failed: %w", err)
		}
		turnLog("[STREAM %d] [Captcha] Success! Got success_token (slider POC)", streamID)
		return successToken, nil
	}

	successToken, err := callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, debugInfo, streamID, client, profile)
	if err == nil {
		turnLog("[STREAM %d] [Captcha] Success! Got success_token", streamID)
		return successToken, nil
	}

	// If checkbox returned bot/slider-detected and slider settings exist, try slider
	if (errors.Is(err, errCaptchaBot) || errors.Is(err, errSliderDetected)) && bootstrap.Settings != nil {
		if _, hasSlider := bootstrap.Settings.SettingsByType[sliderCaptchaType]; hasSlider {
			turnLog("[STREAM %d] [Captcha] Checkbox failed (%v) — escalating to slider POC", streamID, err)
			successToken, sliderErr := callCaptchaNotRobotWithSliderPOC(
				ctx, captchaErr.SessionToken, hash, debugInfo, streamID, client, profile, bootstrap.Settings,
			)
			if sliderErr != nil {
				return "", fmt.Errorf("captchaNotRobot slider POC failed: %w", sliderErr)
			}
			turnLog("[STREAM %d] [Captcha] Success! Got success_token (slider POC after bot escalation)", streamID)
			return successToken, nil
		}
	}

	return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
}

func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

type captchaViewport struct {
	Width            int
	Height           int
	DevicePixelRatio float64
}

// randomViewport returns a randomized viewport matching real Android Chrome
// phones (CSS-pixel layout size paired with its devicePixelRatio).
func randomViewport() captchaViewport {
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
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		return fmt.Sprintf("%x", rand.Int63())
	}
	return hex.EncodeToString(b)
}

// generateHumanCursor produces a realistic mouse trajectory with returns, pauses, and micro-jitter.
func generateHumanCursor() string {
	startX := 40 + rand.Intn(300)  // within a ~360-412px mobile viewport: 40-340
	startY := 200 + rand.Intn(450) // 200-650
	startTime := time.Now().UnixMilli() - int64(rand.Intn(3000)+1500)
	numPoints := 20 + rand.Intn(15)
	points := make([]string, 0, numPoints)

	for i := 0; i < numPoints; i++ {
		// Micro-pause: sometimes repeat the same position for 2-3 frames
		if i > 2 && rand.Intn(8) == 0 {
			for repeat := 0; repeat < 1+rand.Intn(2); repeat++ {
				startTime += int64(rand.Intn(60) + 40)
				if len(points) < numPoints {
					points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, startX, startY, startTime))
				}
			}
			continue
		}
		// Return movement: go backwards 2-8px every ~6 steps
		if i > 3 && rand.Intn(6) == 0 {
			startX -= rand.Intn(8) + 2
			startY -= rand.Intn(5) + 1
		} else {
			startX += rand.Intn(20) - 5 // -5..+14
			startY += rand.Intn(18) - 3 // -3..+14 — not always downward
		}
		startTime += int64(rand.Intn(50) + 15) // 15-65ms between points
		// Keep the trajectory inside a phone viewport so accumulated drift can't
		// place touch points off-screen.
		startX = clampInt(startX, 8, 404)
		startY = clampInt(startY, 60, 850)
		points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, startX, startY, startTime))
	}
	return "[" + strings.Join(points, ",") + "]"
}

// generateSensorNoise produces realistic accelerometer/gyroscope noise.
func generateSensorNoise() string {
	// Accelerometer: tiny random values around zero (gravity compensated)
	accelPoints := make([]string, 8+rand.Intn(6))
	for i := range accelPoints {
		accelPoints[i] = fmt.Sprintf(`{"x":%.4f,"y":%.4f,"z":%.4f}`,
			(rand.Float64()-0.5)*0.04, // ±0.02g
			(rand.Float64()-0.5)*0.04,
			1.0+(rand.Float64()-0.5)*0.03) // ~1g gravity ± noise
	}
	return "[" + strings.Join(accelPoints, ",") + "]"
}

func generateGyroNoise() string {
	// Gyroscope: tiny rotation rates
	points := make([]string, 8+rand.Intn(6))
	for i := range points {
		points[i] = fmt.Sprintf(`{"x":%.4f,"y":%.4f,"z":%.4f}`,
			(rand.Float64()-0.5)*0.02,
			(rand.Float64()-0.5)*0.02,
			(rand.Float64()-0.5)*0.02)
	}
	return "[" + strings.Join(points, ",") + "]"
}

// generateConnectionMetrics produces realistic network metrics with natural variance.
func generateConnectionMetrics() (rtt string, downlink string) {
	rttValues := make([]string, 10)
	for i := range rttValues {
		// 45-85ms with occasional spike
		base := 45 + rand.Intn(40)
		if rand.Intn(10) == 0 {
			base += rand.Intn(40) // spike up to 125ms
		}
		rttValues[i] = strconv.Itoa(base)
	}
	rtt = "[" + strings.Join(rttValues, ",") + "]"

	dlValues := make([]string, 16)
	for i := range dlValues {
		base := 7.5 + rand.Float64()*7.0 // 7.5-14.5 Mbps
		dlValues[i] = fmt.Sprintf("%.1f", math.Round(base*10)/10)
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
	applyBrowserProfileFhttp(req, profile)
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
	// Android Chrome: the visual viewport is the screen height minus the system
	// status bar (availHeight) and additionally the URL/navigation chrome
	// (innerHeight). screen.width == layout viewport width on mobile.
	availHeight := vp.Height - 24 - rand.Intn(8)   // status bar: 24-31px
	innerHeight := vp.Height - 112 - rand.Intn(40) // URL bar + nav: 112-151px
	platform := profile.Platform
	if platform == "" {
		platform = "Linux armv8l"
	}
	memChoices := []int{4, 6, 8}

	return fmt.Sprintf(
		`{"screenWidth":%d,"screenHeight":%d,"screenAvailWidth":%d,"screenAvailHeight":%d,"innerWidth":%d,"innerHeight":%d,"devicePixelRatio":%s,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":%d,"deviceMemory":%d,"maxTouchPoints":5,"connectionEffectiveType":"4g","notificationsPermission":"default","userAgent":"%s","platform":"%s"}`,
		vp.Width, vp.Height, vp.Width, availHeight, vp.Width, innerHeight,
		strconv.FormatFloat(vp.DevicePixelRatio, 'f', -1, 64),
		6+rand.Intn(3), // 6-8 cores
		memChoices[rand.Intn(len(memChoices))],
		profile.UserAgent,
		platform,
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
	applyBrowserProfileFhttp(req, profile)
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
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		req, err := fhttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		applyBrowserProfileFhttp(req, profile)
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
	baseParams := fmt.Sprintf("session_token=%s&domain=vk.com&adFp=&access_token=", neturl.QueryEscape(sessionToken))

	turnLog("[STREAM %d] [Captcha] Step 1/4: settings", streamID)
	settingsResp, err := vkReq("captchaNotRobot.settings", baseParams)
	if err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}
	if parsedSettings, perr := parseCaptchaSettingsResponse(settingsResp); perr == nil && parsedSettings != nil {
		if _, hasSlider := parsedSettings.SettingsByType[sliderCaptchaType]; hasSlider {
			turnLog("[STREAM %d] [Captcha] Slider detected in settings — aborting HTTP solve", streamID)
			return "", errSliderDetected
		}
	}

	time.Sleep(time.Duration(180+rand.Intn(80)) * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 2/4: componentDone (viewport=%dx%d)", streamID, vp.Width, vp.Height)
	browserFp := generateBrowserFp(profile, vp)
	deviceJSON := buildCaptchaDeviceJSON(profile, vp)
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", browserFp, neturl.QueryEscape(deviceJSON))

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}

	time.Sleep(time.Duration(180+rand.Intn(80)) * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 3/4: check", streamID)
	cursorJSON := generateHumanCursor()
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

	accelJSON := generateSensorNoise()
	gyroJSON := generateGyroNoise()
	connRtt, connDownlink := generateConnectionMetrics()

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape(accelJSON), neturl.QueryEscape(gyroJSON), neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON), neturl.QueryEscape("[]"), neturl.QueryEscape(connRtt),
		neturl.QueryEscape(connDownlink),
		browserFp, hash, answer, debugInfo,
	)

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
	default:
		return "", fmt.Errorf("check status: %s", status)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found")
	}

	time.Sleep(time.Duration(180+rand.Intn(80)) * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 4/4: endSession", streamID)
	if _, err := vkReq("captchaNotRobot.endSession", baseParams); err != nil {
		turnLog("[STREAM %d] [Captcha] Warning: endSession failed: %v", streamID, err)
	}

	return successToken, nil
}
