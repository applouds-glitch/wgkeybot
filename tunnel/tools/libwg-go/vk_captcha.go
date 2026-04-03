/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// VkCaptchaError represents a VK captcha error
type VkCaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	CaptchaImg              string
	RedirectUri             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string // captcha_ts from error
	CaptchaAttempt          string // captcha_attempt from error
}

// ParseVkCaptchaError parses a VK error response into VkCaptchaError
func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	codeFloat, _ := errData["error_code"].(float64)
	code := int(codeFloat)

	redirectUri, _ := errData["redirect_uri"].(string)
	captchaSid, _ := errData["captcha_sid"].(string)
	captchaImg, _ := errData["captcha_img"].(string)
	errorMsg, _ := errData["error_msg"].(string)

	// Extract session_token from redirect_uri
	var sessionToken string
	if redirectUri != "" {
		if parsed, err := url.Parse(redirectUri); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		}
	}

	isSound, _ := errData["is_sound_captcha_available"].(bool)

	// captcha_ts can be float64 (scientific notation) or string
	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	// captcha_attempt is usually a float64
	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	return &VkCaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		CaptchaImg:              captchaImg,
		RedirectUri:             redirectUri,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

// IsCaptchaError checks if the error data is a Not Robot Captcha error
func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && e.RedirectUri != "" && e.SessionToken != ""
}

// solveVkCaptcha solves the VK Not Robot Captcha and returns success_token
func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError, streamID int) (string, error) {
	turnLog("[STREAM %d] [Captcha] Solving Not Robot Captcha...", streamID)

	// HAR: Token 2 error → Captcha HTML = 2.72s (browser page load + user perception)
	time.Sleep(1500*time.Millisecond + time.Duration(rand.Intn(1000))*time.Millisecond)

	sessionToken := captchaErr.SessionToken
	if sessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	// Step 1: Fetch the captcha HTML page to get powInput and cookies
	powInput, difficulty, cookies, err := fetchPowInput(ctx, captchaErr.RedirectUri, streamID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch PoW input: %w", err)
	}

	turnLog("[STREAM %d] [Captcha] PoW input: %s, difficulty: %d", streamID, powInput, difficulty)

	// Step 2: Solve PoW
	hash := solvePoW(powInput, difficulty)
	turnLog("[STREAM %d] [Captcha] PoW solved: hash=%s", streamID, hash)

	// Step 3: Call captchaNotRobot API with cookies from captcha page
	successToken, err := callCaptchaNotRobot(ctx, sessionToken, hash, cookies, streamID)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	turnLog("[STREAM %d] [Captcha] Success! Got success_token", streamID)
	return successToken, nil
}

// fetchPowInput fetches the captcha HTML page and extracts powInput, difficulty, and cookies
func fetchPowInput(ctx context.Context, redirectUri string, streamID int) (string, int, string, error) {
	parsedURL, err := url.Parse(redirectUri)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to parse redirect_uri: %w", err)
	}

	domain := parsedURL.Hostname()
	resolvedIP, err := hostCache.Resolve(ctx, domain)
	if err != nil {
		return "", 0, "", fmt.Errorf("DNS resolution failed for %s: %w", domain, err)
	}

	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}
	ipURL := "https://" + resolvedIP + ":" + port + parsedURL.Path
	if parsedURL.RawQuery != "" {
		ipURL += "?" + parsedURL.RawQuery
	}

	req, err := http.NewRequestWithContext(ctx, "GET", ipURL, nil)
	if err != nil {
		return "", 0, "", err
	}
	req.Host = domain
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   protectControl,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				ServerName: domain,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()

	// Capture Set-Cookie headers
	var cookies []string
	for _, setCookie := range resp.Header.Values("Set-Cookie") {
		// Extract just the cookie name=value part (before ; expires= or ; path=)
		cookieParts := strings.Split(setCookie, ";")
		cookies = append(cookies, strings.TrimSpace(cookieParts[0]))
	}
	cookieHeader := strings.Join(cookies, "; ")
	if cookieHeader != "" {
		turnLog("[STREAM %d] [Captcha] Captcha page set %d cookie(s)", streamID, len(cookies))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, "", err
	}

	html := string(body)

	// Extract powInput: const powInput = "..."
	powInputRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	powInputMatch := powInputRe.FindStringSubmatch(html)
	if len(powInputMatch) < 2 {
		return "", 0, "", fmt.Errorf("powInput not found in captcha HTML")
	}
	powInput := powInputMatch[1]

	// Extract difficulty: '0'.repeat(N)
	diffRe := regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`)
	diffMatch := diffRe.FindStringSubmatch(html)
	difficulty := 2 // default
	if len(diffMatch) >= 2 {
		if d, err := strconv.Atoi(diffMatch[1]); err == nil {
			difficulty = d
		}
	}

	return powInput, difficulty, cookieHeader, nil
}

// solvePoW finds nonce where SHA-256(powInput + nonce) starts with '0' * difficulty
func solvePoW(powInput string, difficulty int) string {
	target := strings.Repeat("0", difficulty)

	for nonce := 1; nonce <= 10000000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])

		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}

	// Fallback: should not happen with difficulty <= 3
	return ""
}

// callCaptchaNotRobot executes all 4 steps of the captchaNotRobot API
func callCaptchaNotRobot(ctx context.Context, sessionToken, hash, cookies string, streamID int) (string, error) {
	// Helper to make VK API requests
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		requestURL := "https://api.vk.ru/method/" + method + "?v=5.131"

		parsedURL, err := url.Parse(requestURL)
		if err != nil {
			return nil, err
		}

		domain := parsedURL.Hostname()
		resolvedIP, err := hostCache.Resolve(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed for %s: %w", domain, err)
		}

		port := parsedURL.Port()
		if port == "" {
			port = "443"
		}
		ipURL := "https://" + resolvedIP + ":" + port + parsedURL.Path
		if parsedURL.RawQuery != "" {
			ipURL += "?" + parsedURL.RawQuery
		}

		req, err := http.NewRequestWithContext(ctx, "POST", ipURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		req.Host = domain
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Referer", "https://id.vk.ru/")
		req.Header.Set("sec-ch-ua-platform", `"Windows"`)
		req.Header.Set("sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`)
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("DNT", "1")
		req.Header.Set("Priority", "u=1, i")
		// Add cookies captured from captcha page
		if cookies != "" {
			req.Header.Set("Cookie", cookies)
		}

		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					Control:   protectControl,
				}).DialContext,
				TLSClientConfig: &tls.Config{
					ServerName: domain,
				},
			},
		}

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()

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

	domain := "vk.com"
	baseParams := fmt.Sprintf("session_token=%s&domain=%s&adFp=&access_token=",
		url.QueryEscape(sessionToken), url.QueryEscape(domain))

	// Step 1: settings
	turnLog("[STREAM %d] [Captcha] Step 1/4: settings", streamID)
	_, err := vkReq("captchaNotRobot.settings", baseParams)
	if err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}
	// HAR: settings → componentDone = 0.19s
	time.Sleep(100*time.Millisecond + time.Duration(rand.Intn(100))*time.Millisecond)
	
	// Step 2: componentDone
	turnLog("[STREAM %d] [Captcha] Step 2/4: componentDone", streamID)
	// Generate random browser fingerprint (32 hex chars like MD5)
	browserFp := fmt.Sprintf("%016x%016x", rand.Int63(), rand.Int63())
	// Device info matching HAR capture
	deviceJSON := `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1032,"innerWidth":1920,"innerHeight":945,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":16,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"denied"}`
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s",
		browserFp, url.QueryEscape(deviceJSON))

	_, err = vkReq("captchaNotRobot.componentDone", componentDoneData)
	if err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}
	// HAR: componentDone → check ≈ 1.95s + statEvents delay ≈ 3.2s total
	time.Sleep(1500*time.Millisecond + time.Duration(rand.Intn(1000))*time.Millisecond)

	// Step 3: check (the main one)
	turnLog("[STREAM %d] [Captcha] Step 3/4: check", streamID)
	// Fake cursor data (few points simulating mouse movement)
	cursorJSON := `[{"x":950,"y":500},{"x":945,"y":510},{"x":940,"y":520},{"x":938,"y":525},{"x":938,"y":525}]`
	// answer = base64 of "{}" for checkbox captcha (matching HAR: e30=)
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))
	// Static debug_info from HAR capture
	debugInfo := "d44f534ce8deb56ba20be52e05c433309b49ee4d2a70602deeb17a1954257785"

	// Generate random connectionDownlink values (simulating Network Information API)
	// HAR shows browser repeats the same value 7 times: [9.8,9.8,9.8,9.8,9.8,9.8,9.8]
	baseDownlink := 8.0 + rand.Float64()*4.0 // Random in [8.0, 12.0) for typical WiFi
	downlinkStr := fmt.Sprintf("%.1f", baseDownlink)
	connectionDownlink := "[" + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "," + downlinkStr + "]"

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s"+
			"&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		url.QueryEscape("[]"),       // accelerometer
		url.QueryEscape("[]"),       // gyroscope
		url.QueryEscape("[]"),       // motion
		url.QueryEscape(cursorJSON), // cursor
		url.QueryEscape("[]"),       // taps
		url.QueryEscape("[]"),       // connectionRtt
		url.QueryEscape(connectionDownlink),
		browserFp, // browser_fp
		hash,      // hash (PoW result)
		answer,    // answer
		debugInfo, // debug_info (static)
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	// Extract success_token from response
	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}

	status, _ := respObj["status"].(string)
	if status != "OK" {
		return "", fmt.Errorf("check response status: %s, full response: %v", status, checkResp)
	}

	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found in check response: %v", checkResp)
	}

	// Step 4: endSession
	turnLog("[STREAM %d] [Captcha] Step 4/4: endSession", streamID)
	_, err = vkReq("captchaNotRobot.endSession", baseParams)
	if err != nil {
		// Not critical, we already have success_token
		turnLog("[STREAM %d] [Captcha] Warning: endSession failed: %v", streamID, err)
	}

	return successToken, nil
}
