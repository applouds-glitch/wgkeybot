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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	neturl "net/url"
	"strings"
	"sync"
	"time"
	"unsafe"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
	"github.com/kiper292/tls-client/profiles"
	"github.com/google/uuid"
)

// VKCredentials stores VK API client credentials
type VKCredentials struct {
	ClientID     string
	ClientSecret string
}

// Predefined list of VK credentials (tried in order until success)
var vkCredentialsList = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"}, // VK_WEB_APP_ID
}

// vkRequestMu serializes VK API requests to avoid flood control
var vkRequestMu sync.Mutex

// captchaTokenCaches stores per-link WebView-solved success_tokens.
// Each VK link has its own entry because a success_token is bound to
// that link's captcha session and cannot be shared across links.
type captchaTokenEntry struct {
	mu    sync.Mutex
	token string
	uses  int
}

var captchaTokenCaches = struct {
	mu sync.Mutex
	m  map[string]*captchaTokenEntry
}{m: make(map[string]*captchaTokenEntry)}

func getCaptchaEntry(link string) *captchaTokenEntry {
	captchaTokenCaches.mu.Lock()
	defer captchaTokenCaches.mu.Unlock()
	e, ok := captchaTokenCaches.m[link]
	if !ok {
		e = &captchaTokenEntry{}
		captchaTokenCaches.m[link] = e
	}
	return e
}

func pushCaptchaToken(link, token string, maxUses int) {
	e := getCaptchaEntry(link)
	e.mu.Lock()
	e.token = token
	e.uses = maxUses
	e.mu.Unlock()
	turnLog("[Captcha] success_token cached for link %.12s, up to %d uses", link, maxUses)
}

func popCaptchaToken(link string) string {
	e := getCaptchaEntry(link)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.token == "" || e.uses <= 0 {
		return ""
	}
	e.uses--
	turnLog("[Captcha] Using cached success_token for link %.12s (%d uses left)", link, e.uses)
	return e.token
}

func invalidateCaptchaToken(link string) {
	e := getCaptchaEntry(link)
	e.mu.Lock()
	e.token = ""
	e.uses = 0
	e.mu.Unlock()
	turnLog("[Captcha] Cached success_token invalidated for link %.12s", link)
}

type captchaSolveMode int

const (
	captchaSolveModeAuto captchaSolveMode = iota
	captchaSolveModeSliderPOC
	captchaSolveModeManual
	captchaSolveModeManualVisible
)

// captchaSliderSentinel is returned by the Kotlin captcha handler (see
// CAPTCHA_SLIDER_SENTINEL in Application.kt) when the invisible WebView
// positively identified a slider captcha. It signals "not a token — run the
// slider POC". Must stay byte-for-byte in sync with the Kotlin constant.
const captchaSliderSentinel = "__WGK_SLIDER_DETECTED__"

// captchaSolveModeForAttempt returns the next captcha solve mode for a given attempt.
// Order: HTTP auto → invisible WebView → visible WebView dialog.
// captchaSolveModeSliderPOC is intentionally NOT in this list — it is invoked
// dynamically only when the HTTP solver returns errSliderDetected.
func captchaSolveModeForAttempt(attempt int, manualCaptcha bool, enableSliderPOC bool) (captchaSolveMode, bool) {
	var modes []captchaSolveMode
	modes = append(modes, captchaSolveModeAuto)
	if manualCaptcha {
		modes = append(modes, captchaSolveModeManual)
	}
	if manualCaptcha {
		modes = append(modes, captchaSolveModeManualVisible)
	}
	if attempt < len(modes) {
		return modes[attempt], true
	}
	return 0, false
}

func captchaSolveModeLabel(mode captchaSolveMode) string {
	switch mode {
	case captchaSolveModeAuto:
		return "auto captcha"
	case captchaSolveModeSliderPOC:
		return "auto captcha slider POC"
	case captchaSolveModeManual:
		return "manual captcha"
	case captchaSolveModeManualVisible:
		return "manual captcha (visible dialog)"
	default:
		return "captcha"
	}
}

// vkDelayRandom sleeps for a random duration between minMs and maxMs to avoid bot detection
func vkDelayRandom(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func getCustomNetDialer() net.Dialer {
	return net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   protectControl,
	}
}

// Custom dial context that resolves domains via DNS cache
func getCustomDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	resolvedIP, err := hostCache.Resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	dialer := getCustomNetDialer()
	return dialer.DialContext(ctx, network, net.JoinHostPort(resolvedIP, port))
}

// fetchVkCreds performs the actual VK/OK API calls to fetch credentials.
// Returns (username, password, serverAddr, lifetimeSecs, error).
func fetchVkCreds(ctx context.Context, link string) (string, string, string, int, error) {
	client, err := tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
		tlsclient.WithDialer(getCustomNetDialer()),
		tlsclient.WithDialContext(getCustomDialContext),
	)

	if err != nil {
		return "", "", "", 0, fmt.Errorf("failed to create tlsclient: %w", err)
	}
	defer client.CloseIdleConnections()

	profile := Profile{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Not(A:Brand";v="99", "Google Chrome";v="146", "Chromium";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
	}

	var lastErr error
	for _, creds := range vkCredentialsList {
		user, pass, addr, lifetime, err := getTokenChain(ctx, link, creds, client, profile)
		if err == nil {
			return user, pass, addr, lifetime, nil
		}
		lastErr = err
		if strings.Contains(err.Error(), "error_code:29") || strings.Contains(err.Error(), "Rate limit") {
			turnLog("[VK Auth] Rate limit detected, trying next credentials...")
		}
	}
	return "", "", "", 0, fmt.Errorf("all VK credentials failed: %w", lastErr)
}

// getTokenChain performs the VK/OK API token chain with given credentials.
// Returns (username, password, serverAddr, lifetimeSecs, error).
func getTokenChain(ctx context.Context, link string, creds VKCredentials, client tlsclient.HttpClient, profile Profile) (string, string, string, int, error) {

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		parsedURL, err := neturl.Parse(url)
		if err != nil {
			return nil, fmt.Errorf("parse request URL: %w", err)
		}
		domain := parsedURL.Hostname()

		req, err := fhttp.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Host = domain
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				turnLog("close response body: %s", closeErr)
			}
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	name := generateName()
	escapedName := neturl.QueryEscape(name)

	// Token 1
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		turnLog("[VK Auth] Token 1 request failed: %v", err)
		return "", "", "", 0, err
	}
	if errMsg, ok := resp["error"].(map[string]interface{}); ok {
		turnLog("[VK Auth] Token 1 VK API error: %v", errMsg)
		return "", "", "", 0, fmt.Errorf("VK API error (token1): %v", errMsg)
	}
	dataRaw, ok := resp["data"]
	if !ok {
		return "", "", "", 0, fmt.Errorf("invalid response structure for token1: 'data' not found")
	}
	dataMap, ok := dataRaw.(map[string]interface{})
	if !ok || dataMap == nil {
		return "", "", "", 0, fmt.Errorf("invalid response structure for token1: %v", resp)
	}
	token1Raw, ok := dataMap["access_token"]
	if !ok {
		return "", "", "", 0, fmt.Errorf("token1 not found in response: %v", resp)
	}
	token1, ok := token1Raw.(string)
	if !ok {
		return "", "", "", 0, fmt.Errorf("token1 is not a string: %v", token1Raw)
	}
	turnLog("[VK Auth] Token 1 (anonym_token) received")

	vkDelayRandom(500, 1000)

	// Token 2
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)

	manualCaptcha := true
	autoCaptchaSliderPOC := true
	streamID := 0
	// Set to true when slider POC fails on a slider-confirmed captcha. In that
	// case the invisible WebView (captchaSolveModeManual) can't help either,
	// so we skip it and jump straight to the visible dialog.
	sliderEscalationFailed := false

	// Pre-send a cached success_token if one exists. VK may honour it and skip
	// the captcha challenge entirely. If VK still returns error 14, we invalidate
	// the cache and fall through to the normal flow:
	//   HTTP auto → (slider POC if slider advertised) → invisible WebView → visible dialog
	// If the slider POC fails on a slider-confirmed captcha, the invisible WebView
	// is skipped and we jump straight to the visible dialog.
	baseData := data
	cachedSuccessToken := popCaptchaToken(link)
	if cachedSuccessToken != "" {
		data = baseData + "&success_token=" + neturl.QueryEscape(cachedSuccessToken)
	}

	var token2 string
	for attempt := 0; ; attempt++ {
		resp, err = doRequest(data, urlAddr)
		if err != nil {
			return "", "", "", 0, err
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			captchaErr := ParseVkCaptchaError(errObj)
			if captchaErr != nil && captchaErr.IsCaptchaError() {
				// Cached token was rejected — invalidate and retry from base data.
				if cachedSuccessToken != "" {
					invalidateCaptchaToken(link)
					cachedSuccessToken = ""
					data = baseData
				}
				solveMode, hasSolveMode := captchaSolveModeForAttempt(attempt, manualCaptcha, autoCaptchaSliderPOC)
				// If slider POC already failed on a slider-confirmed captcha, the
				// invisible WebView can't solve it either — skip straight to the
				// visible dialog.
				if sliderEscalationFailed && solveMode == captchaSolveModeManual {
					turnLog("[STREAM %d] [Captcha] Skipping invisible WebView (slider unsolved) — jumping to visible dialog", streamID)
					attempt++
					solveMode, hasSolveMode = captchaSolveModeForAttempt(attempt, manualCaptcha, autoCaptchaSliderPOC)
				}
				if !hasSolveMode {
					turnLog("[STREAM %d] [Captcha] No more solve modes available (attempt %d)", streamID, attempt+1)
					return "", "", "", 0, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}

				var successToken string
				var captchaKey string
				var solveErr error

				switch solveMode {
				case captchaSolveModeAuto:
					turnLog("[Captcha] Attempt %d. Try auto solving...", attempt+1)
					if captchaErr.SessionToken != "" && captchaErr.RedirectURI != "" {
						successToken, solveErr = solveVkCaptcha(ctx, captchaErr, streamID, client, profile, false)
						if solveErr != nil {
							turnLog("[STREAM %d] [Captcha] Auto captcha failed: %v", streamID, solveErr)
						}
						// Slider advertised in settings → escalate to slider POC right
						// now (don't waste a WebView round on a slider it can't solve).
						if errors.Is(solveErr, errSliderDetected) && autoCaptchaSliderPOC {
							turnLog("[STREAM %d] [Captcha] Slider detected — escalating to slider POC", streamID)
							successToken, solveErr = solveVkCaptcha(ctx, captchaErr, streamID, client, profile, true)
							if solveErr != nil {
								turnLog("[STREAM %d] [Captcha] Slider POC failed: %v", streamID, solveErr)
								sliderEscalationFailed = true
							}
						}
					} else {
						solveErr = fmt.Errorf("missing fields for auto solve")
					}
				case captchaSolveModeSliderPOC:
					turnLog("[Captcha] Attempt %d. Try slider solving...", attempt+1)
					if captchaErr.SessionToken != "" && captchaErr.RedirectURI != "" {
						successToken, solveErr = solveVkCaptcha(ctx, captchaErr, streamID, client, profile, true)
						if solveErr != nil {
							turnLog("[STREAM %d] [Captcha] Auto captcha slider POC failed: %v", streamID, solveErr)
						}
					} else {
						solveErr = fmt.Errorf("missing fields for slider POC auto solve")
					}
				case captchaSolveModeManual:
					turnLog("[STREAM %d] [Captcha] Triggering WebView captcha...", streamID)
					turnLog("[Captcha] Attempt %d. Web view solving...", attempt+1)
					turnLog("[Captcha] Opening WebView for manual solving...")
					redirectURICStr := C.CString(captchaErr.RedirectURI)
					defer C.free(unsafe.Pointer(redirectURICStr))

					cToken := C.requestCaptcha(redirectURICStr)
					if cToken == nil {
						solveErr = fmt.Errorf("WebView captcha solving failed: returned nil token")
					}
					defer C.free(unsafe.Pointer(cToken))

					successToken = C.GoString(cToken)
					if successToken == captchaSliderSentinel {
						// Invisible WebView positively identified a slider. Run the
						// slider POC now — it's the only automated solver for sliders,
						// and the visible dialog (next mode) would just annoy the user.
						successToken = ""
						turnLog("[STREAM %d] [Captcha] WebView reported slider — escalating to slider POC", streamID)
						if captchaErr.SessionToken != "" && captchaErr.RedirectURI != "" {
							successToken, solveErr = solveVkCaptcha(ctx, captchaErr, streamID, client, profile, true)
							if solveErr != nil {
								turnLog("[STREAM %d] [Captcha] Slider POC failed: %v", streamID, solveErr)
							} else {
								turnLog("[Captcha] Slider POC solution SUCCESS! Got success_token")
								pushCaptchaToken(link, successToken, 4)
							}
						} else {
							solveErr = fmt.Errorf("missing fields for slider POC after WebView slider")
						}
					} else if successToken == "" {
						solveErr = fmt.Errorf("WebView captcha solving failed: returned empty token")
					} else {
						solveErr = nil
						turnLog("[Captcha] WebView solution SUCCESS! Got success_token")
						pushCaptchaToken(link, successToken, 4)
					}
				case captchaSolveModeManualVisible:
					turnLog("[STREAM %d] [Captcha] Triggering visible captcha dialog...", streamID)
					turnLog("[Captcha] Attempt %d. Visible dialog solving...", attempt+1)
					redirectURICStr := C.CString(captchaErr.RedirectURI)
					defer C.free(unsafe.Pointer(redirectURICStr))

					cToken := C.requestCaptcha(redirectURICStr)
					if cToken == nil {
						solveErr = fmt.Errorf("Visible captcha solving failed: returned nil token")
					}
					defer C.free(unsafe.Pointer(cToken))

					successToken = C.GoString(cToken)
					if successToken == "" {
						solveErr = fmt.Errorf("Visible captcha solving failed: returned empty token")
					} else {
						solveErr = nil
						turnLog("[Captcha] Visible dialog solution SUCCESS! Got success_token")
						pushCaptchaToken(link, successToken, 4)
					}
				}

				if solveErr != nil {
					turnLog("[STREAM %d] [Captcha] %s failed (attempt %d): %v", streamID, captchaSolveModeLabel(solveMode), attempt+1, solveErr)
					nextSolveMode, hasNextSolveMode := captchaSolveModeForAttempt(attempt+1, manualCaptcha, autoCaptchaSliderPOC)
					if hasNextSolveMode {
						turnLog("[STREAM %d] [Captcha] Falling back to %s...", streamID, captchaSolveModeLabel(nextSolveMode))
						continue
					}
					return "", "", "", 0, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}

				if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
					captchaErr.CaptchaAttempt = "1"
				}

				if captchaKey != "" {
					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&captcha_key=%s&captcha_sid=%s&access_token=%s",
						link, escapedName, neturl.QueryEscape(captchaKey), captchaErr.CaptchaSid, token1)
				} else {
					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
						link, escapedName, captchaErr.CaptchaSid, neturl.QueryEscape(successToken), captchaErr.CaptchaTs, captchaErr.CaptchaAttempt, token1)
				}
				continue
			}
			return "", "", "", 0, fmt.Errorf("VK API error: %v", errObj)
		}

		responseRaw, okLoop := resp["response"]
		if !okLoop {
			return "", "", "", 0, fmt.Errorf("invalid response structure for token2: 'response' not found, response: %v", resp)
		}

		respMap, okLoop := responseRaw.(map[string]interface{})
		if !okLoop {
			return "", "", "", 0, fmt.Errorf("unexpected getAnonymousToken response: %v", resp)
		}

		token2Raw, okToken2 := respMap["token"]
		if !okToken2 {
			return "", "", "", 0, fmt.Errorf("token2 not found in response: %v", resp)
		}

		token2, okLoop = token2Raw.(string)
		if !okLoop {
			return "", "", "", 0, fmt.Errorf("token2 is not a string: %v", token2Raw)
		}

		break
	} // end of for

	turnLog("[VK Auth] Token 2 (messages token) received")

	vkDelayRandom(100, 200)

	// Token 3
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", neturl.QueryEscape(sessionData))
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", 0, err
	}
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		return "", "", "", 0, fmt.Errorf("Token 3 API error: %s", errMsg)
	}
	token3Raw, ok := resp["session_key"]
	if !ok {
		return "", "", "", 0, fmt.Errorf("token3 not found in response: %v", resp)
	}
	token3, ok := token3Raw.(string)
	if !ok {
		return "", "", "", 0, fmt.Errorf("token3 is not a string: %v", token3Raw)
	}
	turnLog("[VK Auth] Token 3 (session_key) received")

	vkDelayRandom(100, 200)

	// Token 4 -> TURN Creds
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", neturl.QueryEscape(link), token2, token3)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", 0, err
	}
	if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
		return "", "", "", 0, fmt.Errorf("Token 4 API error: %s", errMsg)
	}
	turnLog("[VK Auth] TURN credentials received")

	tsRaw, ok := resp["turn_server"]
	if !ok {
		return "", "", "", 0, fmt.Errorf("turn_server not found in response: %v", resp)
	}
	ts, ok := tsRaw.(map[string]interface{})
	if !ok || ts == nil {
		return "", "", "", 0, fmt.Errorf("invalid turn_server type: %v", tsRaw)
	}
	urlsRaw, ok := ts["urls"]
	if !ok {
		return "", "", "", 0, fmt.Errorf("urls not found in turn_server: %v", ts)
	}
	urls, ok := urlsRaw.([]interface{})
	if !ok || len(urls) == 0 {
		return "", "", "", 0, fmt.Errorf("invalid urls in turn_server: %v", ts)
	}
	urlStr, ok := urls[0].(string)
	if !ok {
		return "", "", "", 0, fmt.Errorf("invalid url type in turn_server: %v", ts)
	}
	address := strings.TrimPrefix(strings.TrimPrefix(strings.Split(urlStr, "?")[0], "turn:"), "turns:")

	host, port, err := net.SplitHostPort(address)
	if err == nil {
		if ip := net.ParseIP(host); ip == nil {
			resolvedIP, err := hostCache.Resolve(ctx, host)
			if err != nil {
				turnLog("[TURN DNS] Warning: failed to resolve TURN server %s: %v", host, err)
			} else {
				address = net.JoinHostPort(resolvedIP, port)
				turnLog("[TURN DNS] Resolved TURN server %s -> %s", host, resolvedIP)
			}
		}
	}

	usernameRaw, ok := ts["username"]
	if !ok {
		return "", "", "", 0, fmt.Errorf("username not found in turn_server: %v", ts)
	}
	username, ok := usernameRaw.(string)
	if !ok || username == "" {
		return "", "", "", 0, fmt.Errorf("username not found in turn_server: %v", ts)
	}
	credentialRaw, ok := ts["credential"]
	if !ok {
		return "", "", "", 0, fmt.Errorf("credential not found in turn_server: %v", ts)
	}
	credential, ok := credentialRaw.(string)
	if !ok || credential == "" {
		return "", "", "", 0, fmt.Errorf("credential not found in turn_server: %v", ts)
	}

	// Parse TTL from turn_server response (VK returns "lifetime" or "ttl" in seconds).
	var lifetimeSecs int
	if v, ok := ts["lifetime"].(float64); ok && v > 0 {
		lifetimeSecs = int(v)
	} else if v, ok := ts["ttl"].(float64); ok && v > 0 {
		lifetimeSecs = int(v)
	}
	turnLog("[VK Auth] turn_server keys: %v", func() []string {
		keys := make([]string, 0, len(ts))
		for k, v := range ts {
			keys = append(keys, fmt.Sprintf("%s=%v", k, v))
		}
		return keys
	}())
	turnLog("[VK Auth] TURN lifetime from API: %ds", lifetimeSecs)

	vkDelayRandom(5000, 5000)

	return username, credential, address, lifetimeSecs, nil
}
