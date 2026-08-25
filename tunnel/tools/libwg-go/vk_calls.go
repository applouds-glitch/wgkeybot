/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

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
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/google/uuid"
	tlsclient "github.com/kiper292/tls-client"
)

// VK Calls anonymous flow — the captcha-free path to TURN credentials.
//
// Unlike the legacy chain (login.vk.com get_anonym_token → calls.getAnonymousToken
// on api.vk.com v5.282, which is captcha-gated with error_code 14), this flow
// uses the VK Connect app id on api.vk.me with the messages.* endpoints, which
// mint an OK anonym call token WITHOUT a captcha. The final OK CDN join
// (auth.anonymLogin + vchat.joinConversationByLink on calls.okcdn.ru) is the
// same handshake the legacy path already performs.
//
// Ported from amurcanov/proxy-turn-vk-android#218 (itself ported from the iOS
// client), adapted to reuse our protected-socket TLS client, DNS resolver and
// turn_server lifetime parsing.
const (
	vkConnectClientID     = "8093730"
	vkCallsAPIHost        = "internal.api.vk.ru"
	vkCallsAnonAPIVersion = "5.276"
	vkCallsOKHost         = "https://calls.okcdn.ru/fb.do"
	vkCallsOKAppKey       = "CGMMEJLGDIHBABABA"
)

// errCallUnavailable marks a terminal "the VK call is gone" failure: the call
// ended, was deleted, or the join link is invalid/expired. No captcha,
// credential rotation or retry can recover it, so the caller must stop instead
// of falling back to the legacy captcha chain (which would burn credentials and
// prompt the user for a captcha it can never satisfy). The message carries the
// "CALL_UNAVAILABLE" marker so the string-matching pre-fetch caller in
// turn-client.go recognises it, while Go callers can use isCallUnavailable.
var errCallUnavailable = errors.New("CALL_UNAVAILABLE")

func callUnavailablef(format string, a ...interface{}) error {
	return fmt.Errorf("%w: "+format, append([]interface{}{errCallUnavailable}, a...)...)
}

func isCallUnavailable(err error) bool { return errors.Is(err, errCallUnavailable) }

// errVKCallsTransient marks a failure that says nothing about the request and is
// worth simply repeating: VK's own "come back later" codes, an HTTP 5xx, or a
// request that never produced a parsable answer.
//
// It exists because failing this flow is not free. The caller falls through to
// the legacy chain, and that is where the captcha lives — so one hiccup at VK
// used to cost the user a full-screen captcha dialog for a call that would have
// gone through a second later.
var errVKCallsTransient = errors.New("transient VK Calls failure")

func transientVKCallsf(format string, a ...interface{}) error {
	return fmt.Errorf("%w: "+format, append([]interface{}{errVKCallsTransient}, a...)...)
}

func isTransientVKCalls(err error) bool { return errors.Is(err, errVKCallsTransient) }

// isRetryableVKCode reports whether a VK error_code is VK asking us to come back
// rather than a verdict on the request: 1 (unknown error), 6 (too many requests
// per second) and 10 (internal server error) are all documented as "try again".
// Notably absent is 14: a captcha gate is a verdict, and the legacy chain — not
// a retry — is what can answer it.
func isRetryableVKCode(code int) bool {
	switch code {
	case 1, 6, 10:
		return true
	default:
		return false
	}
}

// isFatalVKCallCode reports whether a VK api.vk.me error_code means the call is
// permanently unreachable. Ported from amurcanov/proxy-turn-vk-android@d95b65b5:
// 951 (call not found) and 954 (invalid/expired join link) on the messages.*
// endpoints. The legacy calls.getAnonymousToken 9xxx call domain is classified
// separately in getTokenChain, since 9005 there means CALL_REQUIRES_AUTH.
func isFatalVKCallCode(code int) bool {
	switch code {
	case 951, 954:
		return true
	default:
		return false
	}
}

const (
	// vkCallsAttempts bounds how many times the whole flow runs before the caller
	// falls through to the legacy captcha chain. Three attempts cost at most ~2s
	// of extra requests; the captcha they avoid costs a dialog and six seconds of
	// the user's attention, so the trade is lopsided in favour of retrying.
	vkCallsAttempts = 3
	// vkCallsRetryDelay is the per-attempt backoff step, jittered below. Kept
	// short because the flow itself takes under a second and the whole point is
	// to beat the captcha detour rather than to wait out a real outage.
	vkCallsRetryDelay = 400 * time.Millisecond
)

// getVKCredsViaVKCalls returns (username, password, resolvedTurnAddrs,
// lifetimeSecs, error) from the VK Calls anonymous flow, repeating the whole
// flow while VK answers with something transient.
//
// The retry is deliberately of the whole flow rather than the failing step: each
// attempt is a fresh anonymous device with its own token chain, so a step that
// failed is not resumed under an identity VK has already refused. Steps 1-2 are
// two extra cheap requests, which is the entire cost.
func getVKCredsViaVKCalls(ctx context.Context, link string, client tlsclient.HttpClient, profile Profile) (string, string, []string, int, error) {
	var lastErr error
	for attempt := 1; attempt <= vkCallsAttempts; attempt++ {
		user, pass, addrs, lifetime, err := vkCallsAttempt(ctx, link, client, profile)
		if err == nil {
			return user, pass, addrs, lifetime, nil
		}
		lastErr = err
		// A cancelled context is our own teardown, and a non-transient error is a
		// verdict — captcha gate, dead call, malformed link. Neither is worth a
		// second identical trip to VK.
		if ctx.Err() != nil || !isTransientVKCalls(err) || attempt == vkCallsAttempts {
			break
		}
		delay := time.Duration(attempt)*vkCallsRetryDelay + time.Duration(rand.Intn(300))*time.Millisecond
		turnLog("[VKCalls] attempt %d/%d failed (%v) — retrying in %v", attempt, vkCallsAttempts, err, delay.Round(time.Millisecond))
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return "", "", nil, 0, ctx.Err()
		}
	}
	return "", "", nil, 0, lastErr
}

// vkCallsAttempt runs the 5-step VK Calls anonymous flow once. It reuses the
// caller's TLS client so requests still go over wgProtectSocket-bound sockets.
//
// device_id is freshly generated per attempt, deliberately. Sourcing it from the
// persisted captcha persona instead made every credential group present the SAME
// anonymous device, and groups fetch concurrently (vkSemaphore admits two) into
// the same call: two identical devices racing one messages.getAnonymCallToken,
// which VK answers with error_code 10.
func vkCallsAttempt(ctx context.Context, link string, client tlsclient.HttpClient, profile Profile) (string, string, []string, int, error) {
	deviceID := uuid.New().String()
	name := generateName()
	nameEnc := neturl.QueryEscape(name)
	linkURL := neturl.QueryEscape("https://vk.ru/call/join/" + link)

	doRequest := func(step, url string) (map[string]interface{}, error) {
		req, err := fhttp.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(nil))
		if err != nil {
			return nil, fmt.Errorf("%s: create request: %w", step, err)
		}
		req.Header.Set("User-Agent", profile.UserAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", profileAcceptLanguage(profile))

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, transientVKCallsf("%s: request failed: %w", step, err)
		}
		defer func() { _ = httpResp.Body.Close() }()

		if httpResp.StatusCode >= 500 {
			return nil, transientVKCallsf("%s: HTTP %d", step, httpResp.StatusCode)
		}
		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, transientVKCallsf("%s: read response: %w", step, err)
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			// Not JSON at all: a truncated body, or an interstitial from something
			// between us and VK. Either way the next attempt may well get an answer.
			return nil, transientVKCallsf("%s: unmarshal JSON: %w", step, err)
		}
		return resp, nil
	}

	// Step 1: auth.getAnonymToken (VK Connect app id) → anonymous_token.
	step1URL := fmt.Sprintf(
		"https://%s/method/auth.getAnonymToken?v=%s&client_id=%s&link=%s&device_id=%s&anonymName=%s&lang=en",
		vkCallsAPIHost, vkCallsAnonAPIVersion, vkConnectClientID, linkURL, deviceID, nameEnc,
	)
	resp1, err := doRequest("step1 auth.getAnonymToken", step1URL)
	if err != nil {
		return "", "", nil, 0, err
	}
	if apiErr := vkCallsAPIError("step1 auth.getAnonymToken", resp1); apiErr != nil {
		return "", "", nil, 0, apiErr
	}
	anonymToken, err := extractVKCallsStr(resp1, "response", "token")
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("step1 parse anonymous_token: %w", err)
	}
	anonymTokenEnc := neturl.QueryEscape(anonymToken)
	turnLog("[VKCalls] step1 OK, anonymous_token (%d chars)", len(anonymToken))

	// Step 2: messages.getCallPreview → user_id + secret.
	step2URL := fmt.Sprintf(
		"https://%s/method/messages.getCallPreview?v=%s&anonymous_token=%s&device_id=%s&extended=1&fields=first_name,last_name,photo_200&lang=en&link=%s",
		vkCallsAPIHost, vkCallsAnonAPIVersion, anonymTokenEnc, deviceID, linkURL,
	)
	resp2, err := doRequest("step2 messages.getCallPreview", step2URL)
	if err != nil {
		return "", "", nil, 0, err
	}
	if apiErr := vkCallsAPIError("step2 messages.getCallPreview", resp2); apiErr != nil {
		return "", "", nil, 0, apiErr
	}
	userIDFloat, err := extractVKCallsFloat(resp2, "response", "user_id")
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("step2 parse user_id: %w", err)
	}
	userIDStr := fmt.Sprintf("%.0f", userIDFloat)
	secret, err := extractVKCallsStr(resp2, "response", "secret")
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("step2 parse secret: %w", err)
	}
	turnLog("[VKCalls] step2 OK, user_id=%s, secret (%d chars)", userIDStr, len(secret))

	// Step 3: messages.getAnonymCallToken (user_id, secret) → OK anonym token.
	step3URL := fmt.Sprintf(
		"https://%s/method/messages.getAnonymCallToken?v=%s&anonymous_token=%s&device_id=%s&link=%s&name=%s&user_id=%s&secret=%s&lang=en",
		vkCallsAPIHost, vkCallsAnonAPIVersion, anonymTokenEnc, deviceID, linkURL, nameEnc, userIDStr, neturl.QueryEscape(secret),
	)
	resp3, err := doRequest("step3 messages.getAnonymCallToken", step3URL)
	if err != nil {
		return "", "", nil, 0, err
	}
	if apiErr := vkCallsAPIError("step3 messages.getAnonymCallToken", resp3); apiErr != nil {
		return "", "", nil, 0, apiErr
	}
	okAnonymToken, err := extractVKCallsStr(resp3, "response", "token")
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("step3 parse OK anonym token: %w", err)
	}
	turnLog("[VKCalls] step3 OK, OK anonymToken (%d chars)", len(okAnonymToken))

	// Step 4: auth.anonymLogin on the OK CDN → session_key.
	okDeviceID := uuid.New().String()
	step4URL := vkCallsOKHost + "?session_data=" +
		neturl.QueryEscape(fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":"1.0.1"}`, okDeviceID)) +
		"&method=auth.anonymLogin&format=JSON&application_key=" + vkCallsOKAppKey
	resp4, err := doRequest("step4 auth.anonymLogin", step4URL)
	if err != nil {
		return "", "", nil, 0, err
	}
	if okErr := vkCallsOKError("step4 auth.anonymLogin", resp4); okErr != nil {
		return "", "", nil, 0, okErr
	}
	sessionKey, err := extractVKCallsStr(resp4, "session_key")
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("step4 parse session_key: %w", err)
	}
	turnLog("[VKCalls] step4 OK, session_key (%d chars)", len(sessionKey))

	// Step 5: vchat.joinConversationByLink → turn_server creds.
	step5URL := fmt.Sprintf(
		"%s?joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=%s&session_key=%s",
		vkCallsOKHost, neturl.QueryEscape(link), okAnonymToken, vkCallsOKAppKey, sessionKey,
	)
	resp5, err := doRequest("step5 vchat.joinConversationByLink", step5URL)
	if err != nil {
		return "", "", nil, 0, err
	}
	if okErr := vkCallsOKError("step5 vchat.joinConversationByLink", resp5); okErr != nil {
		return "", "", nil, 0, okErr
	}

	user, pass, addrs, lifetime, err := parseVKCallsTurnServer(ctx, resp5)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("step5 %w", err)
	}
	turnLog("[VKCalls] SUCCESS — TURN urls=%d, lifetime=%ds (no captcha)", len(addrs), lifetime)
	return user, pass, addrs, lifetime, nil
}

// parseVKCallsTurnServer extracts username/credential, resolves every TURN URL
// through our DNS cache and reads the lifetime/ttl — mirroring the legacy chain.
func parseVKCallsTurnServer(ctx context.Context, resp map[string]interface{}) (string, string, []string, int, error) {
	ts, ok := resp["turn_server"].(map[string]interface{})
	if !ok || ts == nil {
		return "", "", nil, 0, fmt.Errorf("turn_server not found in response")
	}
	username, _ := ts["username"].(string)
	credential, _ := ts["credential"].(string)
	if username == "" || credential == "" {
		return "", "", nil, 0, fmt.Errorf("turn_server username/credential missing")
	}
	urls, ok := ts["urls"].([]interface{})
	if !ok || len(urls) == 0 {
		return "", "", nil, 0, fmt.Errorf("turn_server.urls empty")
	}

	var addresses []string
	for _, u := range urls {
		urlStr, ok := u.(string)
		if !ok {
			continue
		}
		address := strings.TrimPrefix(strings.TrimPrefix(strings.Split(urlStr, "?")[0], "turn:"), "turns:")
		if host, port, splitErr := net.SplitHostPort(address); splitErr == nil {
			if ip := net.ParseIP(host); ip == nil {
				if resolvedIP, resolveErr := hostCache.Resolve(ctx, host); resolveErr != nil {
					turnLog("[VKCalls] Warning: failed to resolve TURN server %s: %v", host, resolveErr)
				} else {
					address = net.JoinHostPort(resolvedIP, port)
					turnLog("[VKCalls] Resolved TURN server %s -> %s", host, resolvedIP)
				}
			}
		}
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		return "", "", nil, 0, fmt.Errorf("turn_server.urls had no usable addresses")
	}

	var lifetimeSecs int
	if v, ok := ts["lifetime"].(float64); ok && v > 0 {
		lifetimeSecs = int(v)
	} else if v, ok := ts["ttl"].(float64); ok && v > 0 {
		lifetimeSecs = int(v)
	}
	return username, credential, addresses, lifetimeSecs, nil
}

// vkCallsAPIError reports a VK API ("api.vk.me") error. error_code 14 is the
// captcha gate — surfaced distinctly so the log makes clear the captcha-free
// flow hit a captcha and the caller is falling back to the legacy path.
func vkCallsAPIError(step string, resp map[string]interface{}) error {
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		return nil
	}
	code, _ := errObj["error_code"].(float64)
	msg, _ := errObj["error_msg"].(string)
	if code == 0 && msg == "" {
		return nil
	}
	if isFatalVKCallCode(int(code)) {
		return callUnavailablef("%s: VK call unavailable (error_code %d): %s", step, int(code), msg)
	}
	if int(code) == 14 {
		return fmt.Errorf("%s: VK captcha gate (error_code 14): %s", step, msg)
	}
	if isRetryableVKCode(int(code)) {
		return transientVKCallsf("%s: VK API error_code=%d: %s", step, int(code), msg)
	}
	return fmt.Errorf("%s: VK API error_code=%d: %s", step, int(code), msg)
}

// vkCallsOKError reports an OK CDN ("calls.okcdn.ru") error, which surfaces as a
// top-level error_code/error_msg rather than a nested "error" object.
func vkCallsOKError(step string, resp map[string]interface{}) error {
	if msg, ok := resp["error"].(string); ok && msg != "" {
		return fmt.Errorf("%s: OK CDN error: %s", step, msg)
	}
	code, ok := resp["error_code"].(float64)
	if !ok || code == 0 {
		return nil
	}
	msg, _ := resp["error_msg"].(string)
	return fmt.Errorf("%s: OK CDN error_code=%d: %s", step, int(code), msg)
}

func extractVKCallsStr(resp map[string]interface{}, keys ...string) (string, error) {
	var cur interface{} = resp
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("expected map at key %q, got %T", k, cur)
		}
		cur = m[k]
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("expected string at path %v, got %T", keys, cur)
	}
	return s, nil
}

func extractVKCallsFloat(resp map[string]interface{}, keys ...string) (float64, error) {
	var cur interface{} = resp
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return 0, fmt.Errorf("expected map at key %q, got %T", k, cur)
		}
		cur = m[k]
	}
	f, ok := cur.(float64)
	if !ok {
		return 0, fmt.Errorf("expected number at path %v, got %T", keys, cur)
	}
	return f, nil
}
