/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// TurnCredentials stores cached TURN credentials
type TurnCredentials struct {
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
}

// StreamCredentialsCache holds credentials cache for a single stream
type StreamCredentialsCache struct {
	creds         TurnCredentials
	mutex         sync.RWMutex
	errorCount    atomic.Int32
	lastErrorTime atomic.Int64
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
	minRequestInterval = 1 * time.Second // Minimum interval between VK API requests
)

// vkRequestMu serializes VK API requests to avoid flood control
var vkRequestMu sync.Mutex

// credentialsStore manages per-stream credentials caches
var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*StreamCredentialsCache
}{
	caches: make(map[int]*StreamCredentialsCache),
}

// getStreamCache returns or creates a cache for the given stream ID
func getStreamCache(streamID int) *StreamCredentialsCache {
	// Try read lock first for fast path
	credentialsStore.mu.RLock()
	cache, exists := credentialsStore.caches[streamID]
	credentialsStore.mu.RUnlock()

	if exists {
		return cache
	}

	// Need to create new cache
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	// Double-check after acquiring write lock
	if cache, exists = credentialsStore.caches[streamID]; exists {
		return cache
	}

	cache = &StreamCredentialsCache{}
	credentialsStore.caches[streamID] = cache
	return cache
}

// isAuthError checks if the error is an authentication error
func isAuthError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "invalid credential") ||
		strings.Contains(errStr, "stale nonce")
}

// handleAuthError handles authentication errors for a specific stream.
// Returns true if cache was invalidated, false otherwise.
func handleAuthError(streamID int) bool {
	cache := getStreamCache(streamID)

	now := time.Now().Unix()

	// Reset counter if enough time has passed
	if now - cache.lastErrorTime.Load() > int64(errorWindow.Seconds()) {
		cache.errorCount.Store(0)
	}

	count := cache.errorCount.Add(1)
	cache.lastErrorTime.Store(now)

	turnLog("[STREAM %d] Auth error (count=%d/%d)", streamID, count, maxCacheErrors)

	// Invalidate cache only after N errors within the time window
	if count >= maxCacheErrors {
		turnLog("[VK Auth] Multiple auth errors detected (%d), invalidating cache for stream %d...", count, streamID)
		cache.invalidate(streamID)
		return true
	}

	return false
}

// invalidate invalidates the credentials cache for this stream
func (c *StreamCredentialsCache) invalidate(streamID int) {
	c.mutex.Lock()
	c.creds = TurnCredentials{}
	c.mutex.Unlock()

	// Reset auth error counter
	c.errorCount.Store(0)
	c.lastErrorTime.Store(0)

	turnLog("[STREAM %d] [VK Auth] Credentials cache invalidated", streamID)
}

// invalidateAllCaches invalidates all per-stream caches (called on network change)
func invalidateAllCaches() {
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	for streamID, cache := range credentialsStore.caches {
		cache.invalidate(streamID)
	}

	// Clear the map to free memory
	credentialsStore.caches = make(map[int]*StreamCredentialsCache)
	turnLog("[VK Auth] All per-stream caches cleared")
}

// getVkCreds fetches TURN credentials from VK/OK API with per-stream caching
func getVkCreds(ctx context.Context, link string, streamID int) (string, string, string, error) {
	cache := getStreamCache(streamID)

	// Check cache with read lock first (fast path)
	cache.mutex.RLock()
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		expires := time.Until(cache.creds.ExpiresAt)
		cache.mutex.RUnlock()
		turnLog("[STREAM %d] [VK Auth] Using cached credentials (expires in %v)", streamID, expires)
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr, nil
	}
	cache.mutex.RUnlock()

	turnLog("[STREAM %d] [VK Auth] Cache miss, starting credential fetch...", streamID)

	// Check context before long fetch
	select {
	case <-ctx.Done():
		return "", "", "", ctx.Err()
	default:
	}

	// Fetch credentials with rate limiting
	user, pass, addr, err := fetchVkCredsSerialized(ctx, link, streamID)
	if err != nil {
		return "", "", "", err
	}

	// Store in cache
	cache.mutex.Lock()
	cache.creds = TurnCredentials{
		Username:   user,
		Password:   pass,
		ServerAddr: addr,
		ExpiresAt:  time.Now().Add(credentialLifetime - cacheSafetyMargin),
		Link:       link,
	}
	cache.mutex.Unlock()

	turnLog("[STREAM %d] [VK Auth] Success! Credentials cached until %v", streamID, cache.creds.ExpiresAt)
	return user, pass, addr, nil
}

// fetchVkCredsSerialized wraps fetchVkCreds with rate limiting to avoid VK flood control
func fetchVkCredsSerialized(ctx context.Context, link string, streamID int) (string, string, string, error) {
	vkRequestMu.Lock()
	defer vkRequestMu.Unlock()

	user, pass, addr, err := fetchVkCreds(ctx, link, streamID)
	time.Sleep(minRequestInterval)
	return user, pass, addr, err
}

// fetchVkCreds performs the actual VK/OK API calls to fetch credentials
func fetchVkCreds(ctx context.Context, link string, streamID int) (string, string, string, error) {
	doRequest := func(data string, requestURL string) (resp map[string]interface{}, err error) {
		// Resolve host via DNS cache with cascading fallback
		parsedURL, err := url.Parse(requestURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse URL: %w", err)
		}

		// Resolve domain name
		domain := parsedURL.Hostname()
		resolvedIP, err := hostCache.Resolve(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed for %s: %w", domain, err)
		}

		// Replace host with IP in URL
		port := parsedURL.Port()
		if port == "" {
			port = "443"
		}
		ipURL := "https://" + resolvedIP + ":" + port + parsedURL.Path
		if parsedURL.RawQuery != "" {
			ipURL += "?" + parsedURL.RawQuery
		}

		// Create request with IP instead of domain
		req, err := http.NewRequestWithContext(ctx, "POST", ipURL, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		// Set original host for HTTP Host header
		req.Host = domain
		req.Header.Add("User-Agent", "Mozilla/5.0 (Android 12; Mobile; rv:144.0)")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		// Create HTTP client with custom TLS config for certificate verification
		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					Control:   protectControl,
				}).DialContext,
				TLSClientConfig: &tls.Config{
					ServerName: domain,  // Use domain for certificate verification
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
		if err = json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		if errMsg, ok := resp["error"].(map[string]interface{}); ok {
			return resp, fmt.Errorf("VK error: %v", errMsg)
		}
		return resp, nil
	}

	// Step 1: Get messages anonymous token (single call, no payload needed)
	data := "client_id=6287487&token_type=messages&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487"
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil { return "", "", "", err }
	token1 := resp["data"].(map[string]interface{})["access_token"].(string)

	// Step 2: Get call anonymous token
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", url.QueryEscape(link), token1)
	resp, err = doRequest(data, "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264")
	if err != nil { return "", "", "", err }
	token2 := resp["response"].(map[string]interface{})["token"].(string)

	// Step 3: Get session key via auth.anonymLogin
	data = fmt.Sprintf("session_data=%%7B%%22version%%22%%3A2%%2C%%22device_id%%22%%3A%%22%s%%22%%2C%%22client_version%%22%%3A1.1%%2C%%22client_type%%22%%3A%%22SDK_JS%%22%%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", uuid.New())
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil { return "", "", "", err }
	token3 := resp["session_key"].(string)

	// Step 4: Join conversation and get TURN credentials
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", url.QueryEscape(link), token2, token3)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil { return "", "", "", err }

	ts := resp["turn_server"].(map[string]interface{})
	urls := ts["urls"].([]interface{})
	address := strings.TrimPrefix(strings.TrimPrefix(strings.Split(urls[0].(string), "?")[0], "turn:"), "turns:")

	// Resolve TURN server address via cascading DNS (if it's a domain)
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		// Check if host is IP address
		if ip := net.ParseIP(host); ip == nil {
			// It's a domain name, resolve it
			resolvedIP, err := hostCache.Resolve(ctx, host)
			if err != nil {
				turnLog("[STREAM %d] [TURN DNS] Warning: failed to resolve TURN server %s: %v", streamID, host, err)
				// Don't fail, use original address
			} else {
				address = net.JoinHostPort(resolvedIP, port)
				turnLog("[STREAM %d] [TURN DNS] Resolved TURN server %s -> %s", streamID, host, resolvedIP)
			}
		}
	}

	return ts["username"].(string), ts["credential"].(string), address, nil
}
