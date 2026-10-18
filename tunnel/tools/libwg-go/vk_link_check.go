/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	tlsclient "github.com/kiper292/tls-client"
)

// Verdicts of wgTurnCheckVKLink, read by the settings screen. The negative
// codes reuse wgTurnProxyStart's numbering wherever the meaning is the same
// (-2 the call refuses anonymous joins, -3 a captcha stands in the way, -4 the
// call is gone or the link is wrong), so a link the check calls dead is one the
// start would refuse for the same reason.
const (
	linkCheckOK           int32 = 0
	linkCheckTemporary    int32 = -1 // VK unreachable, or it asked to come back later
	linkCheckRequiresAuth int32 = -2
	linkCheckCaptcha      int32 = -3 // VK's captcha gate: a verdict on this client, not on the call
	linkCheckUnavailable  int32 = -4
	linkCheckRefused      int32 = -5 // any other VK error
)

// vkLinkCheckTimeout bounds one check. The flow is five requests that take
// about a second on a healthy path; the bound is for the phone with no route to
// VK at all, where every request would otherwise sit out its own 20s client
// timeout on each of vkCallsAttempts.
const vkLinkCheckTimeout = 45 * time.Second

// joinHash reduces a VK call link to the join hash the API wants: whatever
// follows the last "join/", up to the first path, query or fragment separator.
// A bare hash comes back as is. wgTurnProxyStart and the link check share it so
// the check judges exactly the string the start would join with.
func joinHash(raw string) string {
	parts := strings.Split(strings.TrimSpace(raw), "join/")
	hash := parts[len(parts)-1]
	if idx := strings.IndexAny(hash, "/?#"); idx != -1 {
		hash = hash[:idx]
	}
	return hash
}

// newVKAPIClient builds the uTLS client every trip to VK goes through — the
// credential fetch and the link check alike — under the session identity: the
// mobile Android UA, the client hints and the ClientHello all come from the
// same Chrome major (vkSessionIdentity in profiles.go), so the transport cannot
// claim a different browser than the headers do, and the captcha phase cannot
// claim a different one than the phase that triggered it. Mobile end-to-end, so
// VK's detector never sees a desktop UA paired with accelerometer readings.
// Returns the Chrome major with the client so callers can name it in the log.
func newVKAPIClient() (tlsclient.HttpClient, Profile, int, error) {
	return newVKAPIClientDialing(getCustomDialContext)
}

// newVKAPIClientDialing is newVKAPIClient with every connection dialled by
// dial: tls-client takes a custom dial over its own dialer for all of them.
func newVKAPIClientDialing(dial func(ctx context.Context, network, addr string) (net.Conn, error)) (tlsclient.HttpClient, Profile, int, error) {
	profile, chromeMajor := vkSessionIdentity()
	client, err := tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		// ClientHello matching the session's Chrome major (vk_tls_clienthello.go)
		// + random extension order: the combination VK's bot detector accepts.
		tlsclient.WithClientProfile(vkChromeClientProfile(chromeMajor)),
		tlsclient.WithRandomTLSExtensionOrder(),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
		tlsclient.WithDialer(getCustomNetDialer()),
		tlsclient.WithDialContext(dial),
		// Additive trust: system CAs + bundled Минцифры chain, in case VK/OK
		// migrate onto Russian roots.
		tlsclient.WithTransportOptions(&tlsclient.TransportOptions{RootCAs: vkRootCAPool()}),
	)
	if err != nil {
		return nil, Profile{}, 0, fmt.Errorf("failed to create tlsclient: %w", err)
	}
	return client, profile, chromeMajor, nil
}

// linkCheckDial is the link check's dial: getCustomDialContext under
// withProtectIfService. Marked here as well as on the check's ctx, because
// tls-client dials an HTTP/2 connection with context.Background()
// (roundTripper.dialTLSHTTP2), and that ctx carries nothing of ours.
func linkCheckDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return getCustomDialContext(withProtectIfService(ctx), network, addr)
}

// checkVKLink asks VK whether a call still admits anonymous participants, by
// running the same captcha-free VK Calls flow a credential fetch starts with
// and classifying its outcome. Only that flow: the legacy chain behind it is
// where the captcha lives, and a check must never open a captcha dialog for a
// link the user is merely looking at. A verdict the flow cannot give without
// the captcha comes back as linkCheckCaptcha rather than a guess.
func checkVKLink(ctx context.Context, link string, client tlsclient.HttpClient, profile Profile) int32 {
	_, _, _, _, err := getVKCredsViaVKCalls(ctx, link, client, profile)
	switch {
	case err == nil:
		return linkCheckOK
	case isCallUnavailable(err):
		return linkCheckUnavailable
	case errors.Is(err, errCallRequiresAuth):
		return linkCheckRequiresAuth
	case errors.Is(err, errVKCallsCaptchaGate):
		return linkCheckCaptcha
	case isTransientVKCalls(err), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return linkCheckTemporary
	default:
		return linkCheckRefused
	}
}

// wgTurnCheckVKLink is the settings screen's "check this link": it takes a VK
// call link or a bare join hash and returns one of the linkCheck* verdicts.
// Independent of the proxy — its own client, no credential cache, no vkSemaphore
// slot — so it can run with the tunnel up or down. With a VpnService registered
// the sockets are protected and bound like every other VK request's, so with the
// tunnel up the trip leaves by the physical network; with none registered — as
// a rule, the tunnel down — they go out as they are (withProtectIfService). Blocking for up to vkLinkCheckTimeout. The link is
// never logged: the journal is exported, and a join link admits anyone.
//
//export wgTurnCheckVKLink
func wgTurnCheckVKLink(linkC *C.char) int32 {
	link := joinHash(C.GoString(linkC))
	if link == "" {
		return linkCheckUnavailable
	}
	client, profile, chromeMajor, err := newVKAPIClientDialing(linkCheckDial)
	if err != nil {
		turnErrorLog("[LinkCheck] cannot build the VK client: %v", err)
		return linkCheckTemporary
	}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(withProtectIfService(context.Background()), vkLinkCheckTimeout)
	defer cancel()
	// As things stood when the check began: a tunnel coming up or going down
	// meanwhile changes the answer for the dials after it.
	path := "VpnService registered at the start: protected, over the physical network"
	if !vpnServiceRegistered() {
		path = "no VpnService at the start: unprotected, over the default network"
	}
	started := time.Now()
	code := checkVKLink(ctx, link, client, profile)
	turnLog("[LinkCheck] verdict %d after %v (Chrome/%d identity, %s)", code, time.Since(started).Round(time.Millisecond), chromeMajor, path)
	return code
}
