/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// fetchCredsWithLifetime fetches TURN credentials for a specific group and returns the remaining TTL.
// groupID selects the correct credential cache slot (groupID * streamsPerCred).
// Uses globalGetCreds (initialised by wgTurnProxyStart).
func fetchCredsWithLifetime(ctx context.Context, link string, groupID int) (user, pass, addr string, lifetimeSecs int, err error) {
	streamID := groupID * streamsPerCred
	u, p, a, e := globalGetCreds(ctx, link, streamID)
	if e != nil {
		err = fmt.Errorf("fetchCredsWithLifetime: %w", e)
		return
	}

	host, _, splitErr := net.SplitHostPort(a)
	if splitErr != nil || host == "" {
		err = fmt.Errorf("fetchCredsWithLifetime: invalid addr %q", a)
		return
	}

	user = u
	pass = p
	addr = a

	// Read the real remaining TTL from the cache slot that getCredsCached just populated.
	// ExpiresAt reflects the actual VK API lifetime (capped at defaultCycleSecs).
	cache := getStreamCache(streamID)
	cache.mutex.RLock()
	remaining := time.Until(cache.creds.ExpiresAt)
	cache.mutex.RUnlock()

	if remaining > cacheSafetyMargin {
		secs := int(remaining.Seconds())
		if secs > defaultCycleSecs {
			secs = defaultCycleSecs
		}
		lifetimeSecs = secs
	} else {
		lifetimeSecs = int((credentialLifetime - cacheSafetyMargin).Seconds())
	}
	return
}
