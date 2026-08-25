/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"strings"

	"golang.zx2c4.com/wireguard/device"
)

// wireGuardPeerKeys extracts the configured peers from the userspace IPC
// settings handed to wgTurnOn. Keeping the keys lets the shared TURN grid call
// Peer.SendKeepalive directly: unlike Device.SendKeepalivesToPeersWithCurrentKeypair,
// that method also stages a keepalive when no keypair exists yet, which starts
// the very first WireGuard handshake.
func wireGuardPeerKeys(settings string) []device.NoisePublicKey {
	var keys []device.NoisePublicKey
	for _, line := range strings.Split(settings, "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "public_key=")
		if !ok {
			continue
		}
		var key device.NoisePublicKey
		if key.FromHex(strings.TrimSpace(value)) == nil {
			keys = append(keys, key)
		}
	}
	return keys
}

// newWireGuardKeepaliveSendFunc returns the callback coalesced with the TURN
// keepalive grid. Peer.SendKeepalive handles both phases safely: before the
// first keypair it initiates a handshake, and afterwards it sends the encrypted
// empty transport packet and performs normal key refresh when necessary.
func newWireGuardKeepaliveSendFunc(dev *device.Device, settings string) func() {
	keys := wireGuardPeerKeys(settings)
	return func() {
		for _, key := range keys {
			if peer := dev.LookupPeer(key); peer != nil {
				peer.SendKeepalive()
			}
		}
	}
}
