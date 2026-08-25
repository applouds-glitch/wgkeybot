/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"testing"

	"golang.zx2c4.com/wireguard/device"
)

func TestWireGuardPeerKeys(t *testing.T) {
	const first = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	const second = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	settings := "private_key=ignored\n" +
		"public_key=" + first + "\n" +
		"public_key=not-a-key\n" +
		"public_key=" + second + "\n"

	keys := wireGuardPeerKeys(settings)
	if len(keys) != 2 {
		t.Fatalf("parsed %d peer keys, want 2", len(keys))
	}
	var wantFirst device.NoisePublicKey
	if err := wantFirst.FromHex(first); err != nil {
		t.Fatal(err)
	}
	var wantSecond device.NoisePublicKey
	if err := wantSecond.FromHex(second); err != nil {
		t.Fatal(err)
	}
	if keys[0] != wantFirst {
		t.Fatal("first key does not match")
	}
	if keys[1] != wantSecond {
		t.Fatal("second key does not match")
	}
}
