/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"crypto/x509"
	"embed"
	"sync"
)

// Additive trust anchors for the VK/OK credential path.
// Mirrors what the VK app does in its own
// KeyStore: it ADDS its trust anchors on top of the system CAs rather than
// replacing them. We bundle the same set VK carries — the Минцифры ("Russian
// Trusted") chain plus VK's self-signed CA — so TLS to api.vk.me / api.vk.com /
// login.vk.com / id.vk.com / calls.okcdn.ru keeps working if VK/OK migrate off
// the public CAs (GTS/HARICA) they use today onto those roots; global
// Android/Windows devices don't carry them in their system store.
//
// Минцифры PEMs come from the official gu-st.ru (Госуслуги) distribution; the
// root's SHA-256 fingerprint matches Минцифры's published value
// (D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31).
// vk_self_signed.cer is VK's self-signed "VK CA" root (RSA/sha256), taken from
// the decompiled app; it is PEM despite the .cer extension.
//
// Certificate pinning is intentionally NOT used. VK itself only applies pins in
// its Push SDK (com.vk.push.core), soft/report-only, never on these API/calls
// endpoints, and none of its pins match the live GTS/HARICA chains — enforcing
// would be subtractive, not additive, and would reject every request today.
//
//go:embed certs/russian_trusted_root_ca.pem certs/russian_trusted_sub_ca.pem certs/russian_trusted_sub_ca_2024.pem certs/vk_self_signed.cer
var vkExtraRootsFS embed.FS

var vkRootCAPoolState struct {
	sync.Once
	pool *x509.CertPool
}

// vkRootCAPool returns the system pool (public CAs: GTS, HARICA, …) plus the
// bundled Минцифры chain. Seeding from SystemCertPool is what makes this
// additive: once tls.Config.RootCAs is set, Go verifies against ONLY that pool
// and the platform verifier is bypassed, so without the seed every public CA
// would be lost.
func vkRootCAPool() *x509.CertPool {
	vkRootCAPoolState.Do(func() {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		entries, _ := vkExtraRootsFS.ReadDir("certs")
		for _, e := range entries {
			pem, err := vkExtraRootsFS.ReadFile("certs/" + e.Name())
			if err != nil {
				turnLog("[VK Certs] failed to read embedded %s: %v", e.Name(), err)
				continue
			}
			if !pool.AppendCertsFromPEM(pem) {
				turnLog("[VK Certs] no certificates parsed from embedded %s", e.Name())
			}
		}
		vkRootCAPoolState.pool = pool
	})
	return vkRootCAPoolState.pool
}
