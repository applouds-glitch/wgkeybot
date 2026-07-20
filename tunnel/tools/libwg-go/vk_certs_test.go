/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func parseEmbeddedCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	data, err := vkExtraRootsFS.ReadFile("certs/" + name)
	if err != nil {
		t.Fatalf("read embedded %s: %v", name, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s: no PEM block", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: parse: %v", name, err)
	}
	return cert
}

func TestVKExtraRootsChain(t *testing.T) {
	root := parseEmbeddedCert(t, "russian_trusted_root_ca.pem")
	if root.Subject.CommonName != "Russian Trusted Root CA" {
		t.Errorf("root CN = %q, want Russian Trusted Root CA", root.Subject.CommonName)
	}
	if !root.IsCA {
		t.Error("root is not a CA certificate")
	}
	for _, name := range []string{"russian_trusted_sub_ca.pem", "russian_trusted_sub_ca_2024.pem"} {
		sub := parseEmbeddedCert(t, name)
		if err := sub.CheckSignatureFrom(root); err != nil {
			t.Errorf("%s not signed by root: %v", name, err)
		}
	}

	// VK's self-signed CA must parse and be usable as a trust anchor.
	vk := parseEmbeddedCert(t, "vk_self_signed.cer")
	if !vk.IsCA {
		t.Error("vk_self_signed is not a CA certificate")
	}
	if vk.Subject.Organization == nil || vk.Subject.Organization[0] != "VK CA" {
		t.Errorf("vk_self_signed O = %v, want [VK CA]", vk.Subject.Organization)
	}
}

func TestVKExtraRootsAllEmbeddedParse(t *testing.T) {
	entries, err := vkExtraRootsFS.ReadDir("certs")
	if err != nil {
		t.Fatalf("ReadDir certs: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("embedded certs = %d, want 4 (3 Минцифры + vk_self_signed)", len(entries))
	}
	for _, e := range entries {
		parseEmbeddedCert(t, e.Name()) // fails the test if any embedded file is not a cert
	}
}

func TestVKRootCAPoolBuilds(t *testing.T) {
	if pool := vkRootCAPool(); pool == nil {
		t.Fatal("vkRootCAPool returned nil")
	}
	if vkRootCAPool() != vkRootCAPoolState.pool {
		t.Error("vkRootCAPool not memoized")
	}
}
