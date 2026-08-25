/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	tls "github.com/bogdanfinn/utls"
	"github.com/kiper292/tls-client/profiles"
)

// The fingerprints VK sees. They are pinned, not computed-and-trusted: the
// ClientHello is assembled by the utls fork, so a fork upgrade can change what
// actually goes on the wire while every line of vk_tls_clienthello.go still
// reads the same. That drift is silent — the only symptom is a BOT verdict
// weeks later — and this test is what makes it loud.
//
// Chrome 151 is our own spec; the others are the fork's, pinned because
// vkChromeClientProfile hands them to devices whose WebView reports those
// majors.
//
// The JA3 here is the canonical-order one: production adds
// WithRandomTLSExtensionOrder, so the JA3 on the wire is deliberately shuffled
// per connection (real Chrome shuffles too). JA4 is order-insensitive over
// extensions and holds on the wire as well.
//
// To re-pin after an intentional change, run with -v: the failure prints the
// computed values.
func TestVKClientHelloFingerprintsArePinned(t *testing.T) {
	cases := []struct {
		major int
		ja3   string
		ja4   string
	}{
		{major: 151, ja3: "f984bd5bc7358922cde86ed4471a2e89", ja4: "t13d1516h2_8daaf6152771_806a8c22fdea"},
		{major: 146, ja3: "5d510aa7220d1a7bc1256493e4b88909", ja4: "t13d1517h2_8daaf6152771_dcad5a053991"},
		{major: 144, ja3: "eeee4c6725bf89c31f225b3dab4cef37", ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd"},
		// 133..143 route to the 131 spec (see vkChromeClientProfile), so this
		// case pins that routing as much as the fingerprint.
		{major: 133, ja3: "a19ab9f02aacf42deddc1f2acb3d3f63", ja4: "t13d1516h2_8daaf6152771_02713d6af862"},
		{major: 131, ja3: "a19ab9f02aacf42deddc1f2acb3d3f63", ja4: "t13d1516h2_8daaf6152771_02713d6af862"},
		{major: 130, ja3: "06565f52c2778f4b53f33474396f34a7", ja4: "t13d1516h2_8daaf6152771_02713d6af862"},
	}

	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.major), func(t *testing.T) {
			hello := buildPinnedClientHello(t, vkChromeClientProfile(tc.major))
			ja3, ja4 := ja3Of(t, hello), ja4Of(t, hello)

			if tc.ja3 == "" || tc.ja4 == "" {
				t.Fatalf("no pinned fingerprint for Chrome %d\n  JA3: %s\n  JA4: %s", tc.major, ja3, ja4)
			}
			if ja3 != tc.ja3 {
				t.Errorf("JA3 changed for Chrome %d:\n  got:  %s\n  want: %s", tc.major, ja3, tc.ja3)
			}
			if ja4 != tc.ja4 {
				t.Errorf("JA4 changed for Chrome %d:\n  got:  %s\n  want: %s", tc.major, ja4, tc.ja4)
			}
		})
	}
}

// TestVKSessionIdentityMajorMatchesClientHello pins the invariant the whole
// identity rests on: the Chrome major in the User-Agent is the major whose
// ClientHello we send. A UA claiming one version over a JA3 claiming another is
// the contradiction vkChromeClientProfile exists to prevent.
func TestVKSessionIdentityMajorMatchesClientHello(t *testing.T) {
	// vkSessionIdentity's persona branch needs the Android layer, so the
	// reachable case here is the fallback — which is exactly the one that used
	// to hardcode a UA independent of the spec.
	profile, major := vkSessionIdentity()

	if got := chromeMajorFromUA(profile.UserAgent); got != major {
		t.Errorf("UA claims Chrome %d but the session reports major %d (UA: %q)", got, major, profile.UserAgent)
	}
	if !strings.Contains(profile.SecChUa, strconv.Itoa(major)) {
		t.Errorf("sec-ch-ua %q does not carry the session's major %d", profile.SecChUa, major)
	}

	// The fallback major must be one the fork ships a spec for, or the fallback
	// identity contradicts itself the moment it is used. Profile versions carry
	// a suffix ("146_PSK"), so compare the major they start with.
	helloVersion := vkChromeClientProfile(major).GetClientHelloId().Version
	if helloMajor := leadingInt(helloVersion); helloMajor != major {
		t.Errorf("Chrome %d falls back to the %s ClientHello; the fallback major must have its own spec",
			major, helloVersion)
	}
}

// leadingInt reads the digits a string starts with ("146_PSK" → 146).
func leadingInt(s string) int {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return n
}

func TestChromeMajorFromUA(t *testing.T) {
	cases := map[string]int{
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36": 151,
		"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 Mobile Safari":     99,
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36":                  0,
		"": 0,
	}
	for ua, want := range cases {
		if got := chromeMajorFromUA(ua); got != want {
			t.Errorf("chromeMajorFromUA(%.60q) = %d, want %d", ua, got, want)
		}
	}
}

// buildPinnedClientHello assembles the ClientHello the profile would send, in
// the spec's own extension order (production shuffles it; see the note on the
// pinned JA3 above). Nothing is written to the network — BuildHandshakeState
// only fills the handshake state in memory.
func buildPinnedClientHello(t *testing.T, profile profiles.ClientProfile) []byte {
	t.Helper()

	// Same TLS config the tls-client roundtripper builds, so the hello under
	// test is the hello production sends: OmitEmptyPsk keeps the PSK extension
	// off a fresh connection (real Chrome only sends it when resuming), and
	// without the session cache BuildHandshakeState refuses to build at all.
	uconn := tls.UClient(
		nil,
		&tls.Config{
			ServerName:         "api.vk.ru",
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
			OmitEmptyPsk:       true,
		},
		profile.GetClientHelloId(),
		false, // deterministic extension order, so the JA3 is comparable
		false,
		false,
	)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("building ClientHello: %v", err)
	}
	raw := uconn.HandshakeState.Hello.Raw
	if len(raw) == 0 {
		t.Fatal("ClientHello came out empty")
	}
	return raw
}

// parsedClientHello is the subset of a ClientHello the JA3/JA4 hashes read.
type parsedClientHello struct {
	legacyVersion  uint16
	cipherSuites   []uint16 // GREASE removed
	extensions     []uint16 // GREASE removed, in wire order
	curves         []uint16 // GREASE removed
	pointFormats   []uint8
	sigAlgs        []uint16 // GREASE removed, in wire order
	alpn           []string
	supportedVers  []uint16 // GREASE removed
	hasServerName  bool
	extensionCount int // GREASE excluded
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// parseClientHello walks the handshake message. It is deliberately a plain
// hand-rolled reader: the point of the test is to see the bytes utls produced,
// not to trust the same library's view of them.
func parseClientHello(t *testing.T, raw []byte) parsedClientHello {
	t.Helper()

	var out parsedClientHello
	// Handshake header: type(1) + length(3).
	if len(raw) < 4 || raw[0] != 1 {
		t.Fatalf("not a ClientHello handshake message (len %d)", len(raw))
	}
	b := raw[4:]

	read := func(n int) []byte {
		if len(b) < n {
			t.Fatalf("ClientHello truncated: wanted %d bytes, %d left", n, len(b))
		}
		v := b[:n]
		b = b[n:]
		return v
	}
	readU8Block := func() []byte { return read(int(read(1)[0])) }
	readU16Block := func() []byte { return read(int(binary.BigEndian.Uint16(read(2)))) }
	u16s := func(p []byte) []uint16 {
		out := make([]uint16, 0, len(p)/2)
		for i := 0; i+1 < len(p); i += 2 {
			out = append(out, binary.BigEndian.Uint16(p[i:]))
		}
		return out
	}
	dropGREASE := func(in []uint16) []uint16 {
		out := make([]uint16, 0, len(in))
		for _, v := range in {
			if !isGREASE(v) {
				out = append(out, v)
			}
		}
		return out
	}

	out.legacyVersion = binary.BigEndian.Uint16(read(2))
	read(32)      // random
	readU8Block() // session id
	out.cipherSuites = dropGREASE(u16s(readU16Block()))
	readU8Block() // compression methods

	extensions := readU16Block()
	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		if len(extensions) < 4+extLen {
			t.Fatalf("extension 0x%04x truncated", extType)
		}
		body := extensions[4 : 4+extLen]
		extensions = extensions[4+extLen:]

		if isGREASE(extType) {
			continue
		}
		out.extensions = append(out.extensions, extType)
		out.extensionCount++

		switch extType {
		case 0x0000: // server_name
			out.hasServerName = true
		case 0x000a: // supported_groups
			if len(body) >= 2 {
				out.curves = dropGREASE(u16s(body[2:]))
			}
		case 0x000b: // ec_point_formats
			if len(body) >= 1 {
				out.pointFormats = append(out.pointFormats, body[1:]...)
			}
		case 0x000d: // signature_algorithms
			if len(body) >= 2 {
				out.sigAlgs = dropGREASE(u16s(body[2:]))
			}
		case 0x0010: // ALPN
			if len(body) >= 2 {
				for p := body[2:]; len(p) >= 1; {
					n := int(p[0])
					if len(p) < 1+n {
						break
					}
					out.alpn = append(out.alpn, string(p[1:1+n]))
					p = p[1+n:]
				}
			}
		case 0x002b: // supported_versions
			if len(body) >= 1 {
				out.supportedVers = dropGREASE(u16s(body[1:]))
			}
		}
	}
	return out
}

// ja3Of computes the JA3 hash: MD5 over
// version,ciphers,extensions,curves,point-formats, GREASE excluded.
func ja3Of(t *testing.T, raw []byte) string {
	t.Helper()
	h := parseClientHello(t, raw)

	join := func(vals []uint16) string {
		parts := make([]string, 0, len(vals))
		for _, v := range vals {
			parts = append(parts, strconv.Itoa(int(v)))
		}
		return strings.Join(parts, "-")
	}
	points := make([]string, 0, len(h.pointFormats))
	for _, p := range h.pointFormats {
		points = append(points, strconv.Itoa(int(p)))
	}

	ja3 := strings.Join([]string{
		strconv.Itoa(int(h.legacyVersion)),
		join(h.cipherSuites),
		join(h.extensions),
		join(h.curves),
		strings.Join(points, "-"),
	}, ",")
	sum := md5.Sum([]byte(ja3))
	return hex.EncodeToString(sum[:])
}

// ja4Of computes the JA4 fingerprint (FoxIO JA4_a_b_c). Unlike JA3 it sorts
// ciphers and extensions, so it survives the per-connection extension shuffle
// production turns on.
func ja4Of(t *testing.T, raw []byte) string {
	t.Helper()
	h := parseClientHello(t, raw)

	version := "12"
	highest := h.legacyVersion
	for _, v := range h.supportedVers {
		if v > highest {
			highest = v
		}
	}
	switch highest {
	case tls.VersionTLS13:
		version = "13"
	case tls.VersionTLS12:
		version = "12"
	case tls.VersionTLS11:
		version = "11"
	case tls.VersionTLS10:
		version = "10"
	}

	sni := "i"
	if h.hasServerName {
		sni = "d"
	}

	alpn := "00"
	if len(h.alpn) > 0 && len(h.alpn[0]) > 0 {
		first := h.alpn[0]
		alpn = string(first[0]) + string(first[len(first)-1])
	}

	twoDigits := func(n int) string {
		if n > 99 {
			n = 99
		}
		return fmt.Sprintf("%02d", n)
	}

	hexList := func(vals []uint16) []string {
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			out = append(out, fmt.Sprintf("%04x", v))
		}
		return out
	}
	truncatedSHA := func(s string) string {
		if s == "" {
			return "000000000000"
		}
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])[:12]
	}

	ciphers := hexList(h.cipherSuites)
	sort.Strings(ciphers)

	// SNI and ALPN are excluded from the JA4_c list but still counted in JA4_a.
	filtered := make([]uint16, 0, len(h.extensions))
	for _, ext := range h.extensions {
		if ext == 0x0000 || ext == 0x0010 {
			continue
		}
		filtered = append(filtered, ext)
	}
	extensions := hexList(filtered)
	sort.Strings(extensions)

	extPart := strings.Join(extensions, ",")
	if len(h.sigAlgs) > 0 {
		extPart += "_" + strings.Join(hexList(h.sigAlgs), ",")
	}

	return fmt.Sprintf("t%s%s%s%s%s_%s_%s",
		version, sni,
		twoDigits(len(h.cipherSuites)),
		twoDigits(h.extensionCount),
		alpn,
		truncatedSHA(strings.Join(ciphers, ",")),
		truncatedSHA(extPart),
	)
}
