/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net/netip"
	"reflect"
	"testing"
)

// The encoder half, test-only: enough protobuf to build the fixtures the
// decoder is checked against, so the tests do not depend on binary blobs.
func pbEncodeVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func pbFieldVarint(field int, v uint64) []byte {
	return append(pbEncodeVarint(uint64(field)<<3|pbWireVarint), pbEncodeVarint(v)...)
}

func pbFieldBytes(field int, data []byte) []byte {
	out := pbEncodeVarint(uint64(field)<<3 | pbWireBytes)
	out = append(out, pbEncodeVarint(uint64(len(data)))...)
	return append(out, data...)
}

func encodeGeoDomain(typ geoDomainType, value string, attrs ...string) []byte {
	var msg []byte
	msg = append(msg, pbFieldVarint(1, uint64(typ))...)
	msg = append(msg, pbFieldBytes(2, []byte(value))...)
	for _, a := range attrs {
		attr := append(pbFieldBytes(1, []byte(a)), pbFieldVarint(2, 1)...)
		msg = append(msg, pbFieldBytes(3, attr)...)
	}
	return msg
}

func encodeGeoSite(code string, domains ...[]byte) []byte {
	msg := pbFieldBytes(1, []byte(code))
	for _, d := range domains {
		msg = append(msg, pbFieldBytes(2, d)...)
	}
	return pbFieldBytes(1, msg)
}

func encodeCIDR(prefix string) []byte {
	p := netip.MustParsePrefix(prefix)
	ip := p.Addr().AsSlice()
	return append(pbFieldBytes(1, ip), pbFieldVarint(2, uint64(p.Bits()))...)
}

func encodeGeoIP(code string, cidrs ...[]byte) []byte {
	msg := pbFieldBytes(1, []byte(code))
	for _, c := range cidrs {
		msg = append(msg, pbFieldBytes(2, c)...)
	}
	return pbFieldBytes(1, msg)
}

func TestParseGeoSiteKeepsWantedCategoriesOnly(t *testing.T) {
	var file []byte
	file = append(file, encodeGeoSite("WHITELIST",
		encodeGeoDomain(geoDomainSuffix, "yandex.ru"),
		encodeGeoDomain(geoDomainFull, "exactly.example"),
		encodeGeoDomain(geoDomainPlain, "gosuslugi"),
		encodeGeoDomain(geoDomainRegex, `^mail\d+\.ru$`, "cn"),
	)...)
	file = append(file, encodeGeoSite("TORRENT", encodeGeoDomain(geoDomainSuffix, "rutracker.org"))...)

	got, err := parseGeoSite(file, map[string]bool{"whitelist": true})
	if err != nil {
		t.Fatalf("parseGeoSite: %v", err)
	}
	want := map[string][]geoDomain{
		"whitelist": {
			{geoDomainSuffix, "yandex.ru"},
			{geoDomainFull, "exactly.example"},
			{geoDomainPlain, "gosuslugi"},
			{geoDomainRegex, `^mail\d+\.ru$`},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGeoSite = %#v, want %#v", got, want)
	}
}

func TestParseGeoIPMasksAndSkipsGarbage(t *testing.T) {
	bad := append(pbFieldBytes(1, []byte{1, 2, 3}), pbFieldVarint(2, 8)...)
	var file []byte
	file = append(file, encodeGeoIP("WHITELIST", encodeCIDR("5.45.192.0/18"), encodeCIDR("2a02:6b8::/32"))...)
	file = append(file, encodeGeoIP("PRIVATE", encodeCIDR("10.0.0.0/8"), bad)...)
	// A prefix that is not masked in the file must come out masked, or range
	// building would start from the wrong address.
	unmasked := append(pbFieldBytes(1, []byte{77, 88, 8, 8}), pbFieldVarint(2, 24)...)
	file = append(file, encodeGeoIP("DIRECT", unmasked)...)

	got, err := parseGeoIP(file, map[string]bool{"whitelist": true, "private": true, "direct": true})
	if err != nil {
		t.Fatalf("parseGeoIP: %v", err)
	}
	want := map[string][]netip.Prefix{
		"whitelist": {netip.MustParsePrefix("5.45.192.0/18"), netip.MustParsePrefix("2a02:6b8::/32")},
		"private":   {netip.MustParsePrefix("10.0.0.0/8")},
		"direct":    {netip.MustParsePrefix("77.88.8.0/24")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGeoIP = %v, want %v", got, want)
	}
}

func TestGeoDataRejectsTruncatedInput(t *testing.T) {
	file := encodeGeoSite("WHITELIST", encodeGeoDomain(geoDomainSuffix, "yandex.ru"))
	if _, err := parseGeoSite(file[:len(file)-3], map[string]bool{"whitelist": true}); err == nil {
		t.Fatal("a truncated file parsed without error")
	}
	if _, err := parseGeoIP([]byte{0x0a, 0xff, 0xff}, nil); err == nil {
		t.Fatal("an unterminated length parsed without error")
	}
}
