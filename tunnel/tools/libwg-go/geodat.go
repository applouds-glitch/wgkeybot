/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// Readers for the V2Ray/Xray geodata files (geosite.dat, geoip.dat) a Happ
// routing profile points at. The files are protocol buffers of a fixed,
// tiny schema (app/router/config.proto upstream):
//
//	GeoSiteList { repeated GeoSite entry = 1 }
//	GeoSite     { string country_code = 1; repeated Domain domain = 2 }
//	Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3 }
//	GeoIPList   { repeated GeoIP entry = 1 }
//	GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3 }
//	CIDR        { bytes ip = 1; uint32 prefix = 2 }
//
// A hand-rolled wire decoder covers that comfortably and keeps the protobuf
// runtime — and its generated code — out of a package that otherwise has no
// use for either.

// geoDomainType mirrors Domain.Type: how the value is compared with a host.
type geoDomainType uint8

const (
	geoDomainPlain  geoDomainType = 0 // substring
	geoDomainRegex  geoDomainType = 1 // Go/RE2 regular expression
	geoDomainSuffix geoDomainType = 2 // the domain itself and every subdomain
	geoDomainFull   geoDomainType = 3 // exact match
)

type geoDomain struct {
	typ   geoDomainType
	value string
}

var errGeoDataTruncated = errors.New("geodata: truncated or malformed protobuf")

const (
	pbWireVarint  = 0
	pbWireFixed64 = 1
	pbWireBytes   = 2
	pbWireFixed32 = 5
)

// pbWalk calls fn for every field of one embedded message. Varint fields arrive
// in num, length-delimited ones in data; the fixed-width kinds are skipped, as
// nothing in this schema uses them.
func pbWalk(b []byte, fn func(field int, num uint64, data []byte) error) error {
	i := 0
	for i < len(b) {
		key, n := pbVarint(b[i:])
		if n <= 0 {
			return errGeoDataTruncated
		}
		i += n
		field, wire := int(key>>3), int(key&7)
		switch wire {
		case pbWireVarint:
			v, n := pbVarint(b[i:])
			if n <= 0 {
				return errGeoDataTruncated
			}
			i += n
			if err := fn(field, v, nil); err != nil {
				return err
			}
		case pbWireBytes:
			l, n := pbVarint(b[i:])
			if n <= 0 {
				return errGeoDataTruncated
			}
			i += n
			if l > uint64(len(b)-i) {
				return errGeoDataTruncated
			}
			if err := fn(field, 0, b[i:i+int(l)]); err != nil {
				return err
			}
			i += int(l)
		case pbWireFixed64:
			if len(b)-i < 8 {
				return errGeoDataTruncated
			}
			i += 8
		case pbWireFixed32:
			if len(b)-i < 4 {
				return errGeoDataTruncated
			}
			i += 4
		default:
			return fmt.Errorf("geodata: unsupported wire type %d", wire)
		}
	}
	return nil
}

// pbVarint decodes one base-128 varint. n is 0 when the input ends mid-value
// and -1 when the value is longer than a uint64 can hold.
func pbVarint(b []byte) (v uint64, n int) {
	var shift uint
	for i, c := range b {
		if i == 10 {
			return 0, -1
		}
		v |= uint64(c&0x7f) << shift
		if c < 0x80 {
			return v, i + 1
		}
		shift += 7
	}
	return 0, 0
}

// parseGeoSite decodes a GeoSiteList, keeping only the categories in wanted
// (compared case-insensitively; the files spell codes in upper case, the
// profiles in lower). Attributes are parsed past and ignored: the profiles this
// supports select whole categories.
func parseGeoSite(b []byte, wanted map[string]bool) (map[string][]geoDomain, error) {
	out := make(map[string][]geoDomain, len(wanted))
	err := pbWalk(b, func(field int, _ uint64, entry []byte) error {
		if field != 1 || entry == nil {
			return nil
		}
		var code string
		var domains []geoDomain
		err := pbWalk(entry, func(field int, _ uint64, data []byte) error {
			switch field {
			case 1:
				code = strings.ToLower(string(data))
			case 2:
				if data == nil {
					return nil
				}
				d := geoDomain{}
				if err := pbWalk(data, func(field int, num uint64, data []byte) error {
					switch field {
					case 1:
						d.typ = geoDomainType(num)
					case 2:
						d.value = string(data)
					}
					return nil
				}); err != nil {
					return err
				}
				domains = append(domains, d)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if wanted[code] {
			out[code] = append(out[code], domains...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// parseGeoIP decodes a GeoIPList into prefixes per category, again for the
// wanted categories only. An entry's reverse_match flag is honoured by the
// caller through the "!" selector rather than here: the profile decides the
// sense, the file only supplies the ranges.
func parseGeoIP(b []byte, wanted map[string]bool) (map[string][]netip.Prefix, error) {
	out := make(map[string][]netip.Prefix, len(wanted))
	err := pbWalk(b, func(field int, _ uint64, entry []byte) error {
		if field != 1 || entry == nil {
			return nil
		}
		var code string
		var prefixes []netip.Prefix
		err := pbWalk(entry, func(field int, _ uint64, data []byte) error {
			switch field {
			case 1:
				code = strings.ToLower(string(data))
			case 2:
				if data == nil {
					return nil
				}
				var ip []byte
				var bits uint64
				if err := pbWalk(data, func(field int, num uint64, data []byte) error {
					switch field {
					case 1:
						ip = data
					case 2:
						bits = num
					}
					return nil
				}); err != nil {
					return err
				}
				addr, ok := netip.AddrFromSlice(ip)
				if !ok {
					// Neither 4 nor 16 bytes: not an address. Skip the entry rather
					// than fail the file over one record.
					return nil
				}
				if bits > uint64(addr.BitLen()) {
					return nil
				}
				prefixes = append(prefixes, netip.PrefixFrom(addr, int(bits)).Masked())
			}
			return nil
		})
		if err != nil {
			return err
		}
		if wanted[code] {
			out[code] = append(out[code], prefixes...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// geoDataMaxSize bounds what is read into memory. The real files are a few
// hundred kilobytes; a limit only guards against a download that was not the
// file at all.
const geoDataMaxSize = 64 << 20

func readGeoDataFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > geoDataMaxSize {
		return nil, fmt.Errorf("geodata: %s is %d bytes, larger than the %d byte limit", path, st.Size(), geoDataMaxSize)
	}
	return os.ReadFile(path)
}
