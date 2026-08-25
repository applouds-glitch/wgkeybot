/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

// The ClientHello every VK session presents, picked to match the Chrome major
// the same session claims in its User-Agent — see vkChromeClientProfile.
//
// Custom Chrome 151 ClientHello, tuned against the reference capture
// (tls.peet.ws from real Chrome 151, the fingerprint VK accepted):
//   - PQ signature schemes 0x0904/0x0905/0x0906 at the front of sig algs
//   - no 0xca34 "trust anchors" extension (Chrome dropped it after 146)
//   - UtlsPreSharedKeyExtension so the session cache exists and later
//     connections resume with a pre_shared_key extension like real Chrome
//
// The rest is copied verbatim from the fork's Chrome_146 (wire-verified:
// ciphers and all other extensions already match Chrome 151).
//
// Paired with tlsclient.WithRandomTLSExtensionOrder(): real Chrome 151
// shuffles its extension order per connection, so a fixed order is a bot
// signal; the shuffle keeps JA4 stable (the JA4 hash is order-insensitive
// over extensions) while matching the browser's behavior.
//
// Verified live: this profile + random extension order + the Chrome 151
// header/pseudo-header order turned VK's captchaNotRobot.check verdict from
// BOT into OK, twice in a row.

import (
	tls "github.com/bogdanfinn/utls"
	"github.com/kiper292/tls-client/profiles"
)

const (
	sigP256MLDSA65 = tls.SignatureScheme(0x0904)
	sigMLDSA65     = tls.SignatureScheme(0x0905)
	sigPSSMLDSA65  = tls.SignatureScheme(0x0906)
)

func chrome151Spec() tls.ClientHelloSpec {
	return tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			tls.CompressionNone,
		},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519MLKEM768},
				{Group: tls.X25519},
			}},
			&tls.SNIExtension{},
			&tls.ApplicationSettingsExtensionNew{
				SupportedProtocols: []string{"h2"},
			},
			&tls.RenegotiationInfoExtension{
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.GREASE_PLACEHOLDER,
				tls.X25519MLKEM768,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
			&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
				tls.CertCompressionBrotli,
			}},
			&tls.SessionTicketExtension{},
			&tls.StatusRequestExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				sigP256MLDSA65,
				sigMLDSA65,
				sigPSSMLDSA65,
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			}},
			&tls.SCTExtension{},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				tls.PointFormatUncompressed,
			}},
			tls.BoringGREASEECH(),
			&tls.ALPNExtension{AlpnProtocols: []string{
				"h2",
				"http/1.1",
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
				tls.PskModeDHE,
			}},
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPreSharedKeyExtension{},
		},
	}
}

func vkChrome151ClientProfile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		tls.ClientHelloID{
			Client:  "Chrome",
			Version: "151",
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return chrome151Spec(), nil
			},
		},
		profiles.Chrome_146.GetSettings(),
		profiles.Chrome_146.GetSettingsOrder(),
		// The verified Chrome 151 pseudo-header order as the client-wide
		// default, so a request that forgets to set PHeaderOrderKey still goes
		// out looking like the browser the ClientHello claims to be.
		vkPHeaderOrder,
		profiles.Chrome_146.GetConnectionFlow(),
		profiles.Chrome_146.GetPriorities(),
		profiles.Chrome_146.GetHeaderPriority(),
		profiles.Chrome_146.GetStreamID(),
		false, nil, nil, 0, nil, false,
	)
}

// vkChromeClientProfile returns the ClientHello for a session claiming Chrome
// major.
//
// The User-Agent this app presents is not ours to choose: the captcha persona
// derives it from the WebView actually installed on the device, because the
// visible WebView fallback runs on that same WebView and reports its real
// navigator.userAgentData brands — a persona claiming another major would
// contradict the browser solving the captcha. So the ClientHello is what has to
// follow the persona, not the other way around. Pinning one spec meant every
// device whose WebView was not 151 sent a JA3 saying 151 under a UA saying
// something else, which is a free and very cheap signal for a bot detector.
//
// Only majors the fork actually ships a spec for can be matched, so a major
// lands on the closest spec at or below it. The PSK variants are preferred
// where they exist: real Chrome resumes with a pre_shared_key extension, which
// is why the 151 spec carries UtlsPreSharedKeyExtension too.
//
// Chrome_133_PSK is skipped on purpose despite sitting in the range: it
// advertises h3 first in its ALPN, and a TCP ClientHello offering HTTP/3 is
// something no real Chrome sends — it would be a worse signal than the version
// gap it closes. 133..143 take the 131 spec instead.
func vkChromeClientProfile(major int) profiles.ClientProfile {
	switch {
	case major >= 147:
		return vkChrome151ClientProfile()
	case major >= 146:
		return profiles.Chrome_146_PSK
	case major >= 144:
		return profiles.Chrome_144_PSK
	case major >= 131:
		return profiles.Chrome_131_PSK
	default:
		return profiles.Chrome_130_PSK
	}
}
