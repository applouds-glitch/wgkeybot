package main

// Custom Chrome 151 ClientHello, tuned against the reference capture
// (tls.peet.ws from real Chrome 151, the fingerprint VK accepted):
//   - PQ signature schemes 0x0904/0x0905/0x0906 at the front of sig algs
//   - no 0xca34 "trust anchors" extension (Chrome dropped it after 146)
//   - UtlsPreSharedKeyExtension so the session cache exists and later
//     connections resume with a pre_shared_key extension like real Chrome
//
// The rest is copied verbatim from the fork's Chrome_146 (wire-verified:
// ciphers and all other extensions already match Chrome 151).

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

func chrome151ClientProfile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		tls.ClientHelloID{
			Client: "Chrome",
			Version: "151",
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return chrome151Spec(), nil
			},
		},
		profiles.Chrome_146.GetSettings(),
		profiles.Chrome_146.GetSettingsOrder(),
		profiles.Chrome_146.GetPseudoHeaderOrder(),
		profiles.Chrome_146.GetConnectionFlow(),
		profiles.Chrome_146.GetPriorities(),
		profiles.Chrome_146.GetHeaderPriority(),
		profiles.Chrome_146.GetStreamID(),
		false, nil, nil, 0, nil, false,
	)
}
