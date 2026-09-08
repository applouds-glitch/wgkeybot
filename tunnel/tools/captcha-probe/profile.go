package main

import (
	fhttp "github.com/bogdanfinn/fhttp"
)

type Profile struct {
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	Platform        string
	AcceptLanguage  string
}

// Desktop Chrome/151 UA paired with the Chrome 151 TLS spec — the exact
// combination of the reference browser run that VK accepted (the PoW
// telemetry still claims Chrome/146, which the bisect test proved accepted).
const captchaDesktopUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"

var captchaHeaderOrder = []string{
	"host", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
	"user-agent", "accept", "content-type", "origin",
	"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
	"accept-encoding", "accept-language", "priority", "content-length",
}

var captchaPHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}

func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", profile.AcceptLanguage)
	req.Header.Set("DNT", "1")
}

// Captcha-phase profile: desktop Chrome/151 client hints matching the
// custom Chrome 151 TLS profile (the mobile Android WebView hints are sent
// only on the trigger requests, like the real app does). Accept-Language
// en-GB mirrors the reference browser and the device JSON claim, so the
// remixlang cookie VK plants stays consistent with the captcha page.
func applyCaptchaBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	applyBrowserProfileFhttp(req, profile)
	req.Header.Set("User-Agent", captchaDesktopUserAgent)
	req.Header.Set("sec-ch-ua", `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"macOS"`)
	req.Header.Set("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Del("DNT")
}
