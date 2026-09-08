// captcha-probe reproduces the VK captcha bootstrap fetch of the wgkeybot
// native layer (vk.go / vk_captcha.go) outside the app, to diagnose why
// "powInput not found in captcha HTML" happens.
//
// Two stages:
//
//  1. Trigger a real captcha (get_anonym_token + calls.getAnonymousToken with
//     the production VK app credentials) and print the full redirect_uri:
//
//	./captcha-probe -link https://vk.ru/call/join/xxxx -out /tmp
//
//  2. Fetch the redirect_uri HTML exactly like production fetchCaptchaBootstrap,
//     dump it to a file, and run the production parser on it:
//
//	./captcha-probe -uri 'https://...redirect_uri...' -out /tmp
//
// Build for the device (same egress IP as the app):
//
//	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o captcha-probe .
//	adb push captcha-probe /data/local/tmp/ && adb shell /data/local/tmp/captcha-probe ...
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	mathrand "math/rand"
	neturl "net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
)

type vkCredentials struct {
	ClientID     string
	ClientSecret string
}

var credsList = []vkCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"}, // VK_WEB_APP_ID
	{ClientID: "8202606", ClientSecret: "lMRsTiMCyPnp5vfoldmn"}, // VK app rotation fallback
}

// The mobile profile from fetchVkCreds in vk.go.
var probeProfile = Profile{
	UserAgent:       "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36",
	SecChUa:         `"Not(A:Brand";v="99", "Google Chrome";v="146", "Chromium";v="146"`,
	SecChUaMobile:   "?1",
	SecChUaPlatform: `"Android"`,
	Platform:        "Linux armv8l",
	AcceptLanguage:  "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
}

var probeNames = []string{"Иван", "Мария", "Алексей", "Елена", "Дмитрий", "Анна"}

func main() {
	linkFlag := flag.String("link", "", "VK call join link (full URL or hash)")
	uriFlag := flag.String("uri", "", "redirect_uri from a captcha error (skip trigger)")
	outFlag := flag.String("out", ".", "output directory for dumps")
	credsFlag := flag.Int("creds", 0, "credential slot index (0 or 1)")
	noCheckFlag := flag.Bool("no-check", false, "skip the live captchaNotRobot.check dry-run")
	tlsCheckFlag := flag.Bool("tlscheck", false, "dump this client's TLS/HTTP2 fingerprint via tls.peet.ws")
	flag.Parse()

	if *uriFlag == "" && *linkFlag == "" && !*tlsCheckFlag {
		flag.Usage()
		os.Exit(2)
	}

	if err := os.MkdirAll(*outFlag, 0o755); err != nil {
		fatalf("create output dir: %v", err)
	}

	client, err := tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(chrome151ClientProfile()),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
		tlsclient.WithTransportOptions(&tlsclient.TransportOptions{RootCAs: vkRootCAPool()}),
		tlsclient.WithRandomTLSExtensionOrder(),
	)
	if err != nil {
		fatalf("create tlsclient: %v", err)
	}
	defer client.CloseIdleConnections()

	if *tlsCheckFlag {
		resp, err := client.Get("https://tls.peet.ws/api/all")
		if err != nil {
			fatalf("tlscheck: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("%s\n", body)
		return
	}

	fmt.Printf("[profile] UA=%s\n", probeProfile.UserAgent)

	redirectURI := *uriFlag
	if redirectURI == "" {
		if *credsFlag < 0 || *credsFlag >= len(credsList) {
			fatalf("bad -creds index: %d", *credsFlag)
		}
		redirectURI = triggerCaptcha(client, *linkFlag, credsList[*credsFlag], *outFlag)
		fmt.Printf("\n[redirect_uri] %s\n", redirectURI)
	}

	bootstrap := probeBootstrap(client, redirectURI, *outFlag)
	if bootstrap != nil && !*noCheckFlag {
		runLiveCheck(client, redirectURI, bootstrap, *outFlag)
	}
}

// doRequest mirrors the closure in getTokenChain (vk.go) — same method,
// headers, Host override and JSON handling.
func doRequest(ctx context.Context, client tlsclient.HttpClient, data, url string) (map[string]interface{}, error) {
	parsedURL, err := neturl.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("parse request URL: %w", err)
	}
	domain := parsedURL.Hostname()

	req, err := fhttp.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return nil, err
	}

	req.Host = domain
	applyBrowserProfileFhttp(req, probeProfile)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://vk.ru")
	req.Header.Set("Referer", "https://vk.ru/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Priority", "u=1, i")

	httpResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return resp, nil
}

func triggerCaptcha(client tlsclient.HttpClient, link string, creds vkCredentials, outDir string) string {
	link = strings.TrimSpace(link)
	if u, err := neturl.Parse(link); err == nil && strings.Contains(u.Path, "/call/join/") {
		link = path.Base(u.Path)
	}
	if link == "" {
		fatalf("empty join link hash")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("[trigger] link hash=%s creds.client_id=%s\n", link, creds.ClientID)

	// Token 1: get_anonym_token (same params as getTokenChain).
	data1 := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s",
		creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp1, err := doRequest(ctx, client, data1, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		fatalf("token1 request failed: %v", err)
	}
	if errMsg, ok := resp1["error"].(map[string]interface{}); ok {
		fatalf("token1 VK API error: %v", errMsg)
	}
	dataMap, ok := resp1["data"].(map[string]interface{})
	if !ok || dataMap == nil {
		fatalf("token1 invalid response structure: %v", resp1)
	}
	token1Raw, ok := dataMap["access_token"]
	if !ok {
		fatalf("token1 access_token not found: %v", resp1)
	}
	token1, ok := token1Raw.(string)
	if !ok {
		fatalf("token1 access_token is not a string: %v", token1Raw)
	}
	fmt.Printf("[trigger] token1 received (len=%d)\n", len(token1))

	time.Sleep(time.Duration(100+mathrand.Intn(51)) * time.Millisecond)

	// getCallPreview — mirrors the production call before getAnonymousToken.
	data2 := fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	if _, err := doRequest(ctx, client, data2,
		fmt.Sprintf("https://api.vk.ru/method/calls.getCallPreview?v=5.282&client_id=%s", creds.ClientID)); err != nil {
		fmt.Printf("[trigger] getCallPreview warning: %v\n", err)
	}

	time.Sleep(time.Duration(200+mathrand.Intn(201)) * time.Millisecond)

	// Token 2: getAnonymousToken — the call that raises the captcha error.
	name := probeNames[mathrand.Intn(len(probeNames))]
	data3 := fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=%s&access_token=%s",
		link, neturl.QueryEscape(name), token1)
	url3 := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.282&client_id=%s", creds.ClientID)
	resp3, err := doRequest(ctx, client, data3, url3)
	if err != nil {
		fatalf("getAnonymousToken request failed: %v", err)
	}

	raw, _ := json.MarshalIndent(resp3, "", "  ")
	dumpFile := path.Join(outDir, "captcha-trigger-response.json")
	if err := os.WriteFile(dumpFile, raw, 0o600); err == nil {
		fmt.Printf("[trigger] raw response saved to %s\n", dumpFile)
	}
	fmt.Printf("[trigger] getAnonymousToken response:\n%s\n", raw)

	errObj, hasErr := resp3["error"].(map[string]interface{})
	if !hasErr {
		fatalf("no captcha error in response — VK served token2 without a captcha from this IP/session; try again or run on the device")
	}

	codeFloat, _ := errObj["error_code"].(float64)
	msg, _ := errObj["error_msg"].(string)
	redirectURI, _ := errObj["redirect_uri"].(string)
	fmt.Printf("[trigger] VK error: code=%v msg=%q\n", int(codeFloat), msg)
	fmt.Printf("[trigger] full redirect_uri:\n%s\n", redirectURI)

	if parsed, err := neturl.Parse(redirectURI); err == nil {
		fmt.Printf("[trigger] session_token=%s\n", parsed.Query().Get("session_token"))
	} else {
		fmt.Printf("[trigger] redirect_uri parse failed: %v\n", err)
	}
	if redirectURI == "" {
		fatalf("redirect_uri missing in captcha error")
	}
	return redirectURI
}

// probeBootstrap mirrors fetchCaptchaBootstrap (vk_captcha.go): same GET,
// headers and Host override; then dumps the body and runs the production
// parser on it.
func probeBootstrap(client tlsclient.HttpClient, redirectURI string, outDir string) *captchaBootstrap {
	parsedURL, err := neturl.Parse(redirectURI)
	if err != nil {
		fatalf("parse redirect_uri: %v", err)
	}
	domain := parsedURL.Hostname()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := fhttp.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		fatalf("build bootstrap request: %v", err)
	}
	req.Host = domain
	applyCaptchaBrowserProfileFhttp(req, probeProfile)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")

	resp, err := client.Do(req)
	if err != nil {
		fatalf("bootstrap GET failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fatalf("read bootstrap body: %v", err)
	}

	fmt.Printf("\n[bootstrap] GET %s\n", redirectURI)
	fmt.Printf("[bootstrap] status=%d content-type=%s content-length=%d\n",
		resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.String() != redirectURI {
		fmt.Printf("[bootstrap] final URL after redirects: %s\n", resp.Request.URL.String())
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		fmt.Printf("[bootstrap] Location header: %s\n", loc)
	}
	for _, h := range []string{"Server", "X-Vk-", "P3P", "Content-Encoding", "Cache-Control"} {
		if v := resp.Header.Get(h); v != "" {
			fmt.Printf("[bootstrap] %s: %s\n", h, v)
		}
	}

	dumpFile := path.Join(outDir, "captcha-bootstrap.html")
	if err := os.WriteFile(dumpFile, body, 0o600); err != nil {
		fmt.Printf("[bootstrap] warning: could not save dump: %v\n", err)
	} else {
		fmt.Printf("[bootstrap] body saved to %s (%d bytes)\n", dumpFile, len(body))
	}

	// Debug: which cookies did the bootstrap page plant in the jar?
	for _, u := range []string{"https://id.vk.ru/", "https://api.vk.ru/"} {
		if pu, err := neturl.Parse(u); err == nil {
			cookies := client.GetCookies(pu)
			fmt.Printf("[bootstrap] jar for %s: %d cookies\n", pu.Host, len(cookies))
			for _, c := range cookies {
				fmt.Printf("[bootstrap]   %s=%s (domain=%s)\n", c.Name, truncate(c.Value, 30), c.Domain)
			}
		}
	}

	html := string(body)
	bootstrap := diagnoseBootstrapHTML(html)
	return bootstrap
}

func diagnoseBootstrapHTML(html string) *captchaBootstrap {
	fmt.Printf("\n[parse] running production parser (parseCaptchaBootstrapHTML)...\n")
	bootstrap, err := parseCaptchaBootstrapHTML(html)
	if err != nil {
		fmt.Printf("[parse] FAILED: %v\n", err)
		return nil
	}
	fmt.Printf("[parse] OK: powInput=%s difficulty=%d v2=%t scriptURL=%s show_captcha_type=%q types=%s\n",
		bootstrap.PowInput, bootstrap.Difficulty, bootstrap.PowV2, bootstrap.ScriptURL,
		bootstrap.Settings.ShowCaptchaType, describeTypes(bootstrap.Settings.SettingsByType))

	titleRe := regexp.MustCompile(`<title[^>]*>([^<]*)</title>`)
	if m := titleRe.FindStringSubmatch(html); len(m) >= 2 {
		fmt.Printf("[diag] <title>: %q\n", m[1])
	}

	patterns := map[string]*regexp.Regexp{
		"powInput":            regexp.MustCompile(`.{0,80}powInput.{0,120}`),
		"pow_input":           regexp.MustCompile(`.{0,80}pow_input.{0,120}`),
		"powNonce":            regexp.MustCompile(`.{0,80}powNonce.{0,120}`),
		"startsWith 0.repeat": regexp.MustCompile(`.{0,80}startsWith\('0'\.repeat.{0,120}`),
		"const difficulty":    regexp.MustCompile(`.{0,80}const\s+difficulty.{0,120}`),
		"not_robot_captcha":   regexp.MustCompile(`.{0,80}not_robot_captcha.{0,120}`),
		"window.init":         regexp.MustCompile(`.{0,60}window\.init.{0,80}`),
		"captcha_settings":    regexp.MustCompile(`.{0,60}captcha_settings.{0,120}`),
	}
	for name, re := range patterns {
		matches := re.FindAllString(html, 5)
		fmt.Printf("[diag] %s: %d match(es)\n", name, len(matches))
		for i, m := range matches {
			fmt.Printf("   [%d] ...%s...\n", i+1, m)
		}
	}

	fmt.Printf("[diag] body head:\n%s\n", truncate(html, 600))
	return bootstrap
}

func describeTypes(m map[string]string) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ",")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "fatal: "+format+"\n", args...)
	os.Exit(1)
}
