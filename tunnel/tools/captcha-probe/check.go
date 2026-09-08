package main

// Live captchaNotRobot.check dry-run: settings -> componentDone -> checkbox
// check with the solved PoW hash, mirroring callCaptchaNotRobotWithSliderPOC's
// first steps in libwg-go. Verifies end-to-end that VK accepts the v2 payload
// format.

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	mathrand "math/rand"
	neturl "net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
)

const captchaNotRobotAPIVersion = "5.131"

var captchaFormFieldOrder = map[string][]string{
	"captchaNotRobot.settings": {
		"session_token", "domain", "adFp", "access_token",
	},
	"captchaNotRobot.componentDone": {
		"session_token", "domain", "adFp", "browser_fp", "device", "access_token",
	},
	"captchaNotRobot.check": {
		"session_token", "domain", "adFp", "accelerometer", "gyroscope", "motion",
		"cursor", "taps", "connectionRtt", "connectionDownlink", "browser_fp",
		"hash", "answer", "debug_info", "access_token",
	},
	"captchaNotRobot.endSession": {
		"session_token", "domain", "adFp", "access_token",
	},
}

type captchaViewport struct {
	Width            int
	Height           int
	DevicePixelRatio float64
}

func encodeCaptchaForm(method string, values neturl.Values) string {
	orderedKeys := captchaFormFieldOrder[method]
	seen := make(map[string]bool, len(values))
	parts := make([]string, 0, len(values))
	appendKey := func(key string) {
		for _, value := range values[key] {
			parts = append(parts, neturl.QueryEscape(key)+"="+neturl.QueryEscape(value))
		}
		seen[key] = true
	}
	for _, key := range orderedKeys {
		if _, ok := values[key]; ok {
			appendKey(key)
		}
	}
	remaining := make([]string, 0, len(values)-len(seen))
	for key := range values {
		if !seen[key] {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)
	for _, key := range remaining {
		appendKey(key)
	}
	return strings.Join(parts, "&")
}

func captchaRequest(ctx context.Context, client tlsclient.HttpClient, method string, values neturl.Values) (map[string]interface{}, error) {
	reqURL := "https://api.vk.ru/method/" + method + "?v=" + captchaNotRobotAPIVersion

	req, err := fhttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(encodeCaptchaForm(method, values)))
	if err != nil {
		return nil, err
	}
	applyCaptchaBrowserProfileFhttp(req, probeProfile)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://id.vk.ru")
	req.Header.Set("Referer", "https://id.vk.ru/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Priority", "u=1, i")
	req.Header[fhttp.HeaderOrderKey] = captchaHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = captchaPHeaderOrder

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
		return nil, err
	}
	return resp, nil
}

func randomViewport() captchaViewport {
	// The reference capture used exactly this viewport; pin it so the
	// device JSON stays identical to the accepted payload.
	return captchaViewport{Width: 412, Height: 915, DevicePixelRatio: 2.625}
}

func generateBrowserFp() string {
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		return fmt.Sprintf("%x", mathrand.Int63())
	}
	return hex.EncodeToString(b)
}

func loadOrCreateBrowserFp(outDir string) string {
	fpPath := path.Join(outDir, "browser-fp.txt")
	if raw, err := os.ReadFile(fpPath); err == nil {
		fp := strings.TrimSpace(string(raw))
		if len(fp) == 32 {
			fmt.Printf("[check] reusing persisted browser_fp: %.8s...\n", fp)
			return fp
		}
	}
	fp := generateBrowserFp()
	if err := os.WriteFile(fpPath, []byte(fp), 0o600); err != nil {
		fmt.Printf("[check] warning: could not persist browser_fp: %v\n", err)
	} else {
		fmt.Printf("[check] generated new browser_fp (saved to %s)\n", fpPath)
	}
	return fp
}

// loadOrCreateAdFp mirrors the browser's window.rb_sync.id (a 16-byte
// base64url id loaded from ad.mail.ru sync-loader): stable per device,
// persisted across runs, sent in every captchaNotRobot call.
func loadOrCreateAdFp(outDir string) string {
	fpPath := path.Join(outDir, "adfp.txt")
	if raw, err := os.ReadFile(fpPath); err == nil {
		fp := strings.TrimSpace(string(raw))
		if len(fp) == 22 {
			fmt.Printf("[check] reusing persisted adFp: %.8s...\n", fp)
			return fp
		}
	}
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		return ""
	}
	fp := base64.RawURLEncoding.EncodeToString(b)
	if err := os.WriteFile(fpPath, []byte(fp), 0o600); err != nil {
		fmt.Printf("[check] warning: could not persist adFp: %v\n", err)
	} else {
		fmt.Printf("[check] generated new adFp (saved to %s)\n", fpPath)
	}
	return fp
}

// buildCaptchaDeviceJSON returns the device JSON and the matching
// hardwareConcurrency/deviceMemory pair, which must equal the hw/mem values
// reported inside the PoW telemetry.
func buildCaptchaDeviceJSON(vp captchaViewport) (string, int, int) {
	// Reference capture values: full viewport as innerWidth/innerHeight, the
	// desktop core/RAM counts, notifications never asked for, and no
	// webdriver key (the page omits it when navigator.webdriver is
	// undefined, as it is in a real Chrome).
	innerWidth := vp.Width
	innerHeight := vp.Height

	hardwareConcurrency := 10
	deviceMemory := 16

	device := fmt.Sprintf(
		`{"screenWidth":%d,"screenHeight":%d,"screenAvailWidth":%d,"screenAvailHeight":%d,"innerWidth":%d,"innerHeight":%d,"devicePixelRatio":%s,"language":"en-GB","languages":["en-GB","en-US","en"],"hardwareConcurrency":%d,"deviceMemory":%d,"connectionEffectiveType":"4g","notificationsPermission":"prompt"}`,
		vp.Width, vp.Height, vp.Width, vp.Height, innerWidth, innerHeight,
		strconv.FormatFloat(vp.DevicePixelRatio, 'f', -1, 64),
		hardwareConcurrency,
		deviceMemory,
	)
	return device, hardwareConcurrency, deviceMemory
}

// generateNetworkSamples mirrors the browser's connectionRtt/connectionDownlink
// arrays: one constant value per session, one sample per 200ms sensors_delay
// tick since componentDone.
func generateNetworkSamples(n int) (string, string) {
	if n < 1 {
		n = 1
	}
	rttVal := 40 + mathrand.Intn(61)
	downlinkVal := math.Round((1.6+mathrand.Float64()*8)*10) / 10

	rtt := make([]float64, 0, n)
	downlink := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		rtt = append(rtt, float64(rttVal))
		downlink = append(downlink, downlinkVal)
	}

	encode := func(v interface{}) string {
		raw, err := json.Marshal(v)
		if err != nil {
			return "[]"
		}
		return string(raw)
	}
	return encode(rtt), encode(downlink)
}

var reCaptchaDebugInfo = regexp.MustCompile(`debug_info:(?:[^"]*\|\|)?"([a-fA-F0-9]{64})"`)

func fetchDebugInfo(ctx context.Context, client tlsclient.HttpClient, scriptURL string) (string, error) {
	req, err := fhttp.NewRequestWithContext(ctx, "GET", scriptURL, nil)
	if err != nil {
		return "", err
	}
	applyCaptchaBrowserProfileFhttp(req, probeProfile)
	req.Header.Set("Accept", "text/javascript,*/*")
	req.Header.Set("Referer", "https://id.vk.ru/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header[fhttp.HeaderOrderKey] = captchaHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = captchaPHeaderOrder

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	m := reCaptchaDebugInfo.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("debug_info not found in captcha script")
	}
	return string(m[1]), nil
}

// runLiveCheck replays settings -> componentDone -> checkbox check with the
// solved hash, then reports the server verdict.
func runLiveCheck(client tlsclient.HttpClient, redirectURI string, bootstrap *captchaBootstrap, outDir string) {
	sessionToken := ""
	if parsed, err := neturl.Parse(redirectURI); err == nil {
		sessionToken = parsed.Query().Get("session_token")
	}
	if sessionToken == "" {
		fmt.Printf("[check] no session_token in redirect_uri; skipping live check\n")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The page reads `domain` from its own URL query and sends it back in
	// every captchaNotRobot call — hardcoding vk.ru breaks sessions where
	// the redirect_uri carries domain=vk.com.
	captchaDomain := "vk.ru"
	if parsed, err := neturl.Parse(redirectURI); err == nil {
		if d := parsed.Query().Get("domain"); d != "" {
			captchaDomain = d
		}
	}
	fmt.Printf("[check] domain=%s\n", captchaDomain)

	// Same as production: one browser_fp, one adFp and one viewport for the
	// whole session; both fps are persisted across runs so VK sees one
	// returning device instead of a bot cycling identities.
	browserFp := loadOrCreateBrowserFp(outDir)
	adFp := loadOrCreateAdFp(outDir)
	vp := randomViewport()

	baseValues := func() neturl.Values {
		values := neturl.Values{}
		values.Set("session_token", sessionToken)
		values.Set("domain", captchaDomain)
		values.Set("adFp", adFp)
		values.Set("access_token", "")
		return values
	}

	// 1. settings
	settingsResp, err := captchaRequest(ctx, client, "captchaNotRobot.settings", baseValues())
	if err != nil {
		fmt.Printf("[check] settings failed: %v\n", err)
		return
	}
	fmt.Printf("[check] settings response:\n%s\n", compactJSON(settingsResp))

	// Debug: cookies the jar holds for api.vk.ru after settings.
	if pu, err := neturl.Parse("https://api.vk.ru/"); err == nil {
		cookies := client.GetCookies(pu)
		fmt.Printf("[check] jar for api.vk.ru: %d cookies\n", len(cookies))
		for _, c := range cookies {
			fmt.Printf("[check]   %s=%s (domain=%s)\n", c.Name, truncate(c.Value, 30), c.Domain)
		}
	}

	time.Sleep(time.Duration(300+mathrand.Intn(200)) * time.Millisecond)

	// 2. componentDone
	deviceJSON, hw, mem := buildCaptchaDeviceJSON(vp)
	cdValues := baseValues()
	cdValues.Set("browser_fp", browserFp)
	cdValues.Set("device", deviceJSON)
	cdResp, err := captchaRequest(ctx, client, "captchaNotRobot.componentDone", cdValues)
	if err != nil {
		fmt.Printf("[check] componentDone failed: %v\n", err)
		return
	}
	fmt.Printf("[check] componentDone: %s\n", compactJSON(cdResp))

	// The browser collects sensor/network samples every 200ms (sensors_delay)
	// between componentDone and check; the rtt/downlink sample count must
	// match that window.
	checkWindowStart := time.Now()
	time.Sleep(time.Duration(5500+mathrand.Intn(1500)) * time.Millisecond)

	debugInfo := ""
	if bootstrap.ScriptURL != "" {
		if v, err := fetchDebugInfo(ctx, client, bootstrap.ScriptURL); err == nil {
			debugInfo = v
			fmt.Printf("[check] debug_info from script: %.12s...\n", v)
		} else {
			fmt.Printf("[check] debug_info fetch failed: %v\n", err)
		}
	}

	// 3. PoW solve + checkbox check
	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty, bootstrap.PowV2, hw, mem)
	if hash == "" {
		fmt.Printf("[check] PoW solve failed\n")
		return
	}
	fmt.Printf("[check] powInput=%q difficulty=%d v2=%t\n", bootstrap.PowInput, bootstrap.Difficulty, bootstrap.PowV2)
	fmt.Printf("[check] hash=%s\n", hash)
	if bootstrap.PowV2 {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hash, "v2.")); err == nil {
			fmt.Printf("[check] decoded payload: %s\n", decoded)
		}
	}

	// The reference browser sent empty arrays for every bridge sensor and
	// VK accepted it with OK, so fabricating motion data only adds risk.
	sampleCount := int(time.Since(checkWindowStart).Milliseconds() / 200)
	rttJSON, downlinkJSON := generateNetworkSamples(sampleCount)
	checkValues := baseValues()
	checkValues.Set("accelerometer", "[]")
	checkValues.Set("gyroscope", "[]")
	checkValues.Set("motion", "[]")
	checkValues.Set("cursor", "[]")
	checkValues.Set("taps", "[]")
	checkValues.Set("connectionRtt", rttJSON)
	checkValues.Set("connectionDownlink", downlinkJSON)
	checkValues.Set("browser_fp", browserFp)
	checkValues.Set("hash", hash)
	checkValues.Set("answer", base64.StdEncoding.EncodeToString([]byte("{}")))
	checkValues.Set("debug_info", debugInfo)

	checkResp, err := captchaRequest(ctx, client, "captchaNotRobot.check", checkValues)
	if err != nil {
		fmt.Printf("[check] check failed: %v\n", err)
		return
	}
	fmt.Printf("[check] check response:\n%s\n", compactJSON(checkResp))

	// 4. endSession
	if _, err := captchaRequest(ctx, client, "captchaNotRobot.endSession", baseValues()); err != nil {
		fmt.Printf("[check] endSession warning: %v\n", err)
	}
}

func compactJSON(v interface{}) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(raw)
}
