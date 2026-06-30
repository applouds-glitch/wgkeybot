package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	neturl "net/url"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
)

const (
	captchaDebugInfo      = "1d3e9babfd3a74f4588bf90cf5c30d3e8e89a0e2a4544da8de8bbf4d78a32f5c"
	sliderCaptchaType     = "slider"
	defaultSliderAttempts = 4
)

type captchaNotRobotSession struct {
	ctx          context.Context
	sessionToken string
	hash         string
	debugInfo    string
	streamID     int
	client       tlsclient.HttpClient
	profile      Profile
	browserFp    string
}

type captchaSettingsResponse struct {
	ShowCaptchaType string
	SettingsByType  map[string]string
}

type captchaCheckResult struct {
	Status          string
	SuccessToken    string
	ShowCaptchaType string
}

type sliderCaptchaContent struct {
	Image    image.Image
	Size     int
	Steps    []int
	Attempts int
}

type sliderCandidate struct {
	Index         int
	ActiveSteps   []int
	Score         int64
	ScoreLuma     int64
	ScoreRGB      int64
	ScoreText     float64
	ConsensusRank int
}

type captchaBootstrap struct {
	PowInput   string
	Difficulty int
	Settings   *captchaSettingsResponse
	ScriptURL  string
}

func newCaptchaNotRobotSession(
	ctx context.Context,
	sessionToken string,
	hash string,
	debugInfo string,
	streamID int,
	client tlsclient.HttpClient,
	profile Profile,
) *captchaNotRobotSession {
	return &captchaNotRobotSession{
		ctx:          ctx,
		sessionToken: sessionToken,
		hash:         hash,
		debugInfo:    debugInfo,
		streamID:     streamID,
		client:       client,
		profile:      profile,
		browserFp:    generateBrowserFp(profile, randomViewport()),
	}
}

func (s *captchaNotRobotSession) baseValues() neturl.Values {
	values := neturl.Values{}
	values.Set("session_token", s.sessionToken)
	values.Set("domain", "vk.com")
	values.Set("adFp", "")
	values.Set("access_token", "")
	return values
}

func (s *captchaNotRobotSession) request(method string, values neturl.Values) (map[string]interface{}, error) {
	reqURL := "https://api.vk.com/method/" + method + "?v=5.282"

	req, err := fhttp.NewRequestWithContext(s.ctx, "POST", reqURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	applyBrowserProfileFhttp(req, s.profile)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://id.vk.com")
	req.Header.Set("Referer", "https://id.vk.com/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Priority", "u=1, i")
	req.Header[fhttp.HeaderOrderKey] = captchaHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = captchaPHeaderOrder

	httpResp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = httpResp.Body.Close()
	}()

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

func (s *captchaNotRobotSession) requestSettings() (*captchaSettingsResponse, error) {
	resp, err := s.request("captchaNotRobot.settings", s.baseValues())
	if err != nil {
		return nil, fmt.Errorf("settings failed: %w", err)
	}
	return parseCaptchaSettingsResponse(resp)
}

func (s *captchaNotRobotSession) requestComponentDone() error {
	values := s.baseValues()
	values.Set("browser_fp", s.browserFp)
	values.Set("device", buildCaptchaDeviceJSON(s.profile, randomViewport()))

	resp, err := s.request("captchaNotRobot.componentDone", values)
	if err != nil {
		return fmt.Errorf("componentDone failed: %w", err)
	}

	respObj, ok := resp["response"].(map[string]interface{})
	if ok {
		if status, _ := respObj["status"].(string); status != "" && status != "OK" {
			return fmt.Errorf("componentDone status: %s", status)
		}
	}

	return nil
}

func (s *captchaNotRobotSession) requestCheckboxCheck() (*captchaCheckResult, error) {
	// A checkbox check models a tap/click, not a slider drag — use the same
	// human-like cursor trajectory the standalone checkbox solver used so the
	// in-session checkbox attempt scores no worse than the old separate path.
	return s.requestCheck(generateHumanCursor(), base64.StdEncoding.EncodeToString([]byte("{}")))
}

func (s *captchaNotRobotSession) requestSliderContent(sliderSettings string) (*sliderCaptchaContent, error) {
	values := s.baseValues()
	if sliderSettings != "" {
		values.Set("captcha_settings", sliderSettings)
	}

	resp, err := s.request("captchaNotRobot.getContent", values)
	if err != nil {
		return nil, fmt.Errorf("getContent failed: %w", err)
	}
	return parseSliderCaptchaContentResponse(resp)
}

func (s *captchaNotRobotSession) requestSliderCheck(activeSteps []int, candidateIndex int, candidateCount int) (*captchaCheckResult, error) {
	answer, err := encodeSliderAnswer(activeSteps)
	if err != nil {
		return nil, err
	}

	return s.requestCheck(generateSliderCursor(candidateIndex, candidateCount), answer)
}

func (s *captchaNotRobotSession) requestCheck(cursor string, answer string) (*captchaCheckResult, error) {
	// Mobile profile: a real Android device exposes accelerometer/gyroscope and
	// reports network metrics, so populate them (matching callCaptchaNotRobot).
	connRtt, connDownlink := generateConnectionMetrics()
	values := s.baseValues()
	values.Set("accelerometer", generateSensorNoise())
	values.Set("gyroscope", generateGyroNoise())
	values.Set("motion", "[]")
	values.Set("cursor", cursor)
	values.Set("taps", "[]")
	values.Set("connectionRtt", connRtt)
	values.Set("connectionDownlink", connDownlink)
	values.Set("browser_fp", s.browserFp)
	values.Set("hash", s.hash)
	values.Set("answer", answer)
	values.Set("debug_info", s.debugInfo)

	resp, err := s.request("captchaNotRobot.check", values)
	if err != nil {
		return nil, fmt.Errorf("check failed: %w", err)
	}
	return parseCaptchaCheckResult(resp)
}

func (s *captchaNotRobotSession) requestEndSession() {
	log.Printf("[STREAM %d] [Captcha] Step 4/4: endSession", s.streamID)
	if _, err := s.request("captchaNotRobot.endSession", s.baseValues()); err != nil {
		log.Printf("[STREAM %d] [Captcha] Warning: endSession failed: %v", s.streamID, err)
	}
}

func callCaptchaNotRobotWithSliderPOC(
	ctx context.Context,
	sessionToken string,
	hash string,
	debugInfo string,
	streamID int,
	client tlsclient.HttpClient,
	profile Profile,
	initialSettings *captchaSettingsResponse,
) (string, error) {
	session := newCaptchaNotRobotSession(ctx, sessionToken, hash, debugInfo, streamID, client, profile)

	log.Printf("[STREAM %d] [Captcha] Step 1/4: settings", streamID)
	settingsResp, err := session.requestSettings()
	if err != nil {
		return "", err
	}
	settingsResp = mergeCaptchaSettings(settingsResp, initialSettings)

	time.Sleep(time.Duration(500+mathrand.Intn(300)) * time.Millisecond)

	log.Printf("[STREAM %d] [Captcha] Step 2/4: componentDone", streamID)
	if err := session.requestComponentDone(); err != nil {
		return "", err
	}

	time.Sleep(time.Duration(500+mathrand.Intn(300)) * time.Millisecond)

	sliderSettings, hasSlider := settingsResp.SettingsByType[sliderCaptchaType]

	// checkboxStatus records the outcome of the checkbox check when we run one.
	// When the slider is already advertised we skip the checkbox entirely, so it
	// stays empty and the error path below adapts its message accordingly.
	checkboxStatus := ""
	if !hasSlider {
		// No slider offered: try the checkbox. Only if VK rejects it do we fall
		// through and attempt getContent without explicit slider settings.
		log.Printf("[STREAM %d] [Captcha] Step 3/4: check", streamID)
		initialCheck, err := session.requestCheckboxCheck()
		if err != nil {
			return "", err
		}
		if initialCheck.Status == "OK" {
			if initialCheck.SuccessToken == "" {
				return "", fmt.Errorf("success_token not found")
			}
			session.requestEndSession()
			return initialCheck.SuccessToken, nil
		}
		checkboxStatus = initialCheck.Status
		log.Printf(
			"[STREAM %d] [Captcha] Checkbox-style check returned status=%s (settings show_type=%q, check show_type=%q, available_types=%s)",
			streamID,
			initialCheck.Status,
			settingsResp.ShowCaptchaType,
			initialCheck.ShowCaptchaType,
			describeCaptchaTypes(settingsResp.SettingsByType),
		)
		log.Printf(
			"[STREAM %d] [Captcha] Slider settings not found in settings response. Trying getContent without captcha_settings...",
			streamID,
		)
	} else {
		// Slider already advertised — skip the checkbox check. It would only
		// return BOT and burn a request against VK's per-token rate limit before
		// we can fetch the slider image, so go straight to getContent.
		log.Printf("[STREAM %d] [Captcha] Slider advertised in settings — fetching it directly (skipping checkbox)", streamID)
	}

	sliderContent, err := session.requestSliderContent(sliderSettings)
	if err != nil {
		log.Printf(
			"[STREAM %d] [Captcha] Slider getContent failed (status: %v). Trying to solve as a checkbox instead...",
			streamID,
			err,
		)
		// Fallback: maybe it's just a checkbox that needs a human-like check
		time.Sleep(time.Duration(300+mathrand.Intn(200)) * time.Millisecond)
		finalCheck, err2 := session.requestCheckboxCheck()
		if err2 == nil && finalCheck.Status == "OK" {
			if finalCheck.SuccessToken == "" {
				return "", fmt.Errorf("success_token not found in fallback check")
			}
			log.Printf("[STREAM %d] [Captcha] Fallback checkbox check succeeded!", streamID)
			session.requestEndSession()
			return finalCheck.SuccessToken, nil
		}
		if checkboxStatus != "" {
			return "", fmt.Errorf("check status: %s (slider getContent failed: %w)", checkboxStatus, err)
		}
		return "", fmt.Errorf("slider getContent failed: %w", err)
	}

	candidates, err := rankSliderCandidates(sliderContent.Image, sliderContent.Size, sliderContent.Steps)
	if err != nil {
		return "", err
	}

	log.Printf(
		"[STREAM %d] [Captcha] Ranked %d slider positions locally; submitting top %d based on attempt budget %d",
		streamID,
		len(candidates),
		minInt(sliderContent.Attempts, len(candidates)),
		sliderContent.Attempts,
	)

	successToken, err := trySliderCaptchaCandidates(candidates, sliderContent.Attempts, func(candidate sliderCandidate) (*captchaCheckResult, error) {
		log.Printf(
			"[STREAM %d] [Captcha] Slider guess position=%d score=%d",
			streamID,
			candidate.Index,
			candidate.Score,
		)
		return session.requestSliderCheck(candidate.ActiveSteps, candidate.Index, len(candidates))
	})
	if err != nil {
		return "", err
	}

	session.requestEndSession()
	return successToken, nil
}

func parseCaptchaSettingsResponse(resp map[string]interface{}) (*captchaSettingsResponse, error) {
	respObj, ok := resp["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid settings response: %v", resp)
	}

	settings := &captchaSettingsResponse{
		SettingsByType: make(map[string]string),
	}
	settings.ShowCaptchaType, _ = respObj["show_captcha_type"].(string)

	rawSettings, ok := expandCaptchaSettings(respObj["captcha_settings"])
	if !ok {
		return settings, nil
	}

	for _, rawItem := range rawSettings {
		item, ok := rawItem.(map[string]interface{})
		if !ok {
			continue
		}

		captchaType, _ := item["type"].(string)
		if captchaType == "" {
			continue
		}

		normalized, err := normalizeCaptchaSettings(item["settings"])
		if err != nil {
			return nil, fmt.Errorf("invalid captcha_settings for %s: %w", captchaType, err)
		}

		settings.SettingsByType[captchaType] = normalized
	}

	return settings, nil
}

func parseCaptchaBootstrapHTML(html string) (*captchaBootstrap, error) {
	powInputRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	powInputMatch := powInputRe.FindStringSubmatch(html)
	if len(powInputMatch) < 2 {
		return nil, fmt.Errorf("powInput not found in captcha HTML")
	}

	difficulty := 2
	for _, expr := range []*regexp.Regexp{
		regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`),
		regexp.MustCompile(`const\s+difficulty\s*=\s*(\d+)`),
	} {
		if match := expr.FindStringSubmatch(html); len(match) >= 2 {
			if parsed, err := strconv.Atoi(match[1]); err == nil {
				difficulty = parsed
				break
			}
		}
	}

	settings, err := parseCaptchaSettingsFromHTML(html)
	if err != nil {
		return nil, err
	}

	var scriptURL string
	if m := reCaptchaScriptSrc.FindStringSubmatch(html); len(m) >= 2 {
		scriptURL = m[1]
	}

	return &captchaBootstrap{
		PowInput:   powInputMatch[1],
		Difficulty: difficulty,
		Settings:   settings,
		ScriptURL:  scriptURL,
	}, nil
}

func parseCaptchaSettingsFromHTML(html string) (*captchaSettingsResponse, error) {
	initRe := regexp.MustCompile(`(?s)window\.init\s*=\s*(\{.*?})\s*;\s*window\.lang`)
	initMatch := initRe.FindStringSubmatch(html)
	if len(initMatch) < 2 {
		return &captchaSettingsResponse{SettingsByType: make(map[string]string)}, nil
	}

	var initPayload struct {
		Data struct {
			ShowCaptchaType string      `json:"show_captcha_type"`
			CaptchaSettings interface{} `json:"captcha_settings"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(initMatch[1]), &initPayload); err != nil {
		return nil, fmt.Errorf("parse window.init captcha data: %w", err)
	}

	return parseCaptchaSettingsResponse(map[string]interface{}{
		"response": map[string]interface{}{
			"show_captcha_type": initPayload.Data.ShowCaptchaType,
			"captcha_settings":  initPayload.Data.CaptchaSettings,
		},
	})
}

func mergeCaptchaSettings(primary *captchaSettingsResponse, fallback *captchaSettingsResponse) *captchaSettingsResponse {
	if primary == nil {
		return cloneCaptchaSettings(fallback)
	}
	if primary.SettingsByType == nil {
		primary.SettingsByType = make(map[string]string)
	}
	if fallback == nil {
		return primary
	}
	if primary.ShowCaptchaType == "" {
		primary.ShowCaptchaType = fallback.ShowCaptchaType
	}
	for captchaType, settings := range fallback.SettingsByType {
		if _, exists := primary.SettingsByType[captchaType]; !exists {
			primary.SettingsByType[captchaType] = settings
		}
	}
	return primary
}

func cloneCaptchaSettings(src *captchaSettingsResponse) *captchaSettingsResponse {
	if src == nil {
		return nil
	}

	cloned := &captchaSettingsResponse{
		ShowCaptchaType: src.ShowCaptchaType,
		SettingsByType:  make(map[string]string, len(src.SettingsByType)),
	}
	for captchaType, settings := range src.SettingsByType {
		cloned.SettingsByType[captchaType] = settings
	}
	return cloned
}

func expandCaptchaSettings(raw interface{}) ([]interface{}, bool) {
	switch value := raw.(type) {
	case nil:
		return nil, false
	case []interface{}:
		return value, true
	case map[string]interface{}:
		items := make([]interface{}, 0, len(value))
		for captchaType, settings := range value {
			items = append(items, map[string]interface{}{
				"type":     captchaType,
				"settings": settings,
			})
		}
		return items, true
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return nil, false
		}

		var items []interface{}
		if err := json.Unmarshal([]byte(trimmed), &items); err == nil {
			return items, true
		}

		var mapping map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &mapping); err == nil {
			return expandCaptchaSettings(mapping)
		}
	}

	return nil, false
}

func normalizeCaptchaSettings(raw interface{}) (string, error) {
	switch value := raw.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
}

func parseCaptchaCheckResult(resp map[string]interface{}) (*captchaCheckResult, error) {
	respObj, ok := resp["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid check response: %v", resp)
	}

	result := &captchaCheckResult{}
	result.Status, _ = respObj["status"].(string)
	result.SuccessToken, _ = respObj["success_token"].(string)
	result.ShowCaptchaType, _ = respObj["show_captcha_type"].(string)
	if result.Status == "" {
		return nil, fmt.Errorf("check status missing: %v", resp)
	}

	return result, nil
}

func parseSliderCaptchaContentResponse(resp map[string]interface{}) (*sliderCaptchaContent, error) {
	respObj, ok := resp["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid slider content response: %v", resp)
	}

	status, _ := respObj["status"].(string)
	if status != "OK" {
		if upper := strings.ToUpper(status); upper == "ERROR" || upper == "ERROR_LIMIT" {
			// VK refuses to serve the slider image to a throttled/flagged
			// session — equivalent to a rate limit, not a transient glitch.
			return nil, errCaptchaRateLimit
		}
		return nil, fmt.Errorf("slider getContent status: %s", status)
	}

	extension, _ := respObj["extension"].(string)
	extension = strings.ToLower(extension)
	if extension != "jpeg" && extension != "jpg" {
		return nil, fmt.Errorf("unsupported slider image format: %s", extension)
	}

	rawImage, _ := respObj["image"].(string)
	if rawImage == "" {
		return nil, fmt.Errorf("slider image missing")
	}

	rawSteps, ok := respObj["steps"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("slider steps missing")
	}

	steps, err := parseIntSlice(rawSteps)
	if err != nil {
		return nil, err
	}

	size, swaps, attempts, err := parseSliderSteps(steps)
	if err != nil {
		return nil, err
	}

	img, err := decodeSliderImage(rawImage)
	if err != nil {
		return nil, err
	}

	return &sliderCaptchaContent{
		Image:    img,
		Size:     size,
		Steps:    swaps,
		Attempts: attempts,
	}, nil
}

func parseIntSlice(raw []interface{}) ([]int, error) {
	values := make([]int, 0, len(raw))
	for _, item := range raw {
		number, err := parseIntValue(item)
		if err != nil {
			return nil, err
		}
		values = append(values, number)
	}
	return values, nil
}

func parseIntValue(raw interface{}) (int, error) {
	switch value := raw.(type) {
	case float64:
		return int(value), nil
	case int:
		return value, nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return 0, fmt.Errorf("invalid numeric value: %v", raw)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("invalid numeric value: %v", raw)
	}
}

func parseSliderSteps(steps []int) (int, []int, int, error) {
	if len(steps) < 3 {
		return 0, nil, 0, fmt.Errorf("slider steps payload too short")
	}

	size := steps[0]
	if size <= 0 {
		return 0, nil, 0, fmt.Errorf("invalid slider size: %d", size)
	}

	remaining := append([]int(nil), steps[1:]...)
	attempts := defaultSliderAttempts
	if len(remaining)%2 != 0 {
		attempts = remaining[len(remaining)-1]
		remaining = remaining[:len(remaining)-1]
	}
	if attempts <= 0 {
		attempts = defaultSliderAttempts
	}
	if len(remaining) == 0 || len(remaining)%2 != 0 {
		return 0, nil, 0, fmt.Errorf("invalid slider swap payload")
	}

	return size, remaining, attempts, nil
}

func decodeSliderImage(rawImage string) (image.Image, error) {
	decoded, err := base64.StdEncoding.DecodeString(rawImage)
	if err != nil {
		return nil, fmt.Errorf("decode slider image: %w", err)
	}

	img, _, err := image.Decode(bytes.NewReader(decoded))
	if err != nil {
		return nil, fmt.Errorf("decode slider image: %w", err)
	}

	return img, nil
}

func encodeSliderAnswer(activeSteps []int) (string, error) {
	payload := struct {
		Value []int `json:"value"`
	}{
		Value: activeSteps,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

func buildSliderActiveSteps(swaps []int, candidateIndex int) []int {
	if candidateIndex <= 0 {
		return []int{}
	}

	end := candidateIndex * 2
	if end > len(swaps) {
		end = len(swaps)
	}

	return append([]int(nil), swaps[:end]...)
}

func buildSliderTileMapping(gridSize int, activeSteps []int) ([]int, error) {
	tileCount := gridSize * gridSize
	if tileCount <= 0 {
		return nil, fmt.Errorf("invalid slider tile count: %d", tileCount)
	}
	if len(activeSteps)%2 != 0 {
		return nil, fmt.Errorf("invalid active steps length: %d", len(activeSteps))
	}

	mapping := make([]int, tileCount)
	for i := range mapping {
		mapping[i] = i
	}

	for idx := 0; idx < len(activeSteps); idx += 2 {
		left := activeSteps[idx]
		right := activeSteps[idx+1]
		if left < 0 || right < 0 || left >= tileCount || right >= tileCount {
			return nil, fmt.Errorf("slider step out of range: %d,%d", left, right)
		}
		mapping[left], mapping[right] = mapping[right], mapping[left]
	}

	return mapping, nil
}

func rankSliderCandidates(img image.Image, gridSize int, swaps []int) ([]sliderCandidate, error) {
	candidateCount := len(swaps) / 2
	if candidateCount == 0 {
		return nil, fmt.Errorf("slider has no candidates")
	}

	candidates := make([]sliderCandidate, candidateCount)

	// Stage 1: luma seam score for all candidates.
	for idx := 1; idx <= candidateCount; idx++ {
		activeSteps := buildSliderActiveSteps(swaps, idx)
		mapping, err := buildSliderTileMapping(gridSize, activeSteps)
		if err != nil {
			return nil, err
		}
		candidates[idx-1] = sliderCandidate{
			Index:       idx,
			ActiveSteps: activeSteps,
			ScoreLuma:   seamScoreLuma(img, gridSize, mapping),
		}
	}

	lumaOrder := append([]sliderCandidate(nil), candidates...)
	sort.SliceStable(lumaOrder, func(i, j int) bool {
		if lumaOrder[i].ScoreLuma == lumaOrder[j].ScoreLuma {
			return lumaOrder[i].Index < lumaOrder[j].Index
		}
		return lumaOrder[i].ScoreLuma < lumaOrder[j].ScoreLuma
	})
	lumaRank := make(map[int]int, candidateCount)
	for rank, g := range lumaOrder {
		lumaRank[g.Index] = rank
	}

	// Stage 2: RGB + Gaussian text score for top-12 candidates, in parallel.
	stage2Count := candidateCount
	if stage2Count > 12 {
		stage2Count = 12
	}
	stage2Set := make(map[int]struct{}, stage2Count)
	for i := 0; i < stage2Count; i++ {
		stage2Set[lumaOrder[i].Index] = struct{}{}
	}

	type stage2Result struct {
		index int
		rgb   int64
		text  float64
		err   error
	}
	jobs := make([]int, 0, stage2Count)
	for idx := range stage2Set {
		jobs = append(jobs, idx)
	}
	jobCh := make(chan int, len(jobs))
	resCh := make(chan stage2Result, len(jobs))

	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobCh {
				mapping, err := buildSliderTileMapping(gridSize, candidates[index-1].ActiveSteps)
				if err != nil {
					resCh <- stage2Result{index: index, err: err}
					continue
				}
				rgb, text := seamScoreRGBText(img, gridSize, mapping)
				resCh <- stage2Result{index: index, rgb: rgb, text: text}
			}
		}()
	}
	for _, idx := range jobs {
		jobCh <- idx
	}
	close(jobCh)
	wg.Wait()
	close(resCh)
	for r := range resCh {
		if r.err != nil {
			return nil, r.err
		}
		g := &candidates[r.index-1]
		g.ScoreRGB = r.rgb
		g.ScoreText = r.text
	}

	// Build RGB and text ranks within the stage-2 set.
	stage2 := make([]sliderCandidate, 0, stage2Count)
	for _, g := range candidates {
		if _, ok := stage2Set[g.Index]; ok {
			stage2 = append(stage2, g)
		}
	}
	rgbOrder := append([]sliderCandidate(nil), stage2...)
	sort.SliceStable(rgbOrder, func(i, j int) bool {
		if rgbOrder[i].ScoreRGB == rgbOrder[j].ScoreRGB {
			return rgbOrder[i].Index < rgbOrder[j].Index
		}
		return rgbOrder[i].ScoreRGB < rgbOrder[j].ScoreRGB
	})
	rgbRank := make(map[int]int, len(rgbOrder))
	for rank, g := range rgbOrder {
		rgbRank[g.Index] = rank
	}

	textOrder := append([]sliderCandidate(nil), stage2...)
	sort.SliceStable(textOrder, func(i, j int) bool {
		if textOrder[i].ScoreText == textOrder[j].ScoreText {
			return textOrder[i].Index < textOrder[j].Index
		}
		return textOrder[i].ScoreText < textOrder[j].ScoreText
	})
	textRank := make(map[int]int, len(textOrder))
	for rank, g := range textOrder {
		textRank[g.Index] = rank
	}

	// Consensus: sum of all available ranks.
	for i := range candidates {
		g := &candidates[i]
		g.ConsensusRank = lumaRank[g.Index]
		if _, ok := stage2Set[g.Index]; ok {
			g.ConsensusRank += rgbRank[g.Index] + textRank[g.Index]
		} else {
			g.ConsensusRank += candidateCount
		}
		g.Score = int64(g.ConsensusRank)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].ConsensusRank == candidates[j].ConsensusRank {
			if candidates[i].ScoreLuma == candidates[j].ScoreLuma {
				return candidates[i].Index < candidates[j].Index
			}
			return candidates[i].ScoreLuma < candidates[j].ScoreLuma
		}
		return candidates[i].ConsensusRank < candidates[j].ConsensusRank
	})

	return candidates, nil
}

// seamScoreLuma scores a candidate by luminance discontinuity at tile boundaries.
func seamScoreLuma(img image.Image, gridSize int, mapping []int) int64 {
	bounds := img.Bounds()
	var score int64

	for row := 0; row < gridSize; row++ {
		for col := 0; col < gridSize-1; col++ {
			li, ri := row*gridSize+col, row*gridSize+col+1
			lDst := sliderTileRect(bounds, gridSize, li)
			rDst := sliderTileRect(bounds, gridSize, ri)
			lSrc := sliderTileRect(bounds, gridSize, mapping[li])
			rSrc := sliderTileRect(bounds, gridSize, mapping[ri])
			h := minInt(lDst.Dy(), rDst.Dy())
			for y := 0; y < h; y++ {
				yy := lDst.Min.Y + y
				a := sampleLumaMapped(img, lDst, lSrc, lDst.Max.X-1, yy)
				b := sampleLumaMapped(img, rDst, rSrc, rDst.Min.X, yy)
				d := int(a) - int(b)
				if d < 0 {
					d = -d
				}
				score += int64(d)
			}
		}
	}
	for row := 0; row < gridSize-1; row++ {
		for col := 0; col < gridSize; col++ {
			ti, bi := row*gridSize+col, (row+1)*gridSize+col
			tDst := sliderTileRect(bounds, gridSize, ti)
			bDst := sliderTileRect(bounds, gridSize, bi)
			tSrc := sliderTileRect(bounds, gridSize, mapping[ti])
			bSrc := sliderTileRect(bounds, gridSize, mapping[bi])
			w := minInt(tDst.Dx(), bDst.Dx())
			for x := 0; x < w; x++ {
				xx := tDst.Min.X + x
				a := sampleLumaMapped(img, tDst, tSrc, xx, tDst.Max.Y-1)
				b := sampleLumaMapped(img, bDst, bSrc, xx, bDst.Min.Y)
				d := int(a) - int(b)
				if d < 0 {
					d = -d
				}
				score += int64(d)
			}
		}
	}
	return score
}

// seamScoreRGBText scores by RGB discontinuity plus a Gaussian-weighted text score
// (text rows sit near 20%, 50%, 80% of image height).
func seamScoreRGBText(img image.Image, gridSize int, mapping []int) (int64, float64) {
	bounds := img.Bounds()
	height := float64(bounds.Dy())
	textCenters := [3]float64{
		float64(bounds.Min.Y) + 0.2*height,
		float64(bounds.Min.Y) + 0.5*height,
		float64(bounds.Min.Y) + 0.8*height,
	}
	sigma := height * 0.14
	if sigma < 1.0 {
		sigma = 1.0
	}
	weight := func(y int) float64 {
		yf := float64(y)
		best := math.Abs(yf - textCenters[0])
		for i := 1; i < 3; i++ {
			if d := math.Abs(yf - textCenters[i]); d < best {
				best = d
			}
		}
		return 1 + 3*math.Exp(-(best*best)/(2*sigma*sigma))
	}

	var rgbScore int64
	var textScore float64

	for row := 0; row < gridSize; row++ {
		for col := 0; col < gridSize-1; col++ {
			li, ri := row*gridSize+col, row*gridSize+col+1
			lDst := sliderTileRect(bounds, gridSize, li)
			rDst := sliderTileRect(bounds, gridSize, ri)
			lSrc := sliderTileRect(bounds, gridSize, mapping[li])
			rSrc := sliderTileRect(bounds, gridSize, mapping[ri])
			h := minInt(lDst.Dy(), rDst.Dy())
			for y := 0; y < h; y++ {
				yy := lDst.Min.Y + y
				l := sampleColorMapped(img, lDst, lSrc, lDst.Max.X-1, yy)
				r := sampleColorMapped(img, rDst, rSrc, rDst.Min.X, yy)
				rgbScore += pixelDiff(l, r)
				_, _, lb, _ := l.RGBA()
				_, _, rb, _ := r.RGBA()
				ld, rd := int(lb>>8), int(rb>>8)
				diff := ld - rd
				if diff < 0 {
					diff = -diff
				}
				textScore += weight(yy) * float64(diff)
			}
		}
	}
	for row := 0; row < gridSize-1; row++ {
		for col := 0; col < gridSize; col++ {
			ti, bi := row*gridSize+col, (row+1)*gridSize+col
			tDst := sliderTileRect(bounds, gridSize, ti)
			bDst := sliderTileRect(bounds, gridSize, bi)
			tSrc := sliderTileRect(bounds, gridSize, mapping[ti])
			bSrc := sliderTileRect(bounds, gridSize, mapping[bi])
			w := minInt(tDst.Dx(), bDst.Dx())
			for x := 0; x < w; x++ {
				xx := tDst.Min.X + x
				t := sampleColorMapped(img, tDst, tSrc, xx, tDst.Max.Y-1)
				b := sampleColorMapped(img, bDst, bSrc, xx, bDst.Min.Y)
				rgbScore += pixelDiff(t, b)
				_, _, tb, _ := t.RGBA()
				_, _, bb, _ := b.RGBA()
				td, bd := int(tb>>8), int(bb>>8)
				diff := td - bd
				if diff < 0 {
					diff = -diff
				}
				textScore += 0.65 * float64(diff)
			}
		}
	}
	return rgbScore, textScore
}

func sampleColorMapped(img image.Image, dstRect, srcRect image.Rectangle, dstX, dstY int) color.Color {
	dx := dstRect.Dx()
	if dx < 1 {
		dx = 1
	}
	dy := dstRect.Dy()
	if dy < 1 {
		dy = 1
	}
	sx := srcRect.Min.X + (dstX-dstRect.Min.X)*srcRect.Dx()/dx
	sy := srcRect.Min.Y + (dstY-dstRect.Min.Y)*srcRect.Dy()/dy
	return img.At(sx, sy)
}

func sampleLumaMapped(img image.Image, dstRect, srcRect image.Rectangle, dstX, dstY int) uint8 {
	c := sampleColorMapped(img, dstRect, srcRect, dstX, dstY)
	r, g, b, _ := c.RGBA()
	y := (299*(r>>8) + 587*(g>>8) + 114*(b>>8)) / 1000
	return uint8(y)
}

func sliderTileRect(bounds image.Rectangle, gridSize int, index int) image.Rectangle {
	w := bounds.Dx() / gridSize
	h := bounds.Dy() / gridSize
	col := index % gridSize
	row := index / gridSize
	return image.Rect(
		bounds.Min.X+col*w,
		bounds.Min.Y+row*h,
		bounds.Min.X+(col+1)*w,
		bounds.Min.Y+(row+1)*h,
	)
}

func pixelDiff(left color.Color, right color.Color) int64 {
	lr, lg, lb, _ := left.RGBA()
	rr, rg, rb, _ := right.RGBA()
	dr := int64(lr>>8) - int64(rr>>8)
	dg := int64(lg>>8) - int64(rg>>8)
	db := int64(lb>>8) - int64(rb>>8)
	if dr < 0 {
		dr = -dr
	}
	if dg < 0 {
		dg = -dg
	}
	if db < 0 {
		db = -db
	}
	return dr + dg + db
}

func generateSliderCursor(candidateIndex int, candidateCount int) string {
	return buildSliderCursor(candidateIndex, candidateCount)
}

func buildSliderCursor(candidateIndex int, candidateCount int) string {
	if candidateCount <= 0 {
		return "[]"
	}
	if candidateIndex < 1 {
		candidateIndex = 1
	}
	if candidateIndex > candidateCount {
		candidateIndex = candidateCount
	}

	type cursorPoint struct {
		X int `json:"x"`
		Y int `json:"y"`
	}

	// Mobile (Android) coordinates: the slider control sits in the lower third
	// of a ~360-412px-wide phone viewport. The thumb is dragged left→right, so
	// the target X is spread across the track by candidate index.
	startX := 40 + mathrand.Intn(30)  // 40-70
	startY := 640 + mathrand.Intn(30) // 640-670

	denom := candidateCount - 1
	if denom < 1 {
		denom = 1
	}
	baseTargetX := 70 + (330-70)*(candidateIndex-1)/denom
	targetX := baseTargetX + mathrand.Intn(10) - 5
	targetY := 648 + mathrand.Intn(14)

	points := make([]cursorPoint, 0, 28)

	// Initial hover near start position.
	for i := 0; i < 1+mathrand.Intn(3); i++ {
		points = append(points, cursorPoint{
			X: startX + mathrand.Intn(5) - 2,
			Y: startY + mathrand.Intn(5) - 2,
		})
	}

	// Quadratic Bézier arc from start to target.
	transitSteps := 2 + mathrand.Intn(3)
	arcOffX := mathrand.Intn(60) - 30
	arcOffY := -(mathrand.Intn(30) + 10)
	for i := 1; i <= transitSteps; i++ {
		t := float64(i) / float64(transitSteps+1)
		cx := float64(startX+targetX)/2 + float64(arcOffX)
		cy := float64(startY+targetY)/2 + float64(arcOffY)
		bx := (1-t)*(1-t)*float64(startX) + 2*t*(1-t)*cx + t*t*float64(targetX)
		by := (1-t)*(1-t)*float64(startY) + 2*t*(1-t)*cy + t*t*float64(targetY)
		jitter := int((1-t)*8) + 2
		points = append(points, cursorPoint{
			X: int(math.Round(bx)) + mathrand.Intn(jitter*2+1) - jitter,
			Y: int(math.Round(by)) + mathrand.Intn(jitter*2+1) - jitter,
		})
	}

	// Fine approach to target.
	approachSteps := 4 + mathrand.Intn(4)
	prev := points[len(points)-1]
	for i := 1; i <= approachSteps; i++ {
		t := float64(i) / float64(approachSteps)
		ax := prev.X + int(math.Round(t*float64(targetX-prev.X))) + mathrand.Intn(5) - 2
		ay := prev.Y + int(math.Round(t*float64(targetY-prev.Y))) + mathrand.Intn(5) - 2
		points = append(points, cursorPoint{X: ax, Y: ay})
	}

	// Settle at destination.
	settleCount := 3 + mathrand.Intn(5)
	for i := 0; i < settleCount; i++ {
		points = append(points, cursorPoint{
			X: targetX + mathrand.Intn(7) - 3,
			Y: targetY + mathrand.Intn(7) - 3,
		})
	}

	// Keep every point inside a phone viewport so Bézier/jitter overshoot can't
	// emit off-screen touch coordinates.
	for i := range points {
		points[i].X = clampInt(points[i].X, 8, 404)
		points[i].Y = clampInt(points[i].Y, 60, 850)
	}

	data, err := json.Marshal(points)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func trySliderCaptchaCandidates(
	candidates []sliderCandidate,
	maxAttempts int,
	check func(candidate sliderCandidate) (*captchaCheckResult, error),
) (string, error) {
	if len(candidates) == 0 {
		return "", fmt.Errorf("slider has no ranked candidates")
	}

	limit := minInt(maxAttempts, len(candidates))
	if limit <= 0 {
		return "", fmt.Errorf("slider has no attempts available")
	}

	for idx := 0; idx < limit; idx++ {
		result, err := check(candidates[idx])
		if err != nil {
			return "", err
		}

		switch result.Status {
		case "OK":
			if result.SuccessToken == "" {
				return "", fmt.Errorf("success_token not found")
			}
			return result.SuccessToken, nil
		case "ERROR_LIMIT":
			return "", errCaptchaRateLimit
		default:
			continue
		}
	}

	return "", fmt.Errorf("slider guesses exhausted")
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

func clampInt(value int, low int, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func describeCaptchaTypes(settingsByType map[string]string) string {
	if len(settingsByType) == 0 {
		return "none"
	}

	types := make([]string, 0, len(settingsByType))
	for captchaType := range settingsByType {
		types = append(types, captchaType)
	}
	sort.Strings(types)
	return strings.Join(types, ",")
}
