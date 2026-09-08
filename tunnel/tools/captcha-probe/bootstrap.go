package main

// Mirror of parseCaptchaBootstrapHTML from tunnel/tools/libwg-go/slider_captcha.go
// so the probe reports exactly what production's parser sees.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var reCaptchaScriptSrc = regexp.MustCompile(`src="(https://[^"]+not_robot_captcha[^"]+)"`)

type captchaSettingsResponse struct {
	ShowCaptchaType string
	SettingsByType  map[string]string
}

type captchaBootstrap struct {
	PowInput   string
	Difficulty int
	Settings   *captchaSettingsResponse
	ScriptURL  string
	PowV2      bool
}

var (
	reLegacyPowInput = regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	reInlineScript   = regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
	rePowV2Args      = regexp.MustCompile(`\}\s*\(\s*"([^"]+)"\s*,\s*(\d+)\s*,\s*"[^"]*"\s*\){1,2}\s*;?\s*$`)
)

func parseCaptchaBootstrapHTML(html string) (*captchaBootstrap, error) {
	bootstrap := &captchaBootstrap{Difficulty: 2}

	for _, scriptMatch := range reInlineScript.FindAllStringSubmatch(html, -1) {
		script := scriptMatch[1]
		if !strings.Contains(script, "captchaPowResult") {
			continue
		}
		if args := rePowV2Args.FindStringSubmatch(script); len(args) >= 3 {
			bootstrap.PowInput = args[1]
			bootstrap.PowV2 = true
			if parsed, err := strconv.Atoi(args[2]); err == nil && parsed > 0 {
				bootstrap.Difficulty = parsed
			}
		}
		break
	}

	if !bootstrap.PowV2 {
		if match := reLegacyPowInput.FindStringSubmatch(html); len(match) >= 2 {
			bootstrap.PowInput = match[1]
		}
	}

	if bootstrap.PowInput == "" {
		return nil, fmt.Errorf("powInput not found in captcha HTML")
	}

	if !bootstrap.PowV2 {
		for _, expr := range []*regexp.Regexp{
			regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`),
			regexp.MustCompile(`const\s+difficulty\s*=\s*(\d+)`),
		} {
			if match := expr.FindStringSubmatch(html); len(match) >= 2 {
				if parsed, err := strconv.Atoi(match[1]); err == nil {
					bootstrap.Difficulty = parsed
					break
				}
			}
		}
	}

	settings, err := parseCaptchaSettingsFromHTML(html)
	if err != nil {
		return nil, err
	}
	bootstrap.Settings = settings

	if m := reCaptchaScriptSrc.FindStringSubmatch(html); len(m) >= 2 {
		bootstrap.ScriptURL = m[1]
	}

	return bootstrap, nil
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
