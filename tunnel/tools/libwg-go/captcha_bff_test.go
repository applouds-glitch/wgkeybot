package main

import (
	"context"
	"errors"
	fhttp "github.com/bogdanfinn/fhttp"
	"io"
	"net/url"
	"strings"
	"testing"
)

func TestCaptchaBFFBootstrapMetadataIsBoundedToVKGlobal(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc"
	page := `<script>window.vk = {api: '{"nested":"}"}', lang: 3, renamed_key: "` + id + `"}; window.lang={foo:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}; const powInput = "challenge";</script>`
	got, err := parseCaptchaBootstrapHTML(page)
	if err != nil || !got.IsBFF || got.DebugInfo != id || got.Lang != "3" {
		t.Fatalf("bootstrap=%+v err=%v", got, err)
	}
	old, err := parseCaptchaBootstrapHTML(`<script>const powInput = "challenge"; window.lang={foo:"` + id + `"};</script>`)
	if err != nil || old.IsBFF || old.DebugInfo != "" {
		t.Fatalf("legacy=%+v err=%v", old, err)
	}
	if block := captchaVKGlobal(`window.vk={key:"unterminated`); block != "" {
		t.Fatal("accepted malformed block")
	}
}

func TestCaptchaBFFSessionSequenceAndCheckFields(t *testing.T) {
	var methods []string
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		method := strings.TrimPrefix(r.URL.Path, "/method/")
		methods = append(methods, method)
		raw, _ := io.ReadAll(r.Body)
		values, err := url.ParseQuery(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		if values.Get("session_token") != "session" || values.Get("domain") != "vk.ru" {
			t.Fatal("session changed")
		}
		switch method {
		case "captchaNotRobot.initSession":
			if string(raw) != "session_token=session&domain=vk.ru&lang=3&access_token=" {
				t.Fatalf("init body: %s", raw)
			}
			return jsonHTTP(`{"response":{"show_captcha_type":"slider","content_settings":[{"type":"slider","settings_key":"opaque-key","settings":"stale"}]}}`), nil
		case "captchaNotRobot.settings":
			return jsonHTTP(`{"response":{"captcha_settings":[]}}`), nil
		case "captchaNotRobot.componentDone":
			return jsonHTTP(`{"response":{"status":"OK"}}`), nil
		case "captchaNotRobot.check":
			if values.Get("debug_info") != "page-uuid" || values.Has("connectionRtt") || values.Has("connectionDownlink") {
				t.Fatalf("BFF fields mismatch")
			}
			return jsonHTTP(`{"response":{"status":"BOT"}}`), nil
		case "captchaNotRobot.getContent":
			if values.Get("captcha_settings") != "opaque-key" {
				t.Fatalf("lost initSession settings_key: %s", values.Get("captcha_settings"))
			}
			return jsonHTTP(`{"response":{"status":"ERROR_LIMIT"}}`), nil
		}
		t.Fatalf("unexpected request %s", method)
		return nil, nil
	}}
	_, err := callCaptchaNotRobotWithSliderPOC(context.Background(), "session", "hash", "page-uuid", 0, client, Profile{}, nil, captchaEndpointsFromRedirectURI("https://vk.ru/captcha"), &captchaBootstrap{IsBFF: true, Lang: "3"})
	if !errors.Is(err, errCaptchaRateLimit) {
		t.Fatalf("expected getContent limit: %v", err)
	}
	want := "captchaNotRobot.initSession,captchaNotRobot.settings,captchaNotRobot.componentDone,captchaNotRobot.check,captchaNotRobot.getContent"
	if strings.Join(methods, ",") != want {
		t.Fatalf("sequence: %v", methods)
	}
}

func TestCaptchaInitSessionRejectsErrorAndLegacyKeepsNetworkFields(t *testing.T) {
	for _, body := range []string{`{"error":{"error_code":100}}`, `{"response":{"status":"ERROR_LIMIT"}}`} {
		client := scriptedHTTPClient{do: func(*fhttp.Request) (*fhttp.Response, error) { return jsonHTTP(body), nil }}
		s := newCaptchaNotRobotSession(context.Background(), "token", captchaEndpointsFromRedirectURI("https://vk.com/captcha"), "hash", "debug", 0, client, Profile{})
		if _, err := s.requestInitSession(""); err == nil {
			t.Fatal("accepted initSession failure")
		}
	}
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(raw))
		if !v.Has("connectionRtt") || !v.Has("connectionDownlink") {
			t.Fatal("legacy check fields removed")
		}
		return jsonHTTP(`{"response":{"status":"OK","success_token":"ok"}}`), nil
	}}
	s := newCaptchaNotRobotSession(context.Background(), "token", captchaEndpointsFromRedirectURI("https://vk.com/captcha"), "hash", "debug", 0, client, Profile{})
	if _, err := s.requestCheckboxCheck(); err != nil {
		t.Fatal(err)
	}
}
