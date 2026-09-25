package main

import (
	"context"
	"errors"
	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
	"io"
	"net/url"
	"strings"
	"testing"
)

type scriptedHTTPClient struct {
	tlsclient.HttpClient
	do func(*fhttp.Request) (*fhttp.Response, error)
}

func (c scriptedHTTPClient) Do(r *fhttp.Request) (*fhttp.Response, error) { return c.do(r) }
func jsonHTTP(body string) *fhttp.Response {
	return &fhttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}
}

func TestVKCallsMissingAnonymousTokenRetriesWholeFlow(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "recovers", false: "bounded"}[success], func(t *testing.T) {
			attempts, joins := 0, 0
			devices := map[string]bool{}
			client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
				q := r.URL.Query()
				method := q.Get("method")
				if method == "" {
					method = strings.TrimPrefix(r.URL.Path, "/method/")
				}
				switch method {
				case "auth.getAnonymToken":
					attempts++
					id := q.Get("device_id")
					if id == "" || devices[id] {
						t.Fatal("retry reused device identity")
					}
					devices[id] = true
					return jsonHTTP(`{"response":{"token":"anon"}}`), nil
				case "messages.getCallPreview":
					return jsonHTTP(`{"response":{"user_id":1,"secret":"secret"}}`), nil
				case "messages.getAnonymCallToken":
					return jsonHTTP(`{"response":{"token":"ok-token"}}`), nil
				case "auth.anonymLogin":
					return jsonHTTP(`{"session_key":"session"}`), nil
				case "vchat.joinConversationByLink":
					joins++
					if success && joins == 3 {
						return jsonHTTP(`{"turn_server":{"username":"u","credential":"p","urls":["turn:127.0.0.1:3478"]}}`), nil
					}
					return jsonHTTP(`{"error_code":100,"error_msg":"PARAM : error.webrtc.auth.anonym_token.not_found"}`), nil
				}
				t.Fatalf("unexpected method %s", method)
				return nil, nil
			}}
			u, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "test-link", client, Profile{})
			if attempts != 3 || joins != 3 {
				t.Fatalf("attempts=%d joins=%d", attempts, joins)
			}
			if success {
				if err != nil || u != "u" {
					t.Fatalf("recovery: %s %v", u, err)
				}
			} else if !isTransientVKCalls(err) {
				t.Fatalf("expected final transient failure: %v", err)
			}
		})
	}
}

// OK rejects a token minted a moment ago as either missing or expired; both
// are the same handoff race and retry the flow instead of opening a captcha.
func TestVKCallsFreshTokenRejectionsRetry(t *testing.T) {
	for _, msg := range []string{
		"PARAM : error.webrtc.auth.anonym_token.not_found",
		"PARAM : error.webrtc.auth.anonym_token.outdated",
	} {
		if !isTransientVKCalls(vkCallsOKError("join", map[string]interface{}{"error_code": float64(100), "error_msg": msg})) {
			t.Fatal(msg)
		}
	}
}

func TestVKCallsOtherOKErrorsDoNotRetry(t *testing.T) {
	for _, msg := range []string{"invalid link", "error.webrtc.auth.other"} {
		if isTransientVKCalls(vkCallsOKError("join", map[string]interface{}{"error_code": float64(100), "error_msg": msg})) {
			t.Fatal(msg)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	client := scriptedHTTPClient{do: func(*fhttp.Request) (*fhttp.Response, error) { calls++; cancel(); return nil, context.Canceled }}
	_, _, _, _, err := getVKCredsViaVKCalls(ctx, "link", client, Profile{})
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: calls=%d err=%v", calls, err)
	}
}

// The join link rides in every VK Calls query string, and the client returns a
// network failure as a url.Error carrying the full URL. The error reaches the
// log ("VK Calls flow failed"), so the URL is cut and the cause kept.
func TestVKCallsRequestErrorOmitsJoinLink(t *testing.T) {
	const link = "SECRETJOINLINKxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: errors.New("i/o timeout")}
	}}
	_, _, _, _, err := vkCallsAttempt(context.Background(), link, client, Profile{})
	if err == nil {
		t.Fatal("expected a request error")
	}
	if strings.Contains(err.Error(), "SECRETJOINLINK") || strings.Contains(err.Error(), "call%2Fjoin") {
		t.Fatalf("join link leaked: %v", err)
	}
	if !strings.Contains(err.Error(), "i/o timeout") || !isTransientVKCalls(err) {
		t.Fatalf("cause or transience lost: %v", err)
	}
}
