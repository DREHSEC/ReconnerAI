package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type replayRoundTripFunc func(*http.Request) (*http.Response, error)

func (f replayRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReplayCapturedHeadersAreFilteredAndIdentityWins(t *testing.T) {
	transport := replayRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-API-Version") != "2026-01" {
			t.Errorf("safe captured header missing: %q", r.Header.Get("X-API-Version"))
		}
		if r.Header.Get("Cookie") != "sid=fresh" {
			t.Errorf("identity did not override captured cookie: %q", r.Header.Get("Cookie"))
		}
		if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Connection") != "" {
			t.Errorf("unsafe transport/spoofing header survived: %#v", r.Header)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	})

	original := identityHTTPClient
	identityHTTPClient = &http.Client{Transport: transport}
	defer func() { identityHTTPClient = original }()
	result := Replay(context.Background(), ReplaySpec{
		Method: "GET", URL: "https://app.example.test/deep/route",
		Headers: map[string][]string{
			"X-API-Version": {"2026-01"}, "Cookie": {"sid=stale"},
			"X-Forwarded-For": {"127.0.0.1"}, "Connection": {"keep-alive"},
		},
	}, &Identity{Label: "User A", Headers: map[string]string{"Cookie": "sid=fresh"}})
	if result.Status != 200 || result.Verdict == "error" {
		t.Fatalf("unexpected replay result: %+v", result)
	}
}

func TestReplayRejectsMalformedCapturedHeadersBeforeNetwork(t *testing.T) {
	calls := 0
	transport := replayRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})
	original := identityHTTPClient
	identityHTTPClient = &http.Client{Transport: transport}
	defer func() { identityHTTPClient = original }()

	for name, headers := range map[string]map[string][]string{
		"bad_name":  {"Bad Header": {"value"}},
		"bad_value": {"X-Test": {"ok\r\nInjected: true"}},
	} {
		t.Run(name, func(t *testing.T) {
			result := Replay(context.Background(), ReplaySpec{URL: "https://app.example.test/", Headers: headers}, nil)
			if result.Verdict != "error" {
				t.Fatalf("malformed captured header was accepted: %+v", result)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("malformed headers reached the network %d times", calls)
	}
}
