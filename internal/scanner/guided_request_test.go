package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/recon-platform/internal/capture"
)

func TestGuidedInjectionPreservesQueryAndFormSiblings(t *testing.T) {
	request := capture.Request{
		Method:   http.MethodPost,
		URL:      "https://app.example.test/search?q=first&q=second&keep=query",
		MimeType: "application/x-www-form-urlencoded",
		Body:     []byte("name=old&keep=body"),
	}
	points := guidedPoints(request)
	g := &guidedContext{request: request, points: points}
	ctx := context.WithValue(context.Background(), guidedContextKey{}, g)

	var secondQuery, form insertionPoint
	for _, point := range points {
		if point.ip.Location == "query" && point.ip.Param == "q" && point.occurrence == 1 {
			secondQuery = point.ip
		}
		if point.ip.Location == "body" && point.ip.Param == "name" {
			form = point.ip
		}
	}
	req, err := g.injected(ctx, secondQuery, "changed & exact", "")
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.RawQuery != "q=first&q=changed+%26+exact&keep=query" {
		t.Fatalf("query siblings or occurrence changed: %s", req.URL.RawQuery)
	}
	req, err = g.injected(ctx, form, "new value", "")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "name=new+value&keep=body" || req.URL.RawQuery != "q=first&q=second&keep=query" {
		t.Fatalf("form mutation changed siblings: url=%s body=%s", req.URL, body)
	}
}

func TestGuidedJSONInjectionPreservesTypesAndTargetsExactPath(t *testing.T) {
	request := capture.Request{
		Method:   http.MethodPost,
		URL:      "https://app.example.test/graphql",
		MimeType: "application/json",
		Body:     []byte(`{"user":{"id":7,"active":true},"items":[{"id":"a"},{"id":"b"}]}`),
	}
	points := guidedPoints(request)
	g := &guidedContext{request: request, points: points}
	ctx := context.WithValue(context.Background(), guidedContextKey{}, g)
	var target insertionPoint
	for _, point := range points {
		if point.ip.Param == "/items/1/id" {
			target = point.ip
		}
	}
	req, err := g.injected(ctx, target, "proof", "ne")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	user := got["user"].(map[string]any)
	items := got["items"].([]any)
	if user["id"].(float64) != 7 || user["active"] != true || items[0].(map[string]any)["id"] != "a" {
		t.Fatalf("unrelated JSON values changed: %#v", got)
	}
	operator := items[1].(map[string]any)["id"].(map[string]any)
	if operator["ne"] != "proof" {
		t.Fatalf("exact JSON path was not replaced: %#v", got)
	}
}

func TestGuidedRoundTripCannotEscapeTemplate(t *testing.T) {
	base := capture.Request{Method: http.MethodGet, URL: "https://app.example.test/orders?id=1"}
	g := &guidedContext{request: base, transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})}
	for _, tc := range []struct {
		method string
		rawURL string
	}{
		{http.MethodPost, base.URL},
		{http.MethodGet, "https://evil.invalid/orders?id=1"},
		{http.MethodGet, "https://app.example.test/admin?id=1"},
	} {
		req, _ := http.NewRequestWithContext(context.Background(), tc.method, tc.rawURL, nil)
		if _, err := g.roundTrip(req); err == nil {
			t.Fatalf("guided request escaped template: %s %s", tc.method, tc.rawURL)
		}
	}
	allowed, _ := url.Parse("https://app.example.test/orders?id=mutated")
	req := &http.Request{Method: http.MethodGet, URL: allowed, Header: make(http.Header), Body: http.NoBody}
	if _, err := g.roundTrip(req); err != nil {
		t.Fatalf("query-only mutation was blocked: %v", err)
	}
}

func TestGuidedRoundTripAllowsOnlyDiscoveredObjectPathMutation(t *testing.T) {
	base := capture.Request{Method: http.MethodGet, URL: "https://app.example.test/orders/12345/details?view=full"}
	g := &guidedContext{request: base, points: guidedIDORPoints(base), transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})}
	for _, rawURL := range []string{
		"https://app.example.test/orders/12346/details?view=full",
		"https://app.example.test/orders/12344/details?view=changed",
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
		if _, err := g.roundTrip(req); err != nil {
			t.Fatalf("discovered object path mutation was blocked: %s: %v", rawURL, err)
		}
	}
	for _, rawURL := range []string{
		"https://app.example.test/accounts/12346/details?view=full",
		"https://app.example.test/orders/12346/summary?view=full",
		"https://app.example.test/orders/../details?view=full",
		"https://app.example.test/orders/12346/extra/details?view=full",
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
		if _, err := g.roundTrip(req); err == nil {
			t.Fatalf("non-object or unrelated path mutation escaped template: %s", rawURL)
		}
	}
}
