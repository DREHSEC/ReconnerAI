package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// Request replay (Phase 7). Takes an observed request and re-issues it under a
// chosen authentication context (unauthenticated / User A / User B / Admin),
// returning a normalized response so the Evidence Viewer can compare. Uses the
// shared HTTP client + AuthContext — NOT the browser. Researcher-triggered only;
// this never auto-mutates requests.

// ReplaySpec describes the request to replay.
type ReplaySpec struct {
	Method      string
	URL         string
	Body        string
	ContentType string
	// Headers are request-template headers captured from the browser/proxy. They
	// are filtered through replayHeaderAllowed before use. Identity headers are
	// applied afterwards and therefore refresh Cookie/Authorization when a bound
	// identity is available.
	Headers map[string][]string
}

// ReplayResult is one identity's replay outcome.
type ReplayResult struct {
	IdentityLabel string           `json:"identity_label"`
	Response      IdentityResponse `json:"-"`
	Status        int              `json:"status"`
	CT            string           `json:"content_type"`
	Len           int              `json:"length"`
	Body          string           `json:"body"`
	Verdict       string           `json:"verdict"`
	TimingMs      int64            `json:"timing_ms"`
}

// Replay issues spec as the given identity (nil = unauthenticated) and returns a
// redacted, classified result.
func Replay(ctx context.Context, spec ReplaySpec, id *Identity) ReplayResult {
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = "GET"
	}
	var bodyReader io.Reader
	if spec.Body != "" {
		bodyReader = strings.NewReader(spec.Body)
	}
	label := "unauthenticated"
	if id != nil {
		label = id.Label
	}
	req, err := http.NewRequestWithContext(ctx, method, spec.URL, bodyReader)
	if err != nil {
		return ReplayResult{IdentityLabel: label, Verdict: "error"}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner/1.0)")
	for name, values := range spec.Headers {
		if !replayHeaderAllowed(name) {
			continue
		}
		if !validHTTPHeaderName(name) {
			return ReplayResult{IdentityLabel: label, Verdict: "error", Body: "invalid captured header name"}
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") || len(value) > 16*1024 {
				return ReplayResult{IdentityLabel: label, Verdict: "error", Body: "invalid captured header: " + http.CanonicalHeaderKey(name)}
			}
			req.Header.Add(name, value)
		}
	}
	if spec.ContentType != "" {
		req.Header.Set("Content-Type", spec.ContentType)
	}
	if id != nil {
		if id.UserAgent != "" {
			req.Header.Set("User-Agent", id.UserAgent)
		}
		for k, v := range id.Headers {
			req.Header.Set(k, v)
		}
	}
	start := time.Now()
	resp, err := identityHTTPClient.Do(req)
	if err != nil {
		return ReplayResult{IdentityLabel: label, Verdict: "error"}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	ir := IdentityResponse{
		Status:  resp.StatusCode,
		CT:      resp.Header.Get("Content-Type"),
		NoSniff: strings.EqualFold(strings.TrimSpace(resp.Header.Get("X-Content-Type-Options")), "nosniff"),
		Body:    string(b),
		Len:     len(b),
	}

	verdict := "ambiguous"
	if looksLikeAuthObject(ir) {
		verdict = "authorized"
	} else if deniesAccess(ir) {
		verdict = "denied"
	}
	// Body shown in the viewer is truncated + redacted.
	shown := ir.Body
	if len(shown) > 4000 {
		shown = shown[:4000] + "\n…(truncated)"
	}
	return ReplayResult{
		IdentityLabel: label, Response: ir, Status: ir.Status, CT: ir.CT, Len: ir.Len,
		Body: RedactText(shown), Verdict: verdict, TimingMs: time.Since(start).Milliseconds(),
	}
}

func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		// RFC 9110 field-name = token (RFC 7230 tchar set).
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func replayHeaderAllowed(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "host", "content-length", "connection", "transfer-encoding", "proxy-authorization",
		"proxy-authenticate", "proxy-connection", "keep-alive", "te", "trailer", "upgrade",
		"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip":
		return false
	default:
		return true
	}
}

// ReplayAcrossIdentities replays a spec unauthenticated + as every identity and
// returns all results plus a cross-identity comparison summary.
func ReplayAcrossIdentities(ctx context.Context, spec ReplaySpec, ids []Identity) (results []ReplayResult, comparison string) {
	unauth := Replay(ctx, spec, nil)
	results = append(results, unauth)
	for i := range ids {
		results = append(results, Replay(ctx, spec, &ids[i]))
	}
	// Simple, honest summary: how many identities were authorized vs denied.
	var authd, denied int
	for _, r := range results[1:] {
		switch r.Verdict {
		case "authorized":
			authd++
		case "denied":
			denied++
		}
	}
	comparison = "unauth=" + results[0].Verdict + "; identities authorized=" + itoa(authd) + " denied=" + itoa(denied)
	return
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
