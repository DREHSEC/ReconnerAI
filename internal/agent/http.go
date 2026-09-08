package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/recon-platform/internal/scanner"
)

const (
	httpTimeout   = 20 * time.Second
	httpBodyCap   = 16384
	httpHeaderCap = 24
	maxRedirects  = 5
)

func newProbeClient() *http.Client {
	return newProbeClientWithTimeout(httpTimeout)
}

func newProbeClientWithTimeout(d time.Duration) *http.Client {
	if d <= 0 {
		d = httpTimeout
	}
	return &http.Client{
		Timeout: d,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   8 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 8 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // lab/bounty targets often have broken certs
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (t *Toolbox) listTargets(ctx context.Context) (any, error) {
	rows, err := t.db.QueryContext(ctx, `
		SELECT id, domain, COALESCE(name,''), COALESCE(kind,'web'), COALESCE(scan_status,'idle'), COALESCE(finding_count,0)
		FROM targets ORDER BY updated_at DESC LIMIT 80`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		ID           string `json:"id"`
		Domain       string `json:"domain"`
		Name         string `json:"name"`
		Kind         string `json:"kind"`
		ScanStatus   string `json:"scan_status"`
		FindingCount int    `json:"finding_count"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		if rows.Scan(&r.ID, &r.Domain, &r.Name, &r.Kind, &r.ScanStatus, &r.FindingCount) == nil {
			out = append(out, r)
		}
	}
	return map[string]any{"count": len(out), "targets": out}, nil
}

func (t *Toolbox) httpRequest(ctx context.Context, currentTarget, method, rawURL, body, contentType, identityLabel string, extra map[string]string, env ...CallEnv) (any, error) {
	var e CallEnv
	if len(env) > 0 {
		e = env[0]
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
	default:
		return nil, fmt.Errorf("unsupported method %s", method)
	}
	rawURL = strings.TrimSpace(rawURL)
	if err := t.ensureInEngagement(ctx, currentTarget, rawURL); err != nil {
		return nil, err
	}
	if why, ok := t.isSuppressed(ctx, currentTarget, rawURL, ""); ok {
		return nil, fmt.Errorf("suppressed (%s)", why)
	}
	host := hostOf(rawURL)
	if e.Mode == modeAlwaysOn {
		if err := t.limiter().allow(host); err != nil {
			return nil, err
		}
	}

	headers := map[string]string{}
	for k, v := range extra {
		if k == "" || v == "" {
			continue
		}
		headers[k] = v
	}
	usedIdentity := ""
	if identityLabel != "" {
		id, err := t.loadIdentity(ctx, currentTarget, identityLabel)
		if err != nil {
			return nil, err
		}
		usedIdentity = id.Label
		if id.UserAgent != "" {
			headers["User-Agent"] = id.UserAgent
		}
		for k, v := range id.Headers {
			headers[k] = v
		}
	}
	if headers["User-Agent"] == "" {
		headers["User-Agent"] = "Mozilla/5.0 (compatible; Reconner-Agent/1.0)"
	}
	if contentType != "" && headers["Content-Type"] == "" {
		headers["Content-Type"] = contentType
	}

	client := t.http
	if client == nil {
		client = newProbeClient()
	}

	type hop struct {
		URL     string            `json:"url"`
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body,omitempty"`
	}
	hops := []hop{}
	next := rawURL
	var lastBody string
	for i := 0; i <= maxRedirects; i++ {
		if err := t.ensureInEngagement(ctx, currentTarget, next); err != nil {
			return map[string]any{
				"error":         err.Error(),
				"stopped_at":    next,
				"identity":      usedIdentity,
				"hops":          hops,
				"redirect_stop": true,
			}, nil
		}
		var bodyReader io.Reader
		if i == 0 && body != "" && method != http.MethodGet && method != http.MethodHead {
			bodyReader = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, next, bodyReader)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}
		capN := t.bodyCap()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, int64(capN+1)))
		resp.Body.Close()
		truncated := len(b) > capN
		if truncated {
			b = b[:capN]
		}
		lastBody = string(b)
		hdrs := map[string]string{}
		n := 0
		for k, vs := range resp.Header {
			if n >= httpHeaderCap {
				break
			}
			if len(vs) == 0 {
				continue
			}
			hdrs[k] = clip(vs[0], 300)
			n++
		}
		hops = append(hops, hop{URL: next, Status: resp.StatusCode, Headers: hdrs, Body: lastBody})
		if e.Mode == modeAlwaysOn && (resp.StatusCode == 429 || resp.StatusCode == 503) {
			t.limiter().backoff(host, t.wafDur())
			t.suppress(ctx, currentTarget, "https://"+host, "", "waf", t.wafDur())
		}
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return map[string]any{
				"status":       resp.StatusCode,
				"url":          next,
				"identity":     usedIdentity,
				"truncated":    truncated,
				"content_type": resp.Header.Get("Content-Type"),
				"headers":      hdrs,
				"body":         lastBody,
				"hops":         hops,
			}, nil
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return map[string]any{
				"status": resp.StatusCode, "url": next, "identity": usedIdentity,
				"headers": hdrs, "body": lastBody, "hops": hops,
			}, nil
		}
		ref, err := resp.Request.URL.Parse(loc)
		if err != nil {
			return map[string]any{
				"status": resp.StatusCode, "url": next, "identity": usedIdentity,
				"headers": hdrs, "body": lastBody, "hops": hops, "redirect": loc,
			}, nil
		}
		next = ref.String()
		method = http.MethodGet
	}
	return map[string]any{"error": "too many redirects", "hops": hops, "identity": usedIdentity}, nil
}

func (t *Toolbox) diffIdentities(ctx context.Context, targetID, method, rawURL, labelA, labelB, body, contentType string, env ...CallEnv) (any, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("url is required")
	}
	probe := func(label string) (map[string]any, error) {
		label = strings.TrimSpace(label)
		idLabel := label
		if strings.EqualFold(label, "unauth") || strings.EqualFold(label, "unauthenticated") || label == "" {
			idLabel = ""
		}
		raw, err := t.httpRequest(ctx, targetID, method, rawURL, body, contentType, idLabel, nil, env...)
		if err != nil {
			return nil, err
		}
		m, _ := raw.(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		return m, nil
	}
	if labelA == "" && labelB == "" {
		labels := t.identityLabels(ctx, targetID)
		switch len(labels) {
		case 0:
			return nil, fmt.Errorf("diff_identities needs two identities (or pass identity_a/identity_b, using unauth for one side)")
		case 1:
			labelA, labelB = labels[0], "unauth"
		default:
			labelA, labelB = labels[0], labels[1]
		}
	} else {
		if labelA == "" {
			labelA = "unauth"
		}
		if labelB == "" {
			labelB = "unauth"
		}
	}
	a, err := probe(labelA)
	if err != nil {
		return nil, fmt.Errorf("identity A: %w", err)
	}
	b, err := probe(labelB)
	if err != nil {
		return nil, fmt.Errorf("identity B: %w", err)
	}
	abody := fmt.Sprint(a["body"])
	bbody := fmt.Sprint(b["body"])
	as := num(a["status"])
	bs := num(b["status"])
	alen, blen := len(abody), len(bbody)
	verdict := "similar"
	if as != bs || abs(alen-blen) > 80 || bodyHash(abody) != bodyHash(bbody) {
		verdict = "different — worth an authorization look"
	}
	return map[string]any{
		"url": rawURL, "method": method, "verdict": verdict,
		"a": map[string]any{"identity": labelA, "status": as, "body_len": alen, "body_hash": bodyHash(abody), "snippet": clip(abody, 160)},
		"b": map[string]any{"identity": labelB, "status": bs, "body_len": blen, "body_hash": bodyHash(bbody), "snippet": clip(bbody, 160)},
	}, nil
}

func bodyHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:8])
}

func (t *Toolbox) identityLabels(ctx context.Context, targetID string) []string {
	rows, err := t.db.QueryContext(ctx, `SELECT label FROM identities WHERE target_id=? ORDER BY is_baseline DESC, created_at ASC LIMIT 6`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var l string
		if rows.Scan(&l) == nil && l != "" {
			out = append(out, l)
		}
	}
	return out
}

func num(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	default:
		return 0
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func (t *Toolbox) loadIdentity(ctx context.Context, targetID, label string) (scanner.Identity, error) {
	ids := scanner.LoadIdentities(ctx, t.db, targetID, t.box)
	want := strings.ToLower(strings.TrimSpace(label))
	for _, id := range ids {
		if strings.EqualFold(id.Label, want) || id.ID == label {
			return id, nil
		}
	}
	return scanner.Identity{}, fmt.Errorf("identity %q not found on this target", label)
}

func (t *Toolbox) ensureInEngagement(ctx context.Context, targetID, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http/https URLs are allowed")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("invalid URL host")
	}
	if isMetadataHost(host) {
		return fmt.Errorf("cloud metadata endpoints are blocked")
	}
	if targetID != "" {
		var exc, inc string
		_ = t.db.QueryRowContext(ctx, `SELECT COALESCE(exclude_scope,''), COALESCE(include_scope,'') FROM targets WHERE id=?`, targetID).Scan(&exc, &inc)
		if err := CheckProgramScope(inc, exc, host); err != nil {
			return err
		}
	}
	ok, err := t.hostInEngagement(ctx, host, rawURL)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("url is not in scope of any Reconner target (add the host as a target or asset first)")
	}
	return nil
}

func isMetadataHost(host string) bool {
	switch host {
	case "169.254.169.254", "metadata.google.internal", "metadata", "fd00:ec2::254":
		return true
	}
	return false
}

func (t *Toolbox) hostInEngagement(ctx context.Context, host, rawURL string) (bool, error) {
	rows, err := t.db.QueryContext(ctx, `SELECT domain FROM targets`)
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var domain string
		if rows.Scan(&domain) != nil {
			continue
		}
		if hostMatchesScope(host, domain) || scanner.URLInScope(domain, nil, rawURL) {
			rows.Close()
			return true, nil
		}
	}
	rows.Close()

	if arows, err := t.db.QueryContext(ctx, `SELECT value FROM assets`); err == nil {
		for arows.Next() {
			var value string
			if arows.Scan(&value) != nil {
				continue
			}
			if hostMatchesScope(host, value) {
				arows.Close()
				return true, nil
			}
		}
		arows.Close()
	}
	if orows, err := t.db.QueryContext(ctx, `SELECT COALESCE(origin,'') FROM identities WHERE origin!=''`); err == nil {
		for orows.Next() {
			var origin string
			if orows.Scan(&origin) != nil {
				continue
			}
			if hostMatchesScope(host, origin) {
				orows.Close()
				return true, nil
			}
		}
		orows.Close()
	}
	if ip := net.ParseIP(host); ip != nil {
		var n int
		_ = t.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM subdomains WHERE ip=?`, host).Scan(&n)
		if n > 0 {
			return true, nil
		}
	}
	return false, nil
}

// hostMatchesScope reports whether host belongs to a stored target/asset value
// (domain, URL, IP, or CIDR). Unlike scanner.URLInScope this allows private/lab
// IPs — the agent runs inside the compose stack against authorized engagements.
func hostMatchesScope(host, scope string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	scope = strings.TrimSpace(scope)
	if host == "" || scope == "" {
		return false
	}
	if strings.Contains(scope, "://") {
		if u, err := url.Parse(scope); err == nil && u.Hostname() != "" {
			scope = u.Hostname()
		}
	}
	scope = strings.ToLower(strings.TrimSuffix(scope, "."))
	if i := strings.IndexByte(scope, '/'); i > 0 {
		if _, n, err := net.ParseCIDR(scope); err == nil {
			if ip := net.ParseIP(host); ip != nil && n.Contains(ip) {
				return true
			}
		}
		scope = scope[:i]
	}
	if strings.Contains(scope, ",") || strings.ContainsAny(scope, " \t") {
		for _, part := range strings.FieldsFunc(scope, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == ';' }) {
			if hostMatchesScope(host, part) {
				return true
			}
		}
		return false
	}
	if host == scope || strings.HasSuffix(host, "."+scope) {
		return true
	}
	return scanner.URLInScope(scope, nil, "https://"+host+"/")
}
