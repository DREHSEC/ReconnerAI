package capture

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type PreviewItem struct {
	Sequence       int      `json:"sequence"`
	Method         string   `json:"method"`
	Route          string   `json:"route"`
	Status         int      `json:"status"`
	OperationKind  string   `json:"operation_kind"`
	Sensitive      bool     `json:"sensitive"`
	HeaderNames    []string `json:"header_names,omitempty"`
	RequestBytes   int      `json:"request_body_bytes"`
	ResponseBytes  int      `json:"response_body_bytes"`
	Accepted       bool     `json:"accepted"`
	RejectReason   string   `json:"reject_reason,omitempty"`
	SuggestedTests []string `json:"suggested_tests,omitempty"`
	AutoEligible   bool     `json:"auto_eligible"`
}

type Preview struct {
	Source         string        `json:"source"`
	Total          int           `json:"total"`
	Accepted       int           `json:"accepted"`
	Rejected       int           `json:"rejected"`
	Sensitive      int           `json:"sensitive"`
	ReadOnly       int           `json:"read_only"`
	StateChanging  int           `json:"state_changing"`
	Authentication int           `json:"authentication"`
	Unknown        int           `json:"unknown"`
	Items          []PreviewItem `json:"items"`
}

// BuildPreview applies scope admission and returns metadata only. Header/body
// values and query values are intentionally absent from the preview contract.
func BuildPreview(exchanges []Exchange, inScope func(string) bool) Preview {
	p := Preview{Items: make([]PreviewItem, 0, len(exchanges))}
	if len(exchanges) > 0 {
		p.Source = exchanges[0].Source
	}
	for _, ex := range exchanges {
		kind := OperationKind(ex.Request)
		sensitive := ContainsSensitiveMaterial(ex)
		item := PreviewItem{
			Sequence: ex.Sequence, Method: ex.Request.Method, Route: SafeDisplayURL(ex.Request.URL),
			Status: ex.Response.Status, OperationKind: kind, Sensitive: sensitive,
			HeaderNames: safeHeaderNames(ex.Request.Headers), RequestBytes: len(ex.Request.Body),
			ResponseBytes: len(ex.Response.Body), Accepted: inScope(ex.Request.URL),
			SuggestedTests: SuggestedTests(ex.Request),
		}
		item.AutoEligible = item.Accepted && SafeAutomaticReplay(ex.Request)
		p.Total++
		if item.Accepted {
			p.Accepted++
		} else {
			p.Rejected++
			item.RejectReason = "out_of_scope"
		}
		if sensitive {
			p.Sensitive++
		}
		switch kind {
		case "read_only", "query_like":
			p.ReadOnly++
		case "state_changing", "payment", "upload":
			p.StateChanging++
		case "authentication":
			p.Authentication++
		default:
			p.Unknown++
		}
		p.Items = append(p.Items, item)
	}
	return p
}

// A GET can still log out, delete or purchase. Both method and intent matter.
func SafeAutomaticReplay(r Request) bool {
	m := strings.ToUpper(r.Method)
	k := OperationKind(r)
	return (m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions) && (k == "read_only" || k == "query_like")
}

func SuggestedTests(r Request) []string {
	tests := map[string]bool{}
	u, _ := url.Parse(r.URL)
	lowerPath := strings.ToLower(u.Path)
	if len(u.Query()) > 0 || len(r.Body) > 0 {
		tests["xss"] = true
		tests["sqli"] = true
	}
	if strings.Contains(strings.ToLower(r.MimeType), "json") {
		tests["nosqli"] = true
	}
	for name := range u.Query() {
		lower := strings.ToLower(name)
		if containsAny(lower, "url", "uri", "host", "domain", "callback", "webhook", "redirect", "next", "return") {
			tests["ssrf"] = true
		}
		if containsAny(lower, "id", "uuid", "user", "account", "project", "order", "file", "document") {
			tests["idor_bola"] = true
		}
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	for _, segment := range segments {
		if looksLikeObjectID(segment) {
			tests["idor_bola"] = true
		}
	}
	if containsAny(lowerPath, "/admin", "/manage", "/role", "/permission", "/staff", "/internal") {
		tests["bac_bfla"] = true
	}
	if strings.Contains(lowerPath, "graphql") {
		tests["graphql_authz"] = true
	}
	out := make([]string, 0, len(tests))
	for test := range tests {
		out = append(out, test)
	}
	sort.Strings(out)
	return out
}

func looksLikeObjectID(s string) bool {
	if len(s) >= 16 {
		return true
	}
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func OperationKind(r Request) string {
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	lowerURL := strings.ToLower(r.URL)
	lowerBody := strings.ToLower(string(r.Body))
	if containsAny(lowerURL, "/login", "/logout", "/signin", "/signout", "/oauth", "/token", "/password", "/mfa") {
		return "authentication"
	}
	if containsAny(lowerURL, "/payment", "/checkout", "/purchase", "/billing") {
		return "payment"
	}
	if strings.Contains(strings.ToLower(r.MimeType), "multipart/form-data") || strings.Contains(lowerURL, "/upload") {
		return "upload"
	}
	if strings.Contains(strings.ToLower(r.MimeType), "json") && strings.Contains(lowerBody, "\"query\"") {
		if strings.Contains(lowerBody, "mutation") {
			return "state_changing"
		}
		return "query_like"
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "read_only"
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return "state_changing"
	default:
		return "unknown"
	}
}

func ContainsSensitiveMaterial(ex Exchange) bool {
	for _, h := range append(append([]Header{}, ex.Request.Headers...), ex.Response.Headers...) {
		name := strings.ToLower(h.Name)
		if name == "cookie" || name == "set-cookie" || name == "authorization" ||
			name == "proxy-authorization" || strings.Contains(name, "csrf") ||
			strings.Contains(name, "token") || strings.Contains(name, "api-key") {
			return true
		}
	}
	body := strings.ToLower(string(ex.Request.Body))
	return containsAny(body, "password=", "\"password\"", "access_token", "refresh_token", "api_key", "apikey")
}

func safeHeaderNames(headers []Header) []string {
	seen := map[string]bool{}
	for _, h := range headers {
		name := http.CanonicalHeaderKey(strings.TrimSpace(h.Name))
		if name != "" {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// SafeDisplayURL preserves the origin and path but replaces every query value.
// It is safe for ordinary metadata tables and API responses.
func SafeDisplayURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "[invalid-url]"
	}
	q := u.Query()
	for name, values := range q {
		masked := make([]string, len(values))
		for i := range masked {
			masked[i] = "{value}"
		}
		q[name] = masked
	}
	u.RawQuery = q.Encode()
	segments := strings.Split(u.EscapedPath(), "/")
	for i, segment := range segments {
		decoded, _ := url.PathUnescape(segment)
		previous := ""
		if i > 0 {
			previous, _ = url.PathUnescape(segments[i-1])
		}
		if sensitivePathValue(previous, decoded) {
			segments[i] = "%7Bsecret%7D"
		}
	}
	u.RawPath = strings.Join(segments, "/")
	u.Path, _ = url.PathUnescape(u.RawPath)
	u.Fragment = ""
	if u.User != nil {
		u.User = nil
	}
	return u.String()
}

func sensitivePathValue(previous, value string) bool {
	previous = strings.ToLower(previous)
	if containsAny(previous, "reset", "verify", "verification", "activate", "magic", "token", "callback") && value != "" {
		return true
	}
	if len(value) < 24 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func containsAny(s string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(s, value) {
			return true
		}
	}
	return false
}
