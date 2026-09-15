package scanner

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/recon-platform/internal/capture"
)

// GuidedOpportunity is a value-free, safe-to-display description of a likely
// test surface. Discovery never exposes captured parameter/header values; those
// remain sealed until the operator explicitly opens the request editor.
type GuidedOpportunity struct {
	Module     string   `json:"module"`
	Parameter  string   `json:"parameter"`
	Location   string   `json:"location"`
	Confidence int      `json:"confidence"`
	Reason     string   `json:"reason"`
	Payloads   []string `json:"payloads,omitempty"`
	Automated  bool     `json:"automated"`
}

// DiscoverGuidedOpportunities ranks parameter/module pairs from the immutable
// captured request. It is intentionally heuristic: the result is a test plan,
// never a vulnerability claim. Native guided analyzers still require response
// differentials or class-specific proof before reporting a hit.
func DiscoverGuidedOpportunities(r capture.Request) []GuidedOpportunity {
	var out []GuidedOpportunity
	seen := map[string]bool{}
	addOpportunity := func(module, parameter, location string, confidence int, reason string, automated bool, payloads ...string) {
		key := module + "\x00" + location + "\x00" + parameter
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, GuidedOpportunity{
			Module: module, Parameter: parameter, Location: location,
			Confidence: confidence, Reason: reason, Payloads: payloads,
			Automated: automated,
		})
	}
	add := func(module, parameter, location string, confidence int, reason string, payloads ...string) {
		addOpportunity(module, parameter, location, confidence, reason, guidedModuleAutomated(module), payloads...)
	}

	for _, point := range guidedPoints(r) {
		ip := point.ip
		name := guidedLeafName(ip.Param)
		value := strings.TrimSpace(ip.Value)
		textual := !looksNumericGuidedValue(value)

		if guidedNameHint(name, "id", "uuid", "user", "account", "profile", "customer", "tenant", "project", "team", "org", "order", "invoice", "document", "record", "object") || looksGuidedObjectID(value) {
			addOpportunity("idor", ip.Param, ip.Location, 88, "Object-like identifier; compare the owner baseline with a second authorized identity", looksGuidedObjectID(value), "{other-user-object-id}")
		}
		if guidedNameHint(name, "q", "query", "search", "filter", "sort", "where", "id", "user", "email", "name", "category", "status", "order") || looksNumericGuidedValue(value) {
			add("sqli", ip.Param, ip.Location, 78, "Database-shaped input; the analyzer uses error and paired boolean controls", "'", "' AND '1'='1'-- -", "' AND '1'='2'-- -")
		}
		if textual && guidedNameHint(name, "q", "query", "search", "name", "title", "message", "comment", "description", "content", "html", "text", "return", "callback") {
			add("xss", ip.Param, ip.Location, 80, "User-controlled text may reach an HTML/JavaScript rendering context", "rcn-xss-marker", `"><svg/onload=alert('reconner')>`)
		}
		if strings.Contains(strings.ToLower(r.MimeType), "json") && guidedNameHint(name, "filter", "query", "search", "where", "selector", "user", "email", "name", "id") {
			add("nosqli", ip.Param, ip.Location, 82, "JSON/query field may be interpreted as a document-database operator", `{"$ne":null}`, `{"$eq":"reconner-control"}`)
		}
		if guidedNameHint(name, "url", "uri", "host", "domain", "endpoint", "callback", "webhook", "avatar", "image", "feed", "proxy") || looksGuidedURL(value) {
			add("ssrf", ip.Param, ip.Location, 86, "URL-shaped server input; guided mode performs bounded in-band differentials", "https://reconner-callback.invalid/proof")
		}
		if guidedNameHint(name, "redirect", "redirecturl", "next", "return", "returnurl", "continue", "destination", "dest", "goto") {
			add("open_redirect", ip.Param, ip.Location, 91, "Navigation target parameter; verify an external Location without following it", "https://reconner-redirect.invalid/proof")
		}
		if guidedNameHint(name, "file", "filename", "path", "page", "template", "include", "folder", "dir", "download", "document") {
			add("lfi", ip.Param, ip.Location, 84, "File/path-shaped input; use a non-destructive differential before any manual proof", "../../reconner-guided-control.txt")
		}
		if textual && guidedNameHint(name, "template", "view", "name", "message", "subject", "content", "email", "format") {
			add("ssti", ip.Param, ip.Location, 68, "Text may be rendered by a server-side template engine", "{{7*7}}", "${7*7}")
		}
		if guidedNameHint(name, "cmd", "command", "exec", "shell", "ping", "lookup", "process") {
			add("cmdi", ip.Param, ip.Location, 72, "Command-like field; requires the separate explicit active-validation workflow", "reconner-control")
		}
	}

	if u, err := url.Parse(r.URL); err == nil {
		segments := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
		for i, raw := range segments {
			value, _ := url.PathUnescape(raw)
			if looksGuidedObjectID(value) {
				add("idor", "path["+strconv.Itoa(i)+"]", "path", 92, "Object identifier embedded in the route; test only with a known object owned by another test identity", "{other-user-object-id}")
			}
		}
	}

	method := strings.ToUpper(strings.TrimSpace(r.Method))
	credentialed := false
	for _, header := range r.Headers {
		name := strings.ToLower(strings.TrimSpace(header.Name))
		if name == "cookie" || name == "authorization" {
			credentialed = true
		}
		if name == "authorization" && strings.Count(header.Value, ".") == 2 {
			add("jwt", "Authorization", "header", 80, "Bearer value resembles a JWT; token-specific verification requires the identity workflow", "{alternate-test-identity-token}")
		}
	}
	if credentialed && (method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions) {
		add("cors", "Origin", "header", 76, "Credentialed read request; test unrelated Origins with paired response controls", "https://reconner-origin-a.invalid", "https://reconner-origin-b.invalid")
	}
	if credentialed && method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		add("csrf", "request", "request", 70, "Credentialed state-changing request; browser cookie semantics and a verified side effect require manual review")
	}
	if strings.Contains(strings.ToLower(r.MimeType), "xml") {
		add("xxe", "XML body", "body", 65, "XML request body detected; exact-template entity mutation is intentionally manual")
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return guidedModuleRank(out[i].Module) < guidedModuleRank(out[j].Module)
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Parameter < out[j].Parameter
	})
	return out
}

func guidedModuleAutomated(module string) bool {
	for _, known := range GuidedModules {
		if module == known {
			return true
		}
	}
	return false
}

func guidedModuleRank(module string) int {
	order := []string{"idor", "sqli", "xss", "nosqli", "ssrf", "open_redirect", "lfi", "ssti", "cors", "csrf", "jwt", "xxe", "cmdi"}
	for i, known := range order {
		if module == known {
			return i
		}
	}
	return len(order)
}

func guidedLeafName(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return strings.ReplaceAll(strings.ReplaceAll(name, "~1", "/"), "~0", "~")
}

func guidedNameHint(name string, hints ...string) bool {
	var words []string
	var current []rune
	runes := []rune(name)
	flush := func() {
		if len(current) > 0 {
			words = append(words, string(current))
			current = nil
		}
	}
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if len(current) > 0 && unicode.IsUpper(r) {
			previous := runes[i-1]
			nextIsLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(previous) || unicode.IsDigit(previous) || unicode.IsUpper(previous) && nextIsLower {
				flush()
			}
		}
		current = append(current, unicode.ToLower(r))
	}
	flush()
	compact := strings.Join(words, "")
	for _, hint := range hints {
		for _, word := range words {
			if word == hint {
				return true
			}
		}
		if compact == hint || strings.HasSuffix(compact, hint) && len(compact) <= len(hint)+10 {
			return true
		}
	}
	return false
}

func looksNumericGuidedValue(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksGuidedObjectID(value string) bool {
	value = strings.TrimSpace(value)
	if looksNumericGuidedValue(value) {
		return value != "0" && value != "1"
	}
	if len(value) == 36 && strings.Count(value, "-") == 4 {
		return true
	}
	if len(value) == 24 || len(value) >= 16 {
		digits := 0
		for _, r := range value {
			if unicode.IsDigit(r) {
				digits++
			}
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
				return false
			}
		}
		return digits > 0
	}
	return false
}

func looksGuidedURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}
