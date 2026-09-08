package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// ParsedScope is include/exclude host patterns from a bounty program dump.
type ParsedScope struct {
	Format  string   `json:"format"`
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// ParseProgramScope accepts HackerOne structured-scope JSON, Bugcrowd target JSON,
// or a plain newline/comma list of hosts and wildcards.
func ParseProgramScope(raw string) ParsedScope {
	raw = strings.TrimSpace(raw)
	out := ParsedScope{Format: "list", Include: []string{}, Exclude: []string{}}
	if raw == "" {
		return out
	}
	if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
		if p, ok := parseHackerOneScope(raw); ok {
			return p
		}
		if p, ok := parseBugcrowdScope(raw); ok {
			return p
		}
	}
	for _, line := range splitScopeLines(raw) {
		out.Include = append(out.Include, line)
	}
	out.Include = uniqLower(out.Include)
	return out
}

func parseHackerOneScope(raw string) (ParsedScope, bool) {
	data, ok := extractH1Items(raw)
	if !ok {
		return ParsedScope{}, false
	}
	out := ParsedScope{Format: "hackerone", Include: []string{}, Exclude: []string{}}
	hits := 0
	for _, item := range data {
		m, _ := item.(map[string]any)
		attrs, _ := m["attributes"].(map[string]any)
		if attrs == nil {
			attrs = m
		}
		if skipNonHostAsset(strField(attrs, "asset_type", "type")) {
			continue
		}
		ident := strField(attrs, "asset_identifier", "identifier", "asset_identifier_value")
		if ident == "" {
			continue
		}
		hits++
		if v, ok := attrs["eligible_for_submission"]; ok && !boolish(v) {
			out.Exclude = append(out.Exclude, ident)
			continue
		}
		out.Include = append(out.Include, ident)
	}
	if hits == 0 {
		// Structured H1 JSON with only non-host assets: still H1, empty include
		// (do not fall through to the line parser, which would ingest raw JSON).
		return out, true
	}
	out.Include = uniqLower(out.Include)
	out.Exclude = uniqLower(out.Exclude)
	return out, true
}

func extractH1Items(raw string) ([]any, bool) {
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return nil, false
	}
	if data, ok := root["data"].([]any); ok && looksLikeH1List(data) {
		return data, true
	}
	if dataObj, ok := root["data"].(map[string]any); ok {
		if items := structuredScopesFrom(dataObj); items != nil {
			return items, true
		}
	}
	if items := structuredScopesFrom(root); items != nil {
		return items, true
	}
	return nil, false
}

func structuredScopesFrom(obj map[string]any) []any {
	rel, _ := obj["relationships"].(map[string]any)
	if rel == nil {
		return nil
	}
	ss, _ := rel["structured_scopes"].(map[string]any)
	if ss == nil {
		return nil
	}
	data, _ := ss["data"].([]any)
	if data == nil {
		return nil
	}
	return data
}

func looksLikeH1List(data []any) bool {
	if len(data) == 0 {
		return false
	}
	for _, item := range data {
		m, _ := item.(map[string]any)
		if m == nil {
			continue
		}
		if _, ok := m["attributes"]; ok {
			return true
		}
		if strField(m, "asset_identifier", "identifier") != "" {
			return true
		}
	}
	return false
}

func skipNonHostAsset(assetType string) bool {
	t := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(assetType), "-", "_"))
	switch t {
	case "android_app", "ios_app", "windows_app", "source_code", "hardware", "ai_model", "other":
		return true
	}
	return false
}

func parseBugcrowdScope(raw string) (ParsedScope, bool) {
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		var arr []any
		if err2 := json.Unmarshal([]byte(raw), &arr); err2 != nil {
			return ParsedScope{}, false
		}
		root = map[string]any{"targets": arr}
	}
	targets, _ := root["targets"].([]any)
	if targets == nil {
		if bc, ok := root["bugcrowd"].(map[string]any); ok {
			targets, _ = bc["targets"].([]any)
		}
	}
	if targets == nil {
		return ParsedScope{}, false
	}
	out := ParsedScope{Format: "bugcrowd", Include: []string{}, Exclude: []string{}}
	hits := 0
	for _, item := range targets {
		m, _ := item.(map[string]any)
		ident := strField(m, "uri", "name", "target", "address")
		if ident == "" {
			continue
		}
		hits++
		cat := strings.ToLower(strField(m, "category", "target_category"))
		if skipNonHostAsset(cat) {
			continue
		}
		if boolish(m["ineligible"]) || cat == "out_of_scope" || cat == "out-of-scope" {
			out.Exclude = append(out.Exclude, ident)
			continue
		}
		out.Include = append(out.Include, ident)
	}
	if hits == 0 {
		return ParsedScope{}, false
	}
	out.Include = uniqLower(out.Include)
	out.Exclude = uniqLower(out.Exclude)
	return out, true
}

func splitScopeLines(raw string) []string {
	repl := strings.NewReplacer(",", "\n", ";", "\n")
	raw = repl.Replace(raw)
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func strField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			s := strings.TrimSpace(fmtString(v))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func fmtString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}

func boolish(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	default:
		return false
	}
}

func uniqLower(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "https://")
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimSuffix(s, "/")
		s = strings.ToLower(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func joinScope(items []string) string {
	return strings.Join(items, "\n")
}

func splitStoredScope(raw string) []string {
	return uniqLower(splitScopeLines(raw))
}

// hostInPatterns reports whether host matches any imported program-scope pattern.
// Patterns are exact hosts, subdomains of that host, *.wildcard, or CIDR — not
// "same eTLD+1" sibling matching (admin.example.com must not match api.example.com).
func hostInPatterns(host string, patterns []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if strings.Contains(p, "://") {
			if u, err := netURLParse(p); err == nil && u != "" {
				p = u
			}
		}
		if i := strings.IndexByte(p, '/'); i > 0 {
			if _, n, err := net.ParseCIDR(p); err == nil {
				if ip := net.ParseIP(host); ip != nil && n.Contains(ip) {
					return true
				}
			}
			p = p[:i]
		}
		if strings.HasPrefix(p, "*.") {
			base := strings.TrimPrefix(p, "*.")
			if host == base || strings.HasSuffix(host, "."+base) {
				return true
			}
			continue
		}
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

func netURLParse(raw string) (string, error) {
	// local helper so scope.go does not import net/url solely for Hostname()
	// if the pattern is already a URL; uniqLower already strips schemes for stored rows.
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty host")
	}
	return raw, nil
}

// CheckProgramScope applies imported include/exclude host lists. Empty include
// means "no extra include restriction" (engagement union still applies).
func CheckProgramScope(includeRaw, excludeRaw, host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return fmt.Errorf("invalid URL host")
	}
	if hostInPatterns(host, splitStoredScope(excludeRaw)) {
		return fmt.Errorf("url is excluded by this target's program scope")
	}
	if strings.TrimSpace(includeRaw) != "" && !hostInPatterns(host, splitStoredScope(includeRaw)) {
		return fmt.Errorf("url is outside this target's imported program scope")
	}
	return nil
}
