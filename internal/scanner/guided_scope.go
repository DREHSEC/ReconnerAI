package scanner

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/recon-platform/internal/database"
)

// Guided scans do not expand api.example.com to every sibling on example.com.
// Captures are admitted by the explicit project hosts, not identity origins.
func GuidedURLInScope(ctx context.Context, db *database.DB, targetID, raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || isBlockedHost(u.Hostname()) {
		return false
	}
	var domain, excluded string
	if db == nil || db.QueryRowContext(ctx, `SELECT domain,COALESCE(exclude_scope,'') FROM targets WHERE id=?`, targetID).Scan(&domain, &excluded) != nil {
		return false
	}
	host := normalizeHost(u.Hostname())
	if ParseExclusions(excluded).Excludes(host) {
		return false
	}
	hosts, _ := SplitScope(domain)
	for _, entry := range hosts {
		entry = strings.TrimSpace(entry)
		if strings.HasPrefix(strings.ToLower(entry), "http://") || strings.HasPrefix(strings.ToLower(entry), "https://") {
			if guidedURLSeedMatch(u, entry) {
				return true
			}
			continue
		}
		if _, network, err := net.ParseCIDR(strings.Trim(entry, "[]")); err == nil {
			if ip := net.ParseIP(host); ip != nil && network.Contains(ip) {
				return true
			}
			continue
		}
		h := hostOfURL(strings.TrimPrefix(entry, "*."))
		if h != "" && (host == h || strings.HasSuffix(host, "."+h)) {
			return true
		}
	}
	return false
}

// A URL target is a narrower contract than a hostname target. Guided capture
// preserves that contract by requiring the same scheme, effective port, exact
// host and endpoint-directory prefix. Plain hostname targets intentionally keep
// their existing subdomain-wide behavior.
func guidedURLSeedMatch(candidate *url.URL, rawSeed string) bool {
	seed, err := url.Parse(strings.TrimSpace(rawSeed))
	if err != nil || seed.User != nil || normalizeHost(seed.Hostname()) == "" {
		return false
	}
	if !strings.EqualFold(candidate.Scheme, seed.Scheme) ||
		normalizeHost(candidate.Hostname()) != normalizeHost(seed.Hostname()) ||
		effectiveHTTPPort(candidate) != effectiveHTTPPort(seed) {
		return false
	}
	prefix := seed.EscapedPath()
	if prefix == "" {
		prefix = "/"
	}
	if !strings.HasSuffix(prefix, "/") {
		if i := strings.LastIndexByte(prefix, '/'); i >= 0 {
			prefix = prefix[:i+1]
		} else {
			prefix = "/"
		}
	}
	path := candidate.EscapedPath()
	if path == "" {
		path = "/"
	}
	return strings.HasPrefix(path, prefix)
}

func effectiveHTTPPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return "443"
}
