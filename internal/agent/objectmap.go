package agent

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/recon-platform/internal/database"
)

var (
	reUUIDPath = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	reHexPath  = regexp.MustCompile(`(?i)(?:/|=)[0-9a-f]{16,}`)
	reNumPath  = regexp.MustCompile(`/\d{2,}`)
	reEmail    = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
)

type pathBucket struct {
	Template string
	Hosts    map[string]int
	Params   map[string]int
	Example  string
	N        int
}

func templateURL(raw string) (host, tmpl string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if !strings.Contains(raw, "://") {
		if strings.HasPrefix(raw, "/") {
			raw = "https://placeholder.invalid" + raw
		} else if strings.Contains(raw, "/") {
			raw = "https://" + raw
		} else {
			return "", ""
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" && u.Path == "" {
		return "", ""
	}
	host = strings.ToLower(u.Hostname())
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	p = reUUIDPath.ReplaceAllString(p, "{id}")
	p = reEmail.ReplaceAllString(p, "{id}")
	p = reNumPath.ReplaceAllString(p, "/{id}")
	p = reHexPath.ReplaceAllStringFunc(p, func(s string) string {
		if strings.HasPrefix(s, "=") {
			return "={id}"
		}
		return "/{id}"
	})
	return host, strings.ToLower(p)
}

func collectPathBuckets(ctx context.Context, db *database.DB, targetID string) []*pathBucket {
	by := map[string]*pathBucket{}
	add := func(raw, param string) {
		host, tmpl := templateURL(raw)
		if tmpl == "" || tmpl == "/" {
			return
		}
		b := by[tmpl]
		if b == nil {
			b = &pathBucket{Template: tmpl, Hosts: map[string]int{}, Params: map[string]int{}, Example: clip(raw, 160)}
			by[tmpl] = b
		}
		b.N++
		if host != "" && host != "placeholder.invalid" {
			b.Hosts[host]++
		}
		if p := strings.TrimSpace(param); p != "" {
			b.Params[strings.ToLower(p)]++
		}
	}
	scanCol := func(q string, args ...any) {
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var u, p string
			n, _ := rows.Columns()
			if len(n) >= 2 {
				if rows.Scan(&u, &p) == nil {
					add(u, p)
				}
			} else {
				if rows.Scan(&u) == nil {
					add(u, "")
				}
			}
		}
	}
	scanCol(`SELECT url, parameter FROM parameters WHERE target_id=? AND (
		lower(parameter) LIKE '%user%' OR lower(parameter) LIKE '%account%' OR lower(parameter) LIKE '%org%'
		OR lower(parameter) LIKE '%tenant%' OR lower(parameter) LIKE '%order%' OR lower(parameter) LIKE '%uuid%'
		OR lower(parameter) LIKE '%role%' OR lower(parameter) LIKE '%member%' OR lower(parameter) LIKE '%id'
		OR url LIKE '%/api/%' OR url LIKE '%/v1/%' OR url LIKE '%/v2/%'
	) LIMIT 600`, targetID)
	scanCol(`SELECT value, '' FROM js_findings WHERE target_id=? AND lower(type) IN ('endpoint','url','graphql') LIMIT 300`, targetID)
	scanCol(`SELECT url, '' FROM http_services WHERE target_id=? AND (url LIKE '%/api/%' OR url LIKE '%/admin%' OR url LIKE '%graphql%' OR url LIKE '%/v1/%') LIMIT 300`, targetID)

	out := make([]*pathBucket, 0, len(by))
	for _, b := range by {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Hosts) != len(out[j].Hosts) {
			return len(out[i].Hosts) > len(out[j].Hosts)
		}
		return out[i].N > out[j].N
	})
	return out
}

func looksLikeResource(b *pathBucket) bool {
	if strings.Contains(b.Template, "{id}") {
		return true
	}
	for p := range b.Params {
		if strings.Contains(p, "id") || strings.Contains(p, "uuid") || strings.Contains(p, "user") ||
			strings.Contains(p, "account") || strings.Contains(p, "order") || strings.Contains(p, "tenant") {
			return true
		}
	}
	return strings.Contains(b.Template, "/users") || strings.Contains(b.Template, "/orders") ||
		strings.Contains(b.Template, "/accounts") || strings.Contains(b.Template, "/org")
}

func formatObjectMap(buckets []*pathBucket, limit int) []string {
	var lines []string
	for _, b := range buckets {
		if !looksLikeResource(b) {
			continue
		}
		hosts := keysByCount(b.Hosts, 4)
		params := keysByCount(b.Params, 5)
		line := fmt.Sprintf("%s  ×%d across %d host(s)", b.Template, b.N, len(b.Hosts))
		if len(params) > 0 {
			line += " params=" + strings.Join(params, ",")
		}
		if len(hosts) > 0 {
			line += " e.g. " + hosts[0]
		}
		lines = append(lines, line)
		if len(lines) >= limit {
			break
		}
	}
	return lines
}

func formatHostRhyme(buckets []*pathBucket, limitCommon, limitOdd int) (common, odd []string) {
	for _, b := range buckets {
		if len(b.Hosts) < 3 {
			continue
		}
		hosts := keysByCount(b.Hosts, 5)
		common = append(common, fmt.Sprintf("%s on %d hosts (%s)", b.Template, len(b.Hosts), strings.Join(hosts, ", ")))
		if len(common) >= limitCommon {
			break
		}
	}
	for _, b := range buckets {
		if len(b.Hosts) != 1 {
			continue
		}
		t := b.Template
		if !(strings.Contains(t, "admin") || strings.Contains(t, "internal") || strings.Contains(t, "graphql") ||
			strings.Contains(t, "debug") || strings.Contains(t, "console") || strings.Contains(t, "ops") ||
			strings.Contains(t, "nonprod") || strings.Contains(t, "swagger") || strings.Contains(t, "actuator")) {
			continue
		}
		host := keysByCount(b.Hosts, 1)
		h := ""
		if len(host) > 0 {
			h = host[0]
		}
		odd = append(odd, fmt.Sprintf("%s only on %s  e.g. %s", b.Template, h, clip(b.Example, 100)))
		if len(odd) >= limitOdd {
			break
		}
	}
	return common, odd
}

func keysByCount(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v != arr[j].v {
			return arr[i].v > arr[j].v
		}
		return arr[i].k < arr[j].k
	})
	if n > len(arr) {
		n = len(arr)
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = arr[i].k
	}
	return out
}

func watchtowerStory(ctx context.Context, db *database.DB, targetID string, limit int) []string {
	if limit <= 0 {
		limit = 12
	}
	rows, err := db.QueryContext(ctx, `
		SELECT change_type, SUBSTR(url,1,140), SUBSTR(COALESCE(old_value,''),1,400), SUBSTR(COALESCE(new_value,''),1,500), COALESCE(detected_at,'')
		FROM monitoring_changes WHERE target_id=? ORDER BY detected_at DESC LIMIT ?`, targetID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var typ, u, oldV, newV, at string
		if rows.Scan(&typ, &u, &oldV, &newV, &at) != nil {
			continue
		}
		line := typ + " " + u
		if oldV != "" || newV != "" {
			line += "\n    old: " + compactWS(oldV) + "\n    new: " + compactWS(newV)
		}
		out = append(out, line)
	}
	return out
}

func compactWS(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return clip(s, 360)
}

func (t *Toolbox) objectMap(ctx context.Context, targetID string) (any, error) {
	buckets := collectPathBuckets(ctx, t.db, targetID)
	lines := formatObjectMap(buckets, 40)
	return map[string]any{"count": len(lines), "objects": lines, "hint": "These are URL templates that look like user-owned resources. diff_identities on an instance; identities prove BOLA, the map is the hunt even without sessions."}, nil
}

func (t *Toolbox) hostRhyme(ctx context.Context, targetID string) (any, error) {
	buckets := collectPathBuckets(ctx, t.db, targetID)
	common, odd := formatHostRhyme(buckets, 20, 16)
	return map[string]any{"repeated": common, "singleton_odd": odd}, nil
}

func (t *Toolbox) watchtowerStoryTool(ctx context.Context, targetID string) (any, error) {
	lines := watchtowerStory(ctx, t.db, targetID, 16)
	if len(lines) == 0 {
		return map[string]any{"changes": []string{}, "hint": "No monitoring_changes. Turn Monitoring on for this project if you want drift to hunt."}, nil
	}
	return map[string]any{"changes": lines, "hint": "Ask: what new capability appeared? Probe that host/path, not a random XSS candidate."}, nil
}
