package agent

import (
	"context"
	"net/url"
	"regexp"
	"strings"
)

var httpURLRe = regexp.MustCompile(`https?://[^\s<>"'\)\]]+`)

func firstHTTPURL(text string) string {
	m := httpURLRe.FindString(text)
	m = strings.TrimRight(m, ".,;:)]}")
	if m == "" {
		return ""
	}
	u, err := url.Parse(m)
	if err != nil || u.Host == "" {
		return ""
	}
	return m
}

func leadTitleFromURL(raw, playbook string) string {
	u, err := url.Parse(raw)
	host := raw
	if err == nil && u.Host != "" {
		host = u.Host
		if p := strings.Trim(u.Path, "/"); p != "" {
			parts := strings.Split(p, "/")
			if n := parts[len(parts)-1]; n != "" && n != "callback" {
				host = host + " /" + n
			} else if n != "" {
				host = host + " /" + n
			}
		}
	}
	if playbook != "" {
		return clip(playbook+": "+host, 120)
	}
	return clip("Hunter lead: "+host, 120)
}

func summaryLooksEmpty(summary string) bool {
	s := strings.ToLower(strings.TrimSpace(summary))
	if len(s) < 40 {
		return true
	}
	for _, p := range []string{"cycle ok", "nothing to do", "nothing actionable", "no actionable"} {
		if s == p || strings.HasPrefix(s, p) && firstHTTPURL(summary) == "" {
			return true
		}
	}
	return false
}

// maybeFileLeadFromSummary files a pending operator lead when a hunter cycle
// described a concrete URL but never called flag_lead. Dedupes on pending URL.
func (t *Toolbox) maybeFileLeadFromSummary(ctx context.Context, targetID, summary, playbook string) (string, error) {
	if t == nil || t.db == nil {
		return "", nil
	}
	summary = strings.TrimSpace(summary)
	raw := firstHTTPURL(summary)
	if raw == "" || summaryLooksEmpty(summary) {
		return "", nil
	}
	low := strings.ToLower(summary)
	if strings.Contains(low, "iteration cap") || strings.Contains(low, "stopped at the iteration") {
		return "", nil
	}
	var existing string
	_ = t.db.QueryRowContext(ctx, `
		SELECT id FROM agent_leads WHERE target_id=? AND url=? AND status IN ('pending','confirmed')
		ORDER BY created_at DESC LIMIT 1`, targetID, raw).Scan(&existing)
	if existing != "" {
		return existing, nil
	}
	title := leadTitleFromURL(raw, playbook)
	res, err := t.flagLead(ctx, targetID, flagLeadArgs{
		Title:    title,
		Body:     clip(summary, 1200),
		Severity: "medium",
		URL:      raw,
		Method:   "GET",
		Evidence: clip(summary, 2000),
		Playbook: playbook,
	})
	if err != nil {
		return "", err
	}
	if m, ok := res.(map[string]any); ok {
		if id, _ := m["lead_id"].(string); id != "" {
			return id, nil
		}
	}
	return "", nil
}
