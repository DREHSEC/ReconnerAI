package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/recon-platform/internal/database"
)

const dossierCap = 120000 // ~30k tokens of ranked surface, not the whole recon graph

// buildSurfaceDossier is the hunter's working memory for one cycle.
// It is not a dump of 200k parameters. It is the interesting 1%: clusters,
// authz-shaped objects, JS-only APIs, odd hosts, leftovers, diffs, and what
// we already tried. Frontier context is spent on *judgment*, not pagination.
func buildSurfaceDossier(ctx context.Context, db *database.DB, targetID string, pb playbook) string {
	if db == nil || targetID == "" {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Surface dossier\n\nSuggested lane: **%s** (%s). You may leave this lane if a higher-impact class is sitting in the lists below. Do not spend this cycle re-listing XSS candidates.\n\n", pb.Name, pb.Reason)

	writeDossierCounts(&b, ctx, db, targetID)
	writeDossierSection(&b, "Recent hunter memory", dossierLines(ctx, db, `
		SELECT kind || ': ' || SUBSTR(content,1,220) FROM agent_hunter_notes
		WHERE target_id=? ORDER BY created_at DESC LIMIT 10`, targetID))
	writeDossierSection(&b, "Last cycles", dossierLines(ctx, db, `
		SELECT COALESCE(last_playbook,'') || ' — ' || SUBSTR(COALESCE(last_summary,''),1,280)
		FROM agent_hunter_state WHERE target_id=? AND COALESCE(last_summary,'')!=''`, targetID))
	writeDossierSection(&b, "Pending leads (already filed — do not repeat)", dossierLines(ctx, db, `
		SELECT COALESCE(severity,'') || ' ' || COALESCE(playbook,'') || ': ' || SUBSTR(title,1,140) || ' ' || SUBSTR(COALESCE(url,''),1,120)
		FROM agent_leads WHERE target_id=? AND status='pending' ORDER BY created_at DESC LIMIT 12`, targetID))
	writeDossierSection(&b, "Dead ends (do not re-probe)", dossierLines(ctx, db, `
		SELECT SUBSTR(url,1,140) || CASE WHEN parameter!='' THEN ' param='||parameter ELSE '' END
		FROM agent_hunter_suppress WHERE target_id=? AND until > datetime('now') ORDER BY until DESC LIMIT 16`, targetID))
	writeDossierSection(&b, "Candidate clusters (type × count — pick a *new* class, not another XSS row)", dossierLines(ctx, db, `
		SELECT type || ' ×' || COUNT(*) || ' e.g. ' || SUBSTR(MIN(url),1,100)
		FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='candidate'
		  AND COALESCE(triage,'') NOT IN ('confirmed','false_positive')
		GROUP BY type ORDER BY COUNT(*) DESC LIMIT 12`, targetID))
	writeDossierSection(&b, "Authz-shaped parameters (objects, not reflected XSS)", dossierLines(ctx, db, `
		SELECT DISTINCT COALESCE(method,'GET') || ' ' || SUBSTR(url,1,110) || '  ' || parameter
		FROM parameters WHERE target_id=? AND (
			lower(parameter) LIKE '%user%' OR lower(parameter) LIKE '%account%' OR lower(parameter) LIKE '%org%'
			OR lower(parameter) LIKE '%tenant%' OR lower(parameter) LIKE '%customer%' OR lower(parameter) LIKE '%order%'
			OR lower(parameter) LIKE '%uuid%' OR lower(parameter) LIKE '%role%' OR lower(parameter) LIKE '%member%'
			OR lower(parameter) LIKE '%owner%' OR lower(parameter) LIKE '%docid%' OR lower(parameter) LIKE '%object%'
		) LIMIT 24`, targetID))
	writeDossierSection(&b, "JS shadows (secrets / hidden APIs / graphql — not CDN junk)", dossierLines(ctx, db, `
		SELECT type || ' ' || SUBSTR(value,1,160) || '  ' || SUBSTR(COALESCE(context,''),1,80)
		FROM js_findings WHERE target_id=? AND lower(type) IN ('secret','apikey','endpoint','url','graphql','jwt','aws','token')
		ORDER BY CASE lower(type) WHEN 'secret' THEN 0 WHEN 'apikey' THEN 1 WHEN 'jwt' THEN 2 ELSE 3 END
		LIMIT 20`, targetID))
	writeDossierSection(&b, "Authorization hypotheses", dossierLines(ctx, db, `
		SELECT COALESCE(kind,'BOLA') || ' ' || COALESCE(action_verb,'READ') || ' ' || COALESCE(object_type,'') ||
			' via ' || SUBSTR(COALESCE(endpoint_template,''),1,120) || ' conf=' || COALESCE(confidence,0)
		FROM hypotheses WHERE target_id=? AND status IN ('HYPOTHESIS','TESTED')
		ORDER BY confidence DESC LIMIT 12`, targetID))
	buckets := collectPathBuckets(ctx, db, targetID)
	writeDossierSection(&b, "Object map (resource URL templates — BOLA candidates even without sessions)", formatObjectMap(buckets, 18))
	common, odd := formatHostRhyme(buckets, 12, 12)
	writeDossierSection(&b, "Cross-host rhyme (same path on many hosts)", common)
	writeDossierSection(&b, "Singleton odd paths (only one host — often the real one)", odd)
	writeDossierSection(&b, "Watchtower diffs (what *changed* — reason about new capability)", watchtowerStory(ctx, db, targetID, 12))
	writeDossierSection(&b, "Backup files", dossierLines(ctx, db, `
		SELECT SUBSTR(url,1,180) FROM backup_findings WHERE target_id=? LIMIT 8`, targetID))
	writeDossierSection(&b, "Admin / debug / graphql paths", dossierLines(ctx, db, `
		SELECT SUBSTR(url,1,180) FROM directory_findings WHERE target_id=? AND (
			lower(url) LIKE '%admin%' OR lower(url) LIKE '%debug%' OR lower(url) LIKE '%graphql%'
			OR lower(url) LIKE '%swagger%' OR lower(url) LIKE '%actuator%' OR lower(url) LIKE '%internal%'
			OR lower(url) LIKE '%console%' OR lower(url) LIKE '%.git%' OR lower(url) LIKE '%phpinfo%'
		) LIMIT 16`, targetID))
	writeDossierSection(&b, "Odd / internal-looking hosts (ops, int, nonprod, admin)", dossierLines(ctx, db, `
		SELECT subdomain || CASE WHEN ip!='' THEN ' '||ip ELSE '' END || CASE WHEN status_code>0 THEN ' HTTP '||status_code ELSE '' END
		FROM subdomains WHERE target_id=? AND is_alive=1 AND (
			subdomain LIKE '%.i.%' OR subdomain LIKE '%-int.%' OR subdomain LIKE '%int.%'
			OR subdomain LIKE '%ops.%' OR subdomain LIKE '%admin%' OR subdomain LIKE '%staging%'
			OR subdomain LIKE '%nonprod%' OR subdomain LIKE '%internal%' OR subdomain LIKE '%graphql%'
			OR subdomain LIKE '%debug%' OR subdomain LIKE '%.pdev.%'
		) ORDER BY subdomain LIMIT 28`, targetID))

	b.WriteString("\n## How to burn this cycle\n")
	b.WriteString("1. Form ONE thesis from the dossier (prefer authz objects, JS-only APIs, odd internal hosts, leftovers, watchtower diffs).\n")
	b.WriteString("2. Probe that thesis with http_request / diff_identities / exec / browser_open. Do not open 20 XSS candidates.\n")
	b.WriteString("3. flag_lead only if this is a *new class* or a *new host family*. Similar XSS/reflection leads will be rejected.\n")
	b.WriteString("4. remember(dead_end) anything boring. stop_hunt with what the next cycle should pick up.\n")

	out := b.String()
	if len(out) > dossierCap {
		out = out[:dossierCap] + "\n…dossier truncated\n"
	}
	return out
}

func writeDossierCounts(b *strings.Builder, ctx context.Context, db *database.DB, targetID string) {
	n := func(q string) int {
		var v int
		_ = db.QueryRowContext(ctx, q, targetID).Scan(&v)
		return v
	}
	fmt.Fprintf(b, "## Counts\nsubdomains=%d alive=%d params=%d reflected=%d js_findings=%d candidates=%d confirmed=%d hyps=%d backups=%d dirs=%d monitor=%d pending_leads=%d\n\n",
		n(`SELECT COUNT(*) FROM subdomains WHERE target_id=?`),
		n(`SELECT COUNT(*) FROM subdomains WHERE target_id=? AND is_alive=1`),
		n(`SELECT COUNT(*) FROM parameters WHERE target_id=?`),
		n(`SELECT COUNT(*) FROM parameters WHERE target_id=? AND is_reflected=1`),
		n(`SELECT COUNT(*) FROM js_findings WHERE target_id=?`),
		n(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='candidate'`),
		n(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='finding' AND COALESCE(triage,'')!='false_positive'`),
		n(`SELECT COUNT(*) FROM hypotheses WHERE target_id=?`),
		n(`SELECT COUNT(*) FROM backup_findings WHERE target_id=?`),
		n(`SELECT COUNT(*) FROM directory_findings WHERE target_id=?`),
		n(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`),
		n(`SELECT COUNT(*) FROM agent_leads WHERE target_id=? AND status='pending'`),
	)
}

func writeDossierSection(b *strings.Builder, title string, lines []string) {
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n", title)
	for _, ln := range lines {
		fmt.Fprintf(b, "- %s\n", ln)
	}
	b.WriteByte('\n')
}

func dossierLines(ctx context.Context, db *database.DB, q string, args ...any) []string {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func hunterCyclePrompt(ctx context.Context, db *database.DB, targetID string, pb playbook) string {
	var b strings.Builder
	b.WriteString(pb.Brief)
	b.WriteString("\n\n")
	b.WriteString(buildSurfaceDossier(ctx, db, targetID, pb))
	return b.String()
}

func hunterScanAllow(playbookMods []string, identityCount int) []string {
	seen := map[string]bool{}
	var out []string
	add := func(names ...string) {
		for _, n := range names {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	add(playbookMods...)
	add("verify", "exposure", "jwt", "js_endpoints", "backup_discovery")
	if identityCount >= 2 {
		add("idor", "authz")
	}
	return out
}

func looksLikeXSSNoise(title, body, playbook string) bool {
	hay := strings.ToLower(playbook + " " + title + " " + body)
	if strings.Contains(hay, "idor") || strings.Contains(hay, "bola") || strings.Contains(hay, "authz") {
		return false
	}
	if strings.Contains(hay, "graphql") || strings.Contains(hay, "jwt") || strings.Contains(hay, ".env") || strings.Contains(hay, "takeover") {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(playbook)) {
	case "reflection", "candidates":
		return true
	}
	return strings.Contains(hay, "xss") || strings.Contains(hay, "reflected")
}

func (t *Toolbox) rejectFloodLead(ctx context.Context, targetID string, a flagLeadArgs) error {
	if t == nil || t.db == nil || !looksLikeXSSNoise(a.Title, a.Body, a.Playbook) {
		return nil
	}
	var n int
	_ = t.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM agent_leads WHERE target_id=? AND status='pending' AND (
			lower(COALESCE(playbook,'')) IN ('candidates','reflection')
			OR lower(title) LIKE '%xss%' OR lower(body) LIKE '%reflected%'
		)`, targetID).Scan(&n)
	if n >= 6 {
		return fmt.Errorf("inbox already has %d XSS/reflection leads — hunt a different class from the dossier (authz object, JS-only API, leftover admin, odd internal host, watchtower diff)", n)
	}
	return nil
}
