package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/recon-platform/internal/database"
)

type playbook struct {
	Name        string
	Reason      string
	Brief       string
	ScanModules []string
}

func pickPlaybook(ctx context.Context, db *database.DB, targetID string) playbook {
	count := func(q string, args ...any) int {
		var n int
		_ = db.QueryRowContext(ctx, q, args...).Scan(&n)
		return n
	}
	var domain, name, kind string
	_ = db.QueryRowContext(ctx, `SELECT domain, COALESCE(name,''), COALESCE(kind,'web') FROM targets WHERE id=?`, targetID).
		Scan(&domain, &name, &kind)
	identities := count(`SELECT COUNT(*) FROM identities WHERE target_id=?`, targetID)
	idLabels := []string{}
	if rows, err := db.QueryContext(ctx, `SELECT label FROM identities WHERE target_id=? ORDER BY is_baseline DESC LIMIT 4`, targetID); err == nil {
		for rows.Next() {
			var l string
			if rows.Scan(&l) == nil && l != "" {
				idLabels = append(idLabels, l)
			}
		}
		rows.Close()
	}
	freshWatch := count(`SELECT COUNT(*) FROM monitoring_changes mc
		LEFT JOIN agent_hunter_state s ON s.target_id=mc.target_id
		WHERE mc.target_id=? AND mc.detected_at > COALESCE(s.last_run,'1970-01-01')`, targetID)
	reflected := countUnsuppressedReflected(ctx, db, targetID)
	hyps := count(`SELECT COUNT(*) FROM hypotheses WHERE target_id=? AND status IN ('HYPOTHESIS','TESTED')`, targetID)
	jsHits := count(`SELECT COUNT(*) FROM js_findings WHERE target_id=?`, targetID)
	cands := countInterestingCandidates(ctx, db, targetID)
	backups := count(`SELECT COUNT(*) FROM backup_findings WHERE target_id=?`, targetID)
	dirs := count(`SELECT COUNT(*) FROM directory_findings WHERE target_id=?`, targetID)
	confirmed := count(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='finding' AND COALESCE(triage,'')!='false_positive'`, targetID)
	var lastPlaybook, lastSummary string
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(last_playbook,''), COALESCE(last_summary,'') FROM agent_hunter_state WHERE target_id=?`, targetID).Scan(&lastPlaybook, &lastSummary)
	reflectionClosed := laneClosedInNotes(ctx, db, targetID, "reflection") || skipStaleLane("reflection", lastPlaybook, lastSummary)
	candidatesClosed := skipStaleLane("candidates", lastPlaybook, lastSummary)

	notes := []string{}
	if rows, err := db.QueryContext(ctx, `SELECT kind, SUBSTR(content,1,180) FROM agent_hunter_notes WHERE target_id=? ORDER BY created_at DESC LIMIT 8`, targetID); err == nil {
		for rows.Next() {
			var k, c string
			if rows.Scan(&k, &c) == nil {
				notes = append(notes, k+": "+c)
			}
		}
		rows.Close()
	}

	head := fmt.Sprintf("Target %s (%s, kind=%s). Identities=%d confirmed=%d candidates=%d reflected_params=%d js_findings=%d hypotheses=%d backups=%d dirs=%d watchtower_new=%d.",
		domain, name, kind, identities, confirmed, cands, reflected, jsHits, hyps, backups, dirs, freshWatch)
	if len(idLabels) > 0 {
		head += " Identity labels: " + strings.Join(idLabels, ", ") + ". For diff_identities omit labels to auto-pick the first two (or one vs unauth)."
	}
	if len(notes) > 0 {
		head += "\nHunter memory:\n- " + strings.Join(notes, "\n- ")
	}

	switch {
	case identities >= 2 && hyps > 0:
		return playbook{"authz", "two identities + untested hypotheses", head + "\n\nPLAYBOOK authz: list_hypotheses, pick the highest-confidence unread BOLA/IDOR, diff_identities on the object URL (include unauth). If a cross-user read works, flag_lead with evidence. start_scan is limited to [idor,authz] and only if those modules never finished. Do not skip the unauthenticated control.", []string{"idor", "authz"}}
	case identities >= 2:
		return playbook{"authz_surface", "two identities, no hypotheses yet", head + "\n\nPLAYBOOK authz_surface: interesting_params for id/uuid/user/order/account, then diff_identities on 2-4 of them vs unauth. flag_lead on a real boundary break. start_scan only [idor,authz] if coverage says they never ran.", []string{"idor", "authz"}}
	case freshWatch > 0:
		return playbook{"watchtower", "fresh monitor diffs", head + "\n\nPLAYBOOK watchtower: list_monitoring_changes, then http_request the new hosts/URLs (browser_open if the change is a JS-rendered app). remember(dead_end) anything boring. start_scan only [exposure,nuclei] if they never completed.", []string{"exposure", "nuclei"}}
	case cands > 0 && !candidatesClosed:
		return playbook{"candidates", "unproven candidates sitting in review", head + "\n\nPLAYBOOK candidates: inspect NON-XSS candidate types (ssrf, sqli, idor, jwt, exposure, backup). Do not page reflected-XSS. flag_lead only a new class. start_scan only [verify].", []string{"verify"}}
	case reflected > 0 && !reflectionClosed:
		return playbook{"reflection", "reflected parameters nobody finished", head + "\n\nPLAYBOOK reflection: interesting_params reflected_only. Probe redirect/url/next/file/path with http_request. remember(dead_end) encoded sinks. start_scan only [xss,open_redirect] if not already completed.", []string{"xss", "open_redirect"}}
	case jsHits > 0:
		return playbook{"js_shadow", "JS secrets and hidden endpoints", head + "\n\nPLAYBOOK js_shadow: list_js_findings. Hit undocumented API paths with http_request. Use browser_open for SPA-only routes http_request cannot render. Record secrets as leads, do not exfiltrate off-scope. start_scan only [js_endpoints,jwt] if missing.", []string{"js_endpoints", "jwt"}}
	case backups > 0 || dirs > 0:
		return playbook{"leftovers", "directories and backup files", head + "\n\nPLAYBOOK leftovers: http_request interesting leftover paths (.git, .env, dump, bak, phpinfo, actuator). start_scan only [backup_discovery,exposure] if never completed.", []string{"backup_discovery", "exposure"}}
	default:
		return playbook{"coverage", "fill gaps a one-shot scan left", head + "\n\nPLAYBOOK coverage: call coverage, probe 2-3 odd URLs by hand, then start_scan at most two missing high-signal modules from [http_probe,param_discovery,nuclei,exposure]. Do not enqueue xss/sqli from coverage — those need a reflection/candidate playbook.", []string{"http_probe", "param_discovery", "nuclei", "exposure"}}
	}
}

func countInterestingCandidates(ctx context.Context, db *database.DB, targetID string) int {
	if db == nil || targetID == "" {
		return 0
	}
	var n int
	_ = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM vuln_findings
		WHERE target_id=? AND COALESCE(status,'finding')='candidate'
		  AND lower(COALESCE(type,'')) NOT IN ('xss','open_redirect','vulnerable_js_library','csti')`, targetID).Scan(&n)
	return n
}

func countUnsuppressedReflected(ctx context.Context, db *database.DB, targetID string) int {
	if db == nil || targetID == "" {
		return 0
	}
	rows, err := db.QueryContext(ctx, `SELECT url FROM parameters WHERE target_id=? AND is_reflected=1`, targetID)
	if err != nil {
		return 0
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil || raw == "" {
			continue
		}
		var kind string
		err := db.QueryRowContext(ctx, `
			SELECT kind FROM agent_hunter_suppress
			WHERE target_id=? AND until > CURRENT_TIMESTAMP
			  AND (url=? OR url=?)
			ORDER BY until DESC LIMIT 1`, targetID, raw, hostOf(raw)).Scan(&kind)
		if err != nil {
			n++
		}
	}
	return n
}

func laneClosedInNotes(ctx context.Context, db *database.DB, targetID, lane string) bool {
	if db == nil || targetID == "" || lane == "" {
		return false
	}
	var n int
	_ = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM agent_hunter_notes
		WHERE target_id=? AND created_at > datetime('now','-2 days')
		  AND (lower(content) LIKE ? OR lower(content) LIKE ?)`,
		targetID, "%"+strings.ToLower(lane)+" lane closed%", "%lane closed for "+strings.ToLower(lane)+"%").Scan(&n)
	return n > 0
}

func skipStaleLane(name, lastPlaybook, lastSummary string) bool {
	if !strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(lastPlaybook)) {
		return false
	}
	s := strings.ToLower(lastSummary)
	return strings.Contains(s, "iteration cap") || strings.Contains(s, "lane closed")
}
