package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scheduler"
	"github.com/recon-platform/internal/secret"
)

const (
	rowCap    = 40
	fieldCap  = 400
	resultCap = 24000
)

// ScanStarter enqueues a planned module list. *scheduler.Scheduler implements this.
type ScanStarter interface {
	CreateTask(targetID string, modules []string, priority int) (*models.Task, error)
}

// Toolbox dispatches allowlisted tools bound to one target.
type Toolbox struct {
	db        *database.DB
	sched     ScanStarter
	box       *secret.Box
	http      *http.Client
	limit     *hostLimiter
	limitOnce sync.Once
	cfg       *config.Config
	browsers  map[string]*browserSession
	browserMu sync.Mutex
}

func NewToolbox(db *database.DB, sched ScanStarter, box *secret.Box) *Toolbox {
	return &Toolbox{db: db, sched: sched, box: box, http: newProbeClient()}
}

func toolDefs(includeStop bool) []ToolDef {
	return toolDefsFor(includeStop, true, true)
}

func toolDefsFor(includeStop, includeExec, includeBrowser bool) []ToolDef {
	defs := []ToolDef{
		fn("target_brief", "Summary of the target: scope, scan status, identity count (not secrets), tech/WAF rollup, and counts of hosts, params, findings, candidates, nuclei, monitor diffs.", objectSchema(nil)),
		fn("surface_dossier", "Ranked interesting 1% of the recon graph: candidate clusters, authz-shaped objects, JS-only APIs, odd internal hosts, leftovers, watchtower diffs, dead ends, hunter memory. Use this instead of paging list_candidates. Large on purpose.", objectSchema(nil)),
		fn("object_map", "URL templates that look like user-owned resources (/{id}/orders, accountId, tenant). The BOLA map even without identities. Identities later prove it.", objectSchema(nil)),
		fn("host_rhyme", "Same path template across many hosts, plus singleton odd paths (admin/graphql/internal) that appear on only one host.", objectSchema(nil)),
		fn("watchtower_story", "Recent monitoring diffs with old→new snippets. Reason about what capability appeared. Empty if Monitoring is off.", objectSchema(nil)),
		fn("list_findings", "Confirmed vulnerability findings (status=finding). Filter by type or severity.", objectSchema(map[string]any{
			"type":     strProp("Vulnerability class, e.g. xss, sqli, ssrf"),
			"severity": strProp("critical|high|medium|low|info"),
		})),
		fn("list_candidates", "Unconfirmed candidates that need review, plus a nuclei summary.", objectSchema(map[string]any{
			"type": strProp("Optional vulnerability class filter"),
		})),
		fn("inspect_finding", "One finding (confirmed or candidate) plus truncated evidence.", objectSchema(map[string]any{
			"finding_id": strProp("Finding id from list_findings / list_candidates"),
		}, "finding_id")),
		fn("list_parameters", "Discovered parameters. Prefer reflected_only=true for XSS/injection leads.", objectSchema(map[string]any{
			"reflected_only": map[string]any{"type": "boolean", "description": "Only reflected parameters"},
			"query":          strProp("Substring match on parameter name or URL"),
		})),
		fn("list_js_findings", "Secrets, endpoints and other JS analysis hits.", objectSchema(map[string]any{
			"type": strProp("Optional type filter, e.g. secret, endpoint, apikey"),
		})),
		fn("list_hypotheses", "Ranked authorization hypotheses (BOLA/IDOR/BFLA). Not findings until verified.", objectSchema(nil)),
		fn("list_monitoring_changes", "Watchtower diffs: new hosts, header/JS/title changes.", objectSchema(nil)),
		fn("search_surface", "Substring search across live URLs, parameters and JS file URLs.", objectSchema(map[string]any{
			"query": strProp("Substring to search"),
		}, "query")),
		fn("scan_status", "Running and pending scan tasks for this target.", objectSchema(nil)),
		fn("list_targets", "All Reconner targets in this deployment (domain, kind, scan status, finding counts). Use before probing another host.", objectSchema(nil)),
		fn("http_request", "Send an HTTP request to an in-scope host. Scope is the union of every Reconner target, asset and identity origin — not the open internet. Optional identity_label replays that target's captured session headers. Follows in-scope redirects.", objectSchema(map[string]any{
			"method":         strProp("GET (default), POST, PUT, PATCH, DELETE, HEAD, OPTIONS"),
			"url":            strProp("Absolute http/https URL"),
			"headers":        map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "Extra request headers"},
			"body":           strProp("Request body for POST/PUT/PATCH"),
			"content_type":   strProp("Content-Type when sending a body"),
			"identity_label": strProp("Optional identity label or id on the current target whose session headers are replayed"),
		}, "url")),
		fn("interesting_params", "Parameters a hunter would actually touch: reflected, plus names like url/redirect/file/id/token/user/order. Excludes params already tied to a finding.", objectSchema(map[string]any{
			"reflected_only": map[string]any{"type": "boolean", "description": "Only reflected parameters"},
		})),
		fn("coverage", "Which scan modules have already finished on this target vs high-signal detectors that have never run.", objectSchema(nil)),
		fn("remember", "Write hunter memory. kind=dead_end with url (and optional parameter) suppresses that surface for 7 days so the next cycle will not re-probe it.", objectSchema(map[string]any{
			"kind":      strProp("lead | dead_end | note | waf"),
			"content":   strProp("One or two sentences"),
			"url":       strProp("URL to suppress when kind is dead_end or waf"),
			"parameter": strProp("Optional parameter name to suppress with the URL"),
		}, "content")),
		fn("flag_lead", "File a pending lead for the operator. Not a finding. Include the URL and a short evidence snippet. Operator must confirm or dismiss.", objectSchema(map[string]any{
			"title":    strProp("Short title"),
			"body":     strProp("What you saw and why it matters"),
			"severity": strProp("info|low|medium|high|critical"),
			"url":      strProp("Related URL"),
			"method":   strProp("HTTP method used"),
			"status":   map[string]any{"type": "integer", "description": "HTTP status observed"},
			"evidence": strProp("Truncated response or diff summary"),
		}, "title", "body")),
		fn("diff_identities", "Replay the same request as two identities (or one identity vs unauthenticated) and compare status, length and a body hash. Classic BOLA/IDOR check.", objectSchema(map[string]any{
			"url":          strProp("Absolute http/https URL"),
			"method":       strProp("GET default"),
			"identity_a":   strProp("First identity label (or 'unauth')"),
			"identity_b":   strProp("Second identity label (or 'unauth')"),
			"body":         strProp("Optional body"),
			"content_type": strProp("Optional Content-Type"),
		}, "url")),
		fn("start_scan", "Enqueue Reconner modules for this target. Unknown names are rejected. The planner adds required recon.", objectSchema(map[string]any{
			"modules": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Module ids, e.g. xss, sqli, nuclei, param_discovery",
			},
			"note": strProp("Optional operator-visible reason for this scan"),
		}, "modules")),
	}
	if includeExec {
		defs = append(defs, fn("exec", "Run a bash command inside the Reconner container. For local toolchain (nuclei -tl, jq, grep templates) and in-scope CLIs (curl/httpx/nmap against Reconner targets). Out-of-scope hosts and cloud metadata are rejected. Secrets are stripped from the environment. Output is truncated. Hunter commands that mention a host count against the per-host HTTP budget.", objectSchema(map[string]any{
			"command": strProp("Shell command (bash -lc)"),
			"cwd":     strProp("Optional working directory. /data is not allowed."),
		}, "command")))
	}
	if includeBrowser {
		defs = append(defs,
			fn("browser_open", "Open an in-scope URL in Obscura (JS-capable headless browser). Scope-checked like http_request. Optional identity_label replays cookies/headers. Returns a snapshot with @eN refs. Hunter navigations count against the per-host HTTP budget.", objectSchema(map[string]any{
				"url":            strProp("Absolute http/https URL"),
				"identity_label": strProp("Optional identity label whose session cookies/headers are applied"),
			}, "url")),
			fn("browser_snapshot", "Current page URL, title, readable text, and interactive @eN refs. Refs go stale after click/fill/navigate.", objectSchema(nil)),
			fn("browser_click", "Click an element from the last snapshot (ref like e3) or a CSS selector.", objectSchema(map[string]any{
				"ref":      strProp("Snapshot ref, e.g. e3"),
				"selector": strProp("Optional CSS selector instead of ref"),
			})),
			fn("browser_fill", "Fill an input from the last snapshot or a CSS selector. Triggers input+change.", objectSchema(map[string]any{
				"ref":      strProp("Snapshot ref, e.g. e3"),
				"selector": strProp("Optional CSS selector instead of ref"),
				"value":    strProp("Text to enter"),
			}, "value")),
			fn("browser_eval", "Evaluate a JavaScript expression in the current page. Result is truncated. Do not exfiltrate cookies or Authorization headers.", objectSchema(map[string]any{
				"expression": strProp("JavaScript expression"),
			}, "expression")),
			fn("browser_close", "Close the Obscura session for this target.", objectSchema(nil)),
		)
	}
	if includeStop {
		defs = append(defs, fn("stop_hunt", "End the hunt loop with a reason.", objectSchema(map[string]any{
			"reason":  strProp("found | nothing_to_do | blocked | repeating"),
			"summary": strProp("One-paragraph outcome for the operator"),
		}, "reason")))
	}
	return defs
}

func fn(name, desc string, params map[string]any) ToolDef {
	return ToolDef{Type: "function", Name: name, Description: desc, Parameters: params}
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func objectSchema(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

type toolResult struct {
	JSON     string
	StopHunt bool
	StopMsg  string
}

func (t *Toolbox) Dispatch(ctx context.Context, targetID, name, argsJSON string, env ...CallEnv) toolResult {
	var e CallEnv
	if len(env) > 0 {
		e = env[0]
	}
	args := map[string]any{}
	if strings.TrimSpace(argsJSON) != "" {
		if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
			return errResult("invalid tool arguments: " + err.Error())
		}
	}
	var (
		payload any
		err     error
		stop    bool
		stopMsg string
	)
	switch name {
	case "target_brief":
		payload, err = t.targetBrief(ctx, targetID)
	case "surface_dossier":
		payload, err = t.surfaceDossier(ctx, targetID)
	case "object_map":
		payload, err = t.objectMap(ctx, targetID)
	case "host_rhyme":
		payload, err = t.hostRhyme(ctx, targetID)
	case "watchtower_story":
		payload, err = t.watchtowerStoryTool(ctx, targetID)
	case "list_findings":
		payload, err = t.listFindings(ctx, targetID, strArg(args, "type"), strArg(args, "severity"), "finding")
	case "list_candidates":
		payload, err = t.listCandidates(ctx, targetID, strArg(args, "type"))
	case "inspect_finding":
		payload, err = t.inspectFinding(ctx, targetID, strArg(args, "finding_id"))
	case "list_parameters":
		payload, err = t.listParameters(ctx, targetID, boolArg(args, "reflected_only"), strArg(args, "query"))
	case "list_js_findings":
		payload, err = t.listJSFindings(ctx, targetID, strArg(args, "type"))
	case "list_hypotheses":
		payload, err = t.listHypotheses(ctx, targetID)
	case "list_monitoring_changes":
		payload, err = t.listMonitoring(ctx, targetID)
	case "search_surface":
		payload, err = t.searchSurface(ctx, targetID, strArg(args, "query"))
	case "scan_status":
		payload, err = t.scanStatus(ctx, targetID)
	case "list_targets":
		payload, err = t.listTargets(ctx)
	case "http_request":
		payload, err = t.httpRequest(ctx, targetID, strArg(args, "method"), strArg(args, "url"),
			strArg(args, "body"), strArg(args, "content_type"), strArg(args, "identity_label"),
			stringMap(args["headers"]), e)
	case "interesting_params":
		payload, err = t.interestingParams(ctx, targetID, boolArg(args, "reflected_only"))
	case "coverage":
		payload, err = t.coverage(ctx, targetID)
	case "remember":
		payload, err = t.remember(ctx, targetID, strArg(args, "kind"), strArg(args, "content"), strArg(args, "url"), strArg(args, "parameter"))
	case "flag_lead":
		payload, err = t.flagLead(ctx, targetID, flagLeadArgs{
			Title:    strArg(args, "title"),
			Body:     strArg(args, "body"),
			Severity: strArg(args, "severity"),
			URL:      strArg(args, "url"),
			Method:   strArg(args, "method"),
			Status:   intArg(args, "status"),
			Evidence: strArg(args, "evidence"),
			Playbook: e.Playbook,
		})
	case "diff_identities":
		payload, err = t.diffIdentities(ctx, targetID, strArg(args, "method"), strArg(args, "url"),
			strArg(args, "identity_a"), strArg(args, "identity_b"), strArg(args, "body"), strArg(args, "content_type"), e)
	case "start_scan":
		payload, err = t.startScan(ctx, targetID, stringSlice(args["modules"]), strArg(args, "note"), e)
	case "exec":
		if t.cfg != nil && !t.cfg.AIExecEnabled {
			err = fmt.Errorf("exec is disabled — enable it in System → Integrations")
		} else {
			payload, err = t.execCommand(ctx, targetID, strArg(args, "command"), strArg(args, "cwd"), e)
		}
	case "browser_open":
		payload, err = t.browserOpen(ctx, targetID, strArg(args, "url"), strArg(args, "identity_label"), e)
	case "browser_snapshot":
		t.browserMu.Lock()
		sess := t.browsers[targetID]
		t.browserMu.Unlock()
		payload, err = t.browserSnapshot(sess)
	case "browser_click":
		payload, err = t.browserAct(ctx, targetID, "browser_click", strArg(args, "ref"), strArg(args, "selector"), "")
	case "browser_fill":
		payload, err = t.browserAct(ctx, targetID, "browser_fill", strArg(args, "ref"), strArg(args, "selector"), strArg(args, "value"))
	case "browser_eval":
		payload, err = t.browserEval(ctx, targetID, strArg(args, "expression"))
	case "browser_close":
		payload = t.browserClose(targetID)
	case "stop_hunt":
		stop = true
		stopMsg = strArg(args, "summary")
		if stopMsg == "" {
			stopMsg = strArg(args, "reason")
		}
		payload = map[string]any{"stopped": true, "reason": strArg(args, "reason"), "summary": stopMsg}
		if e.Mode == modeAlwaysOn {
			if id, err2 := t.maybeFileLeadFromSummary(ctx, targetID, stopMsg, e.Playbook); err2 == nil && id != "" {
				payload.(map[string]any)["lead_id"] = id
			}
		}
	default:
		return errResult("unknown tool: " + name)
	}
	if err != nil {
		return errResult(err.Error())
	}
	return toolResult{JSON: marshalCap(payload), StopHunt: stop, StopMsg: stopMsg}
}

func (t *Toolbox) targetBrief(ctx context.Context, targetID string) (any, error) {
	var domain, name, kind, scanStatus, priority string
	var inc, exc string
	err := t.db.QueryRowContext(ctx, `
		SELECT domain, COALESCE(name,''), COALESCE(kind,'web'), COALESCE(scan_status,'idle'), COALESCE(priority,'medium'),
			COALESCE(include_scope,''), COALESCE(exclude_scope,'')
		FROM targets WHERE id=?`, targetID).Scan(&domain, &name, &kind, &scanStatus, &priority, &inc, &exc)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("target not found")
	}
	if err != nil {
		return nil, err
	}
	count := func(q string) int {
		var n int
		_ = t.db.QueryRowContext(ctx, q, targetID).Scan(&n)
		return n
	}
	brief := map[string]any{
		"domain":      domain,
		"name":        name,
		"kind":        kind,
		"scan_status": scanStatus,
		"priority":    priority,
		"identities":  count(`SELECT COUNT(*) FROM identities WHERE target_id=?`),
		"counts": map[string]int{
			"subdomains":       count(`SELECT COUNT(*) FROM subdomains WHERE target_id=?`),
			"alive_hosts":      count(`SELECT COUNT(*) FROM subdomains WHERE target_id=? AND is_alive=1`),
			"http_services":    count(`SELECT COUNT(*) FROM http_services WHERE target_id=?`),
			"parameters":       count(`SELECT COUNT(*) FROM parameters WHERE target_id=?`),
			"reflected_params": count(`SELECT COUNT(*) FROM parameters WHERE target_id=? AND is_reflected=1`),
			"js_files":         count(`SELECT COUNT(*) FROM js_files WHERE target_id=?`),
			"js_findings":      count(`SELECT COUNT(*) FROM js_findings WHERE target_id=?`),
			"confirmed":        count(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='finding' AND COALESCE(triage,'')!='false_positive'`),
			"candidates":       count(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='candidate'`),
			"nuclei":           count(`SELECT COUNT(*) FROM nuclei_findings WHERE target_id=? AND COALESCE(verification,'unverified')!='rejected'`),
			"hypotheses":       count(`SELECT COUNT(*) FROM hypotheses WHERE target_id=?`),
			"monitor_changes":  count(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`),
			"directory":        count(`SELECT COUNT(*) FROM directory_findings WHERE target_id=?`),
			"backups":          count(`SELECT COUNT(*) FROM backup_findings WHERE target_id=?`),
		},
	}

	type rollup struct {
		Label string `json:"label"`
		N     int    `json:"n"`
	}
	wafs := []rollup{}
	if rows, err := t.db.QueryContext(ctx, `
		SELECT COALESCE(waf,''), COUNT(*) FROM http_services
		WHERE target_id=? AND COALESCE(waf,'')!='' GROUP BY waf ORDER BY COUNT(*) DESC LIMIT 8`, targetID); err == nil {
		for rows.Next() {
			var r rollup
			if rows.Scan(&r.Label, &r.N) == nil {
				wafs = append(wafs, r)
			}
		}
		rows.Close()
	}
	cms := []rollup{}
	if rows, err := t.db.QueryContext(ctx, `
		SELECT COALESCE(cms,''), COUNT(*) FROM http_services
		WHERE target_id=? AND COALESCE(cms,'')!='' GROUP BY cms ORDER BY COUNT(*) DESC LIMIT 8`, targetID); err == nil {
		for rows.Next() {
			var r rollup
			if rows.Scan(&r.Label, &r.N) == nil {
				cms = append(cms, r)
			}
		}
		rows.Close()
	}
	tech := []string{}
	if rows, err := t.db.QueryContext(ctx, `
		SELECT DISTINCT COALESCE(server,''), COALESCE(framework,'') FROM subdomains
		WHERE target_id=? AND is_alive=1 LIMIT 30`, targetID); err == nil {
		seen := map[string]bool{}
		for rows.Next() {
			var server, fw string
			if rows.Scan(&server, &fw) != nil {
				continue
			}
			for _, v := range []string{server, fw} {
				v = strings.TrimSpace(v)
				if v == "" || seen[v] {
					continue
				}
				seen[v] = true
				tech = append(tech, v)
			}
		}
		rows.Close()
	}
	brief["waf"] = wafs
	brief["cms"] = cms
	brief["tech"] = tech
	brief["program_scope"] = map[string]any{
		"include": splitStoredScope(inc),
		"exclude": splitStoredScope(exc),
	}
	return brief, nil
}

func (t *Toolbox) surfaceDossier(ctx context.Context, targetID string) (any, error) {
	if t.db == nil {
		return nil, fmt.Errorf("database is not available")
	}
	pb := pickPlaybook(ctx, t.db, targetID)
	md := buildSurfaceDossier(ctx, t.db, targetID, pb)
	return map[string]any{"lane": pb.Name, "reason": pb.Reason, "markdown": md}, nil
}

func (t *Toolbox) listFindings(ctx context.Context, targetID, typ, severity, status string) (any, error) {
	q := `SELECT id, type, severity, url, parameter, SUBSTR(COALESCE(payload,''),1,200),
		SUBSTR(COALESCE(evidence,''),1,400), COALESCE(confidence,0), COALESCE(lifecycle,'LEGACY'), created_at
		FROM vuln_findings WHERE target_id=? AND COALESCE(triage,'')!='false_positive'`
	args := []any{targetID}
	if status != "" && status != "all" {
		q += ` AND COALESCE(status,'finding')=?`
		args = append(args, status)
	}
	if typ != "" {
		q += ` AND type=?`
		args = append(args, typ)
	}
	if severity != "" {
		q += ` AND severity=?`
		args = append(args, severity)
	}
	q += ` ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at DESC LIMIT ?`
	args = append(args, rowCap)
	rows, err := t.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Severity   string `json:"severity"`
		URL        string `json:"url"`
		Parameter  string `json:"parameter"`
		Payload    string `json:"payload"`
		Evidence   string `json:"evidence"`
		Confidence int    `json:"confidence"`
		Lifecycle  string `json:"lifecycle"`
		CreatedAt  string `json:"created_at"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		if rows.Scan(&r.ID, &r.Type, &r.Severity, &r.URL, &r.Parameter, &r.Payload, &r.Evidence, &r.Confidence, &r.Lifecycle, &r.CreatedAt) == nil {
			out = append(out, r)
		}
	}
	return map[string]any{"count": len(out), "capped_at": rowCap, "findings": out}, nil
}

func (t *Toolbox) listCandidates(ctx context.Context, targetID, typ string) (any, error) {
	findings, err := t.listFindings(ctx, targetID, typ, "", "candidate")
	if err != nil {
		return nil, err
	}
	var nuclei int
	_ = t.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM nuclei_findings
		WHERE target_id=? AND COALESCE(verification,'unverified')!='rejected'`, targetID).Scan(&nuclei)
	type nrow struct {
		Template string `json:"template"`
		Severity string `json:"severity"`
		URL      string `json:"url"`
	}
	hits := []nrow{}
	if rows, err := t.db.QueryContext(ctx, `
		SELECT COALESCE(template_id,''), COALESCE(severity,''), COALESCE(matched_url,'')
		FROM nuclei_findings
		WHERE target_id=? AND COALESCE(verification,'unverified')!='rejected'
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
		LIMIT ?`, targetID, rowCap); err == nil {
		for rows.Next() {
			var r nrow
			if rows.Scan(&r.Template, &r.Severity, &r.URL) == nil {
				hits = append(hits, r)
			}
		}
		rows.Close()
	}
	return map[string]any{"vuln_candidates": findings, "nuclei_count": nuclei, "nuclei": hits}, nil
}

func (t *Toolbox) inspectFinding(ctx context.Context, targetID, id string) (any, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("finding_id is required")
	}
	var (
		typ, sev, url, param, payload, evidence, status, lifecycle, triage string
		confidence                                                         int
	)
	err := t.db.QueryRowContext(ctx, `
		SELECT type, severity, url, parameter,
			SUBSTR(COALESCE(payload,''),1,2000), SUBSTR(COALESCE(evidence,''),1,4000),
			COALESCE(status,'finding'), COALESCE(lifecycle,'LEGACY'), COALESCE(triage,''), COALESCE(confidence,0)
		FROM vuln_findings WHERE id=? AND target_id=?`, id, targetID).
		Scan(&typ, &sev, &url, &param, &payload, &evidence, &status, &lifecycle, &triage, &confidence)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("finding not found")
	}
	if err != nil {
		return nil, err
	}
	ev := []map[string]string{}
	if rows, err := t.db.QueryContext(ctx, `
		SELECT COALESCE(identity_label,''), SUBSTR(COALESCE(request_text,''),1,800),
			SUBSTR(COALESCE(response_text,''),1,800), SUBSTR(COALESCE(note,''),1,400)
		FROM evidence WHERE finding_id=? AND target_id=? LIMIT 6`, id, targetID); err == nil {
		for rows.Next() {
			var ident, req, resp, note string
			if rows.Scan(&ident, &req, &resp, &note) == nil {
				ev = append(ev, map[string]string{"identity": ident, "request": req, "response": resp, "note": note})
			}
		}
		rows.Close()
	}
	return map[string]any{
		"id": id, "type": typ, "severity": sev, "url": url, "parameter": param,
		"payload": payload, "evidence": evidence, "status": status,
		"lifecycle": lifecycle, "triage": triage, "confidence": confidence,
		"http_evidence": ev,
	}, nil
}

func (t *Toolbox) listParameters(ctx context.Context, targetID string, reflectedOnly bool, query string) (any, error) {
	q := `SELECT url, parameter, SUBSTR(COALESCE(value,''),1,120), source, is_reflected, COALESCE(method,'GET'), COALESCE(location,'query')
		FROM parameters WHERE target_id=?`
	args := []any{targetID}
	if reflectedOnly {
		q += ` AND is_reflected=1`
	}
	if query != "" {
		q += ` AND (parameter LIKE ? OR url LIKE ?)`
		like := "%" + query + "%"
		args = append(args, like, like)
	}
	q += ` ORDER BY is_reflected DESC, parameter LIMIT ?`
	args = append(args, rowCap)
	rows, err := t.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		URL       string `json:"url"`
		Parameter string `json:"parameter"`
		Value     string `json:"value"`
		Source    string `json:"source"`
		Reflected bool   `json:"reflected"`
		Method    string `json:"method"`
		Location  string `json:"location"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		var reflected int
		if rows.Scan(&r.URL, &r.Parameter, &r.Value, &r.Source, &reflected, &r.Method, &r.Location) == nil {
			r.Reflected = reflected == 1
			out = append(out, r)
		}
	}
	return map[string]any{"count": len(out), "capped_at": rowCap, "parameters": out}, nil
}

func (t *Toolbox) listJSFindings(ctx context.Context, targetID, typ string) (any, error) {
	q := `SELECT jf.type, jf.severity, SUBSTR(COALESCE(jf.value,''),1,240), SUBSTR(COALESCE(jf.context,''),1,240), COALESCE(jsf.url,'')
		FROM js_findings jf LEFT JOIN js_files jsf ON jsf.id=jf.js_file_id
		WHERE jf.target_id=?`
	args := []any{targetID}
	if typ != "" {
		q += ` AND jf.type=?`
		args = append(args, typ)
	}
	q += ` ORDER BY CASE jf.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END LIMIT ?`
	args = append(args, rowCap)
	rows, err := t.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		Type     string `json:"type"`
		Severity string `json:"severity"`
		Value    string `json:"value"`
		Context  string `json:"context"`
		FileURL  string `json:"js_url"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		if rows.Scan(&r.Type, &r.Severity, &r.Value, &r.Context, &r.FileURL) == nil {
			out = append(out, r)
		}
	}
	return map[string]any{"count": len(out), "findings": out}, nil
}

func (t *Toolbox) listHypotheses(ctx context.Context, targetID string) (any, error) {
	rows, err := t.db.QueryContext(ctx, `
		SELECT kind, identity_label, object_type, object_id, action_verb, endpoint_template,
			expected, observed, status, confidence, test_plan, SUBSTR(COALESCE(reason,''),1,400), COALESCE(finding_id,'')
		FROM hypotheses WHERE target_id=? ORDER BY
		CASE status WHEN 'VERIFIED' THEN 0 WHEN 'HYPOTHESIS' THEN 1 WHEN 'TESTED' THEN 2 ELSE 3 END, confidence DESC LIMIT ?`,
		targetID, rowCap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		Kind       string `json:"kind"`
		Identity   string `json:"identity"`
		ObjectType string `json:"object_type"`
		ObjectID   string `json:"object_id"`
		Action     string `json:"action"`
		Endpoint   string `json:"endpoint"`
		Expected   string `json:"expected"`
		Observed   string `json:"observed"`
		Status     string `json:"status"`
		Confidence int    `json:"confidence"`
		TestPlan   string `json:"test_plan"`
		Reason     string `json:"reason"`
		FindingID  string `json:"finding_id"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		if rows.Scan(&r.Kind, &r.Identity, &r.ObjectType, &r.ObjectID, &r.Action, &r.Endpoint,
			&r.Expected, &r.Observed, &r.Status, &r.Confidence, &r.TestPlan, &r.Reason, &r.FindingID) == nil {
			out = append(out, r)
		}
	}
	return map[string]any{"count": len(out), "hypotheses": out}, nil
}

func (t *Toolbox) listMonitoring(ctx context.Context, targetID string) (any, error) {
	rows, err := t.db.QueryContext(ctx, `
		SELECT url, change_type, SUBSTR(COALESCE(old_value,''),1,200), SUBSTR(COALESCE(new_value,''),1,200), detected_at
		FROM monitoring_changes WHERE target_id=? ORDER BY detected_at DESC LIMIT ?`, targetID, rowCap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		URL        string `json:"url"`
		ChangeType string `json:"change_type"`
		Old        string `json:"old"`
		New        string `json:"new"`
		DetectedAt string `json:"detected_at"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		if rows.Scan(&r.URL, &r.ChangeType, &r.Old, &r.New, &r.DetectedAt) == nil {
			out = append(out, r)
		}
	}
	return map[string]any{"count": len(out), "changes": out}, nil
}

func (t *Toolbox) searchSurface(ctx context.Context, targetID, query string) (any, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("query is required")
	}
	like := "%" + query + "%"
	urls := []string{}
	if rows, err := t.db.QueryContext(ctx, `
		SELECT DISTINCT url FROM http_services WHERE target_id=? AND url LIKE ? LIMIT 20`, targetID, like); err == nil {
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				urls = append(urls, u)
			}
		}
		rows.Close()
	}
	params := []map[string]string{}
	if rows, err := t.db.QueryContext(ctx, `
		SELECT url, parameter FROM parameters WHERE target_id=? AND (parameter LIKE ? OR url LIKE ?) LIMIT 20`,
		targetID, like, like); err == nil {
		for rows.Next() {
			var u, p string
			if rows.Scan(&u, &p) == nil {
				params = append(params, map[string]string{"url": u, "parameter": p})
			}
		}
		rows.Close()
	}
	js := []string{}
	if rows, err := t.db.QueryContext(ctx, `
		SELECT url FROM js_files WHERE target_id=? AND url LIKE ? LIMIT 20`, targetID, like); err == nil {
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				js = append(js, u)
			}
		}
		rows.Close()
	}
	return map[string]any{"query": query, "urls": urls, "parameters": params, "js_files": js}, nil
}

func (t *Toolbox) scanStatus(ctx context.Context, targetID string) (any, error) {
	rows, err := t.db.QueryContext(ctx, `
		SELECT id, type, status, COALESCE(current_module,''), COALESCE(progress,0), COALESCE(total,0),
			COALESCE(eta_seconds,0), COALESCE(modules,'[]'), COALESCE(error,'')
		FROM tasks WHERE target_id=? AND status IN ('running','pending','paused')
		ORDER BY created_at DESC LIMIT 10`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		ID            string   `json:"id"`
		Type          string   `json:"type"`
		Status        string   `json:"status"`
		CurrentModule string   `json:"current_module"`
		Progress      int      `json:"progress"`
		Total         int      `json:"total"`
		EtaSeconds    int      `json:"eta_seconds"`
		Modules       []string `json:"modules"`
		Error         string   `json:"error,omitempty"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		var mods string
		if rows.Scan(&r.ID, &r.Type, &r.Status, &r.CurrentModule, &r.Progress, &r.Total, &r.EtaSeconds, &mods, &r.Error) == nil {
			r.Modules = models.JSONToStringSlice(mods)
			out = append(out, r)
		}
	}
	return map[string]any{"active": out}, nil
}

func (t *Toolbox) startScan(ctx context.Context, targetID string, modules []string, note string, env CallEnv) (any, error) {
	cleaned, err := allowModules(modules)
	if err != nil {
		return nil, err
	}
	cleaned, err = t.gateHunterScan(ctx, targetID, cleaned, env)
	if err != nil {
		return nil, err
	}
	if t.sched == nil {
		return nil, fmt.Errorf("scheduler is not available")
	}
	if err := requireIDORIdentities(ctx, t.db, targetID, cleaned); err != nil {
		return nil, err
	}
	task, err := t.sched.CreateTask(targetID, cleaned, 5)
	if err != nil {
		return nil, fmt.Errorf("enqueue scan: %w", err)
	}
	return map[string]any{
		"task_id": task.ID,
		"modules": task.Modules,
		"status":  task.Status,
		"note":    clip(note, 200),
		"message": "Scan queued. Reconner's planner expanded detectors into the executable module list. Poll scan_status; do not assume findings yet.",
	}, nil
}

func allowModules(modules []string) ([]string, error) {
	known := knownModuleSet()
	if len(modules) == 0 {
		return nil, fmt.Errorf("modules is required")
	}
	out := make([]string, 0, len(modules))
	seen := map[string]bool{}
	var unknown []string
	for _, m := range modules {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		if !known[m] {
			unknown = append(unknown, m)
			continue
		}
		out = append(out, m)
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown module(s): %s", strings.Join(unknown, ", "))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("modules is required")
	}
	return out, nil
}

func knownModuleSet() map[string]bool {
	m := map[string]bool{}
	for _, n := range scheduler.AllModules {
		m[n] = true
	}
	for _, n := range []string{scheduler.ModuleDAST, scheduler.ModuleDOMXSS, scheduler.ModulePortScan} {
		m[n] = true
	}
	delete(m, scheduler.ModuleNetworkBrute)
	delete(m, scheduler.ModuleNetworkIngram)
	return m
}

func (t *Toolbox) interestingParams(ctx context.Context, targetID string, reflectedOnly bool) (any, error) {
	q := `
		SELECT p.url, p.parameter, SUBSTR(COALESCE(p.value,''),1,80), p.source, p.is_reflected, COALESCE(p.method,'GET')
		FROM parameters p
		WHERE p.target_id=?
		  AND NOT EXISTS (
		    SELECT 1 FROM vuln_findings v WHERE v.target_id=p.target_id AND v.parameter=p.parameter AND v.url=p.url
		  )`
	args := []any{targetID}
	if reflectedOnly {
		q += ` AND p.is_reflected=1`
	} else {
		q += ` AND (p.is_reflected=1 OR lower(p.parameter) LIKE '%url%' OR lower(p.parameter) LIKE '%redirect%'
			OR lower(p.parameter) LIKE '%next%' OR lower(p.parameter) LIKE '%return%'
			OR lower(p.parameter) LIKE '%callback%' OR lower(p.parameter) LIKE '%dest%'
			OR lower(p.parameter) LIKE '%file%' OR lower(p.parameter) LIKE '%path%'
			OR lower(p.parameter) LIKE '%token%' OR lower(p.parameter) LIKE '%jwt%'
			OR lower(p.parameter) LIKE '%id' OR lower(p.parameter) LIKE '%uuid%'
			OR lower(p.parameter) LIKE '%user%' OR lower(p.parameter) LIKE '%account%'
			OR lower(p.parameter) LIKE '%order%' OR lower(p.parameter) LIKE '%doc%')`
	}
	q += ` ORDER BY p.is_reflected DESC, p.parameter LIMIT ?`
	args = append(args, rowCap)
	rows, err := t.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		URL       string `json:"url"`
		Parameter string `json:"parameter"`
		Value     string `json:"value"`
		Source    string `json:"source"`
		Reflected bool   `json:"reflected"`
		Method    string `json:"method"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		var ref int
		if rows.Scan(&r.URL, &r.Parameter, &r.Value, &r.Source, &ref, &r.Method) == nil {
			r.Reflected = ref == 1
			out = append(out, r)
		}
	}
	return map[string]any{"count": len(out), "parameters": out}, nil
}

func (t *Toolbox) coverage(ctx context.Context, targetID string) (any, error) {
	var mods, done string
	_ = t.db.QueryRowContext(ctx, `
		SELECT COALESCE(modules,'[]'), COALESCE(completed_modules,'[]')
		FROM tasks WHERE target_id=? ORDER BY created_at DESC LIMIT 1`, targetID).Scan(&mods, &done)
	ran := map[string]bool{}
	for _, m := range models.JSONToStringSlice(done) {
		ran[m] = true
	}
	for _, m := range models.JSONToStringSlice(mods) {
		if ran[m] {
			continue
		}
		// listed but not completed still counts as attempted
		ran[m] = false
	}
	high := []string{"http_probe", "js_analysis", "param_discovery", "xss", "sqli", "nuclei", "exposure", "idor", "jwt", "open_redirect", "backup_discovery"}
	missing := []string{}
	for _, m := range high {
		if done := ran[m]; !done {
			missing = append(missing, m)
		}
	}
	completed := models.JSONToStringSlice(done)
	return map[string]any{"last_task_modules": models.JSONToStringSlice(mods), "completed": completed, "missing_high_signal": missing}, nil
}

func (t *Toolbox) remember(ctx context.Context, targetID, kind, content, rawURL, param string) (any, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, fmt.Errorf("content is required")
	}
	if kind == "" {
		kind = "note"
	}
	_, err := t.db.ExecContext(ctx, `
		INSERT INTO agent_hunter_notes (id, target_id, kind, content) VALUES (?,?,?,?)`,
		uuid.New().String(), targetID, clip(kind, 40), clip(content, 800))
	if err != nil {
		return nil, err
	}
	dur := t.deadEndDur()
	if kind == "waf" {
		dur = t.wafDur()
	}
	if (kind == "dead_end" || kind == "waf") && strings.TrimSpace(rawURL) != "" {
		t.suppress(ctx, targetID, rawURL, param, kind, dur)
	}
	return map[string]any{"stored": true, "kind": kind, "suppressed": kind == "dead_end" || kind == "waf"}, nil
}

type flagLeadArgs struct {
	Title, Body, Severity, URL, Method, Evidence, Playbook string
	Status                                                 int
}

// LeadReportMarkdown is a disclosure draft for an operator-confirmed hunter lead.
// It is not a verified finding.
func LeadReportMarkdown(title, body, severity, method, urlStr, evidence, playbook, status string) string {
	var b strings.Builder
	b.WriteString("# Hunter lead\n\n")
	if title != "" {
		b.WriteString("**Title:** " + title + "\n\n")
	}
	if severity != "" {
		b.WriteString("**Severity:** " + severity + "\n\n")
	}
	if status != "" {
		b.WriteString("**Operator status:** " + status + "\n\n")
	}
	if playbook != "" {
		b.WriteString("**Playbook:** " + playbook + "\n\n")
	}
	if urlStr != "" {
		if method == "" {
			method = "GET"
		}
		b.WriteString("**URL:** `" + method + " " + urlStr + "`\n\n")
	}
	if body != "" {
		b.WriteString("## Summary\n\n" + body + "\n\n")
	}
	if evidence != "" {
		b.WriteString("## Evidence\n\n```\n" + evidence + "\n```\n\n")
	}
	b.WriteString("_Operator-confirmed hunter lead. Not a Reconner-verified finding. Attach verifier evidence and the HTML report before disclosure._\n")
	return b.String()
}

func (t *Toolbox) flagLead(ctx context.Context, targetID string, a flagLeadArgs) (any, error) {
	a.Title = strings.TrimSpace(a.Title)
	a.Body = strings.TrimSpace(a.Body)
	if a.Title == "" || a.Body == "" {
		return nil, fmt.Errorf("title and body are required")
	}
	if err := t.rejectFloodLead(ctx, targetID, a); err != nil {
		return nil, err
	}
	if a.Severity == "" {
		a.Severity = "medium"
	}
	id := uuid.New().String()
	_, err := t.db.ExecContext(ctx, `
		INSERT INTO agent_leads (id, target_id, title, body, severity, url, method, status_code, evidence, playbook, status)
		VALUES (?,?,?,?,?,?,?,?,?,?, 'pending')`,
		id, targetID, clip(a.Title, 120), clip(a.Body, 1200), a.Severity, clip(a.URL, 500),
		clip(a.Method, 16), a.Status, clip(a.Evidence, 2000), clip(a.Playbook, 40))
	if err != nil {
		return nil, err
	}
	_, _ = t.db.ExecContext(ctx, `
		INSERT INTO notifications (id, target_id, type, title, body, url, severity, is_read, created_at)
		VALUES (?, ?, 'hunter_lead', ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)`,
		uuid.New().String(), targetID, clip(a.Title, 120), clip(a.Body, 800), clip(a.URL, 500), a.Severity)
	_, _ = t.remember(ctx, targetID, "lead", a.Title+": "+a.Body, a.URL, "")
	return map[string]any{"flagged": true, "lead_id": id, "status": "pending", "title": a.Title}, nil
}

func intArg(args map[string]any, k string) int {
	v, ok := args[k]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	default:
		var n int
		fmt.Sscanf(fmt.Sprint(t), "%d", &n)
		return n
	}
}

func requireIDORIdentities(ctx context.Context, db *database.DB, targetID string, modules []string) error {
	wants := false
	for _, m := range modules {
		if strings.EqualFold(m, scheduler.ModuleIDOR) {
			wants = true
			break
		}
	}
	if !wants {
		return nil
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identities WHERE target_id=?`, targetID).Scan(&n)
	if n < 2 {
		return fmt.Errorf("IDOR/BOLA testing requires two identities (User A + User B). Add two sets of session tokens or cookies on the target before starting a scan with the IDOR module — currently configured: %d", n)
	}
	return nil
}

func strArg(args map[string]any, k string) string {
	v, ok := args[k]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func boolArg(args map[string]any, k string) bool {
	v, ok := args[k]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	default:
		return false
	}
}

func stringMap(v any) map[string]string {
	out := map[string]string{}
	switch t := v.(type) {
	case map[string]string:
		return t
	case map[string]any:
		for k, val := range t {
			if k == "" || val == nil {
				continue
			}
			out[k] = fmt.Sprint(val)
		}
	}
	return out
}

func stringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return strings.Split(t, ",")
	default:
		return nil
	}
}

func marshalCap(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"marshal failed"}`
	}
	if len(b) <= resultCap {
		return string(b)
	}
	preview, _ := json.Marshal(clip(string(b), resultCap))
	return fmt.Sprintf(`{"error":"result truncated","preview":%s}`, preview)
}

func errResult(msg string) toolResult {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return toolResult{JSON: string(b)}
}
