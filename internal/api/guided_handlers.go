package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/capture"
	"github.com/recon-platform/internal/scanner"
	"github.com/recon-platform/internal/secret"
)

func (h *Handler) captureAudit(r *http.Request, id, action string) error {
	_, e := h.db.ExecContext(r.Context(), `INSERT INTO capture_audit(target_id,resource_id,action) VALUES(?,?,?)`, mux.Vars(r)["id"], id, action)
	return e
}

func (h *Handler) handleCaptureTemplates(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	rows, e := h.db.QueryContext(r.Context(), `SELECT rt.id,rt.method,rt.norm_url,rt.operation_kind,rt.preflight_status,rt.request_shape_hash,rt.encrypted_request
		FROM request_templates rt JOIN capture_sessions cs ON cs.id=rt.capture_session_id
		WHERE rt.target_id=? AND rt.capture_session_id=? AND cs.target_id=?
		AND (cs.expires_at IS NULL OR cs.expires_at>datetime('now')) ORDER BY rt.sequence,rt.id`, v["id"], v["cid"], v["id"])
	if e != nil {
		h.writeError(w, 500, "could not load requests")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	box := secret.New(h.cfg.SessionSecret)
	for rows.Next() {
		var id, method, route, kind, status, version, encrypted string
		if e := rows.Scan(&id, &method, &route, &kind, &status, &version, &encrypted); e != nil {
			h.writeError(w, 500, "could not decode request")
			return
		}
		var request capture.Request
		if json.Unmarshal([]byte(box.Decrypt(encrypted)), &request) != nil {
			h.writeError(w, 500, "request could not be decrypted")
			return
		}
		items = append(items, map[string]any{
			"id": id, "method": method, "route": route, "kind": kind,
			"preflight_status": status, "version": version,
			"suggestions": scanner.DiscoverGuidedOpportunities(request),
		})
	}
	if e := rows.Err(); e != nil {
		h.writeError(w, 500, "could not load requests")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.writeSuccess(w, items)
}

func (h *Handler) handleRevealCaptureTemplate(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	var enc, version string
	if e := h.db.QueryRowContext(r.Context(), `SELECT rt.encrypted_request,rt.request_shape_hash
		FROM request_templates rt JOIN capture_sessions cs ON cs.id=rt.capture_session_id
		WHERE rt.target_id=? AND rt.capture_session_id=? AND rt.id=? AND cs.target_id=?
		AND (cs.expires_at IS NULL OR cs.expires_at>datetime('now'))`, v["id"], v["cid"], v["tid"], v["id"]).Scan(&enc, &version); e != nil {
		h.writeError(w, 404, "request not found")
		return
	}
	var request capture.Request
	if json.Unmarshal([]byte(secret.New(h.cfg.SessionSecret).Decrypt(enc)), &request) != nil {
		h.writeError(w, 500, "request could not be decrypted")
		return
	}
	if h.captureAudit(r, v["tid"], "reveal_request") != nil {
		h.writeError(w, 500, "could not audit reveal")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.writeSuccess(w, map[string]any{"request": request, "version": version})
}

func (h *Handler) handleEditCaptureTemplate(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	var input struct {
		Request capture.Request `json:"request"`
		Version string          `json:"version"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 12<<20))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || input.Version == "" {
		h.writeError(w, 400, "invalid request or missing version")
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		h.writeError(w, 400, "unexpected trailing data")
		return
	}
	req := input.Request
	req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
	u, e := url.Parse(req.URL)
	if e != nil || u.User != nil || !scanner.GuidedURLInScope(r.Context(), h.db, v["id"], req.URL) {
		h.writeError(w, 400, "request URL is outside project scope")
		return
	}
	if !strings.Contains("|GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE|", "|"+req.Method+"|") || req.Method == "" || len(req.Body) > capture.MaxMessageBytes || len(req.Headers) > 256 {
		h.writeError(w, 400, "unsupported method or request too large")
		return
	}
	for _, header := range req.Headers {
		if strings.TrimSpace(header.Name) == "" || strings.ContainsAny(header.Name, " \t\r\n:") || strings.ContainsAny(header.Value, "\r\n") || len(header.Value) > 16384 {
			h.writeError(w, 400, "invalid header")
			return
		}
	}
	if strings.ContainsAny(req.MimeType, "\r\n") {
		h.writeError(w, 400, "invalid content type")
		return
	}
	preview := capture.BuildPreview([]capture.Exchange{{Request: req}}, func(string) bool { return true })
	p, _ := json.Marshal(preview.Items[0])
	b, _ := json.Marshal(req)
	enc := secret.New(h.cfg.SessionSecret).Encrypt(string(b))
	if !strings.HasPrefix(enc, "enc:v1:") {
		h.writeError(w, 500, "encryption failed")
		return
	}
	// Hash the full edited request: auth-only edits must also invalidate the version.
	version := keyedCaptureHash(h.cfg.SessionSecret, b)
	policy := "manual_only"
	if capture.SafeAutomaticReplay(req) {
		policy = "proof_only"
	}
	tx, e := h.db.BeginTx(r.Context(), nil)
	if e != nil {
		h.writeError(w, 500, "edit failed")
		return
	}
	defer tx.Rollback()
	res, e := tx.ExecContext(r.Context(), `UPDATE request_templates SET method=?,norm_url=?,content_type=?,operation_kind=?,request_shape_hash=?,encrypted_request=?,redacted_preview=?,replay_policy=?,preflight_status='pending',preflight_reason='request edited; baseline invalidated',preflight_at=NULL
		WHERE id=? AND target_id=? AND capture_session_id=? AND request_shape_hash=?
		AND EXISTS (SELECT 1 FROM capture_sessions cs WHERE cs.id=request_templates.capture_session_id AND cs.target_id=? AND (cs.expires_at IS NULL OR cs.expires_at>datetime('now')))`, req.Method, capture.SafeDisplayURL(req.URL), req.MimeType, capture.OperationKind(req), version, enc, string(p), policy, v["tid"], v["id"], v["cid"], input.Version, v["id"])
	if e != nil {
		h.writeError(w, 409, "edit conflicts with another request")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		h.writeError(w, 409, "request changed or no longer exists; reload it")
		return
	}
	empty, _ := json.Marshal(capture.Response{})
	encResponse := secret.New(h.cfg.SessionSecret).Encrypt(string(empty))
	if _, e = tx.ExecContext(r.Context(), `UPDATE captured_responses SET status=0,content_type='',encrypted_response=?,body_hash='',response_len=0 WHERE request_template_id=?`, encResponse, v["tid"]); e != nil {
		h.writeError(w, 500, "baseline reset failed")
		return
	}
	if _, e = tx.ExecContext(r.Context(), `INSERT INTO capture_audit(target_id,resource_id,action) VALUES(?,?,'edit_request')`, v["id"], v["tid"]); e != nil {
		h.writeError(w, 500, "edit audit failed")
		return
	}
	if tx.Commit() != nil {
		h.writeError(w, 500, "edit commit failed")
		return
	}
	h.writeSuccess(w, map[string]string{"version": version})
}

func (h *Handler) handleAnalyzeCapture(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	var input struct {
		TemplateIDs []string              `json:"template_ids"`
		Modules     []string              `json:"modules"`
		Checks      []scanner.GuidedCheck `json:"checks"`
		AllowUnsafe bool                  `json:"allow_unsafe"`
		Confirm     bool                  `json:"confirm_active"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || !input.Confirm {
		h.writeError(w, 400, "active testing must be explicitly confirmed")
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		h.writeError(w, 400, "unexpected trailing data")
		return
	}
	if h.sched == nil {
		h.writeError(w, 503, "scheduler unavailable")
		return
	}
	known := map[string]bool{}
	for _, m := range scanner.GuidedModules {
		known[m] = true
	}
	seenModules := map[string]bool{}
	var modules []string
	var checks []scanner.GuidedCheck
	var templateIDs []string
	if len(input.Checks) > 0 {
		if len(input.Checks) > 200 {
			h.writeError(w, 400, "select between 1 and 200 suggested checks per run")
			return
		}
		seenChecks := map[string]bool{}
		seenTemplates := map[string]bool{}
		for _, check := range input.Checks {
			check.TemplateID = strings.TrimSpace(check.TemplateID)
			check.Module = strings.TrimSpace(check.Module)
			if check.TemplateID == "" || !known[check.Module] {
				h.writeError(w, 400, "unsupported or incomplete guided check")
				return
			}
			key := check.TemplateID + "\x00" + check.Module
			if seenChecks[key] {
				continue
			}
			seenChecks[key] = true
			checks = append(checks, check)
			if !seenModules[check.Module] {
				modules = append(modules, check.Module)
				seenModules[check.Module] = true
			}
			if !seenTemplates[check.TemplateID] {
				templateIDs = append(templateIDs, check.TemplateID)
				seenTemplates[check.TemplateID] = true
			}
		}
	} else {
		if len(input.TemplateIDs) == 0 {
			h.writeError(w, 400, "select between 1 and 50 requests per run")
			return
		}
		if len(input.Modules) == 0 {
			input.Modules = append([]string{}, scanner.GuidedModules...)
		}
		for _, m := range input.Modules {
			if !known[m] {
				h.writeError(w, 400, "unsupported guided module")
				return
			}
			if !seenModules[m] {
				modules = append(modules, m)
				seenModules[m] = true
			}
		}
		templateIDs = input.TemplateIDs
	}
	if len(templateIDs) == 0 || len(modules) == 0 {
		h.writeError(w, 400, "select at least one guided check")
		return
	}
	job := scanner.GuidedInput{Modules: modules, Checks: checks, AllowUnsafe: input.AllowUnsafe}
	box := secret.New(h.cfg.SessionSecret)
	ids := map[string]bool{}
	total := 0
	for _, id := range templateIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if ids[id] {
			continue
		}
		if len(ids) >= 50 {
			h.writeError(w, 400, "select between 1 and 50 requests per run")
			return
		}
		ids[id] = true
		var enc, resp string
		if e := h.db.QueryRowContext(r.Context(), `SELECT rt.encrypted_request,COALESCE(cr.encrypted_response,'') FROM request_templates rt JOIN capture_sessions cs ON cs.id=rt.capture_session_id LEFT JOIN captured_responses cr ON cr.request_template_id=rt.id WHERE rt.id=? AND rt.target_id=? AND rt.capture_session_id=? AND (cs.expires_at IS NULL OR cs.expires_at>datetime('now'))`, id, v["id"], v["cid"]).Scan(&enc, &resp); e != nil {
			h.writeError(w, 404, "selected request not found or capture expired")
			return
		}
		t := scanner.GuidedTemplate{ID: id}
		if json.Unmarshal([]byte(box.Decrypt(enc)), &t.Request) != nil || json.Unmarshal([]byte(box.Decrypt(resp)), &t.Response) != nil {
			h.writeError(w, 500, "capture could not be decrypted")
			return
		}
		if !scanner.GuidedURLInScope(r.Context(), h.db, v["id"], t.Request.URL) {
			h.writeError(w, 400, "request is no longer in project scope")
			return
		}
		// Keep just the response metadata/body needed by passive checks; don't copy
		// multi-megabyte captured response bodies into every job snapshot.
		t.Response.Body = nil
		total += len(t.Request.Body)
		if total > capture.MaxImportBytes {
			h.writeError(w, 400, "selected request bodies exceed run limit")
			return
		}
		job.Templates = append(job.Templates, t)
	}
	if len(job.Templates) == 0 {
		h.writeError(w, 400, "select between 1 and 50 requests per run")
		return
	}
	b, _ := json.Marshal(job)
	enc := box.Encrypt(string(b))
	if !strings.HasPrefix(enc, "enc:v1:") {
		h.writeError(w, 500, "encryption failed")
		return
	}
	runID := uuid.NewString()
	if _, e := h.db.ExecContext(r.Context(), `INSERT INTO guided_runs(id,target_id,capture_id,encrypted_input) VALUES(?,?,?,?)`, runID, v["id"], v["cid"], enc); e != nil {
		h.writeError(w, 500, "could not create run")
		return
	}
	task, e := h.sched.CreateGuidedTask(v["id"], runID, modules)
	if e != nil {
		_, _ = h.db.Exec(`DELETE FROM guided_runs WHERE id=?`, runID)
		h.writeError(w, 500, "could not queue run")
		return
	}
	_, _ = h.db.Exec(`UPDATE guided_runs SET task_id=? WHERE id=?`, task.ID, runID)
	_ = h.captureAudit(r, runID, "analyze_capture")
	h.writeSuccess(w, map[string]string{"run_id": runID, "task_id": task.ID})
}

func (h *Handler) handleCaptureRuns(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	rows, e := h.db.QueryContext(r.Context(), `SELECT gr.id,gr.task_id,COALESCE(t.status,'unknown'),gr.redacted_report,gr.created_at FROM guided_runs gr LEFT JOIN tasks t ON t.id=gr.task_id WHERE gr.target_id=? AND gr.capture_id=? ORDER BY gr.created_at DESC,gr.id DESC LIMIT 20`, v["id"], v["cid"])
	if e != nil {
		h.writeError(w, 500, "could not load runs")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, task, status, report, created string
		if e := rows.Scan(&id, &task, &status, &report, &created); e != nil {
			h.writeError(w, 500, "could not decode runs")
			return
		}
		out = append(out, map[string]any{"id": id, "task_id": task, "status": status, "report": json.RawMessage(report), "created_at": created})
	}
	if e := rows.Err(); e != nil {
		h.writeError(w, 500, "could not load runs")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.writeSuccess(w, out)
}

func (h *Handler) handleRevealGuidedReport(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	var enc string
	if h.db.QueryRowContext(r.Context(), `SELECT gr.encrypted_report FROM guided_runs gr
		JOIN capture_sessions cs ON cs.id=gr.capture_id
		WHERE gr.id=? AND gr.target_id=? AND gr.capture_id=? AND cs.target_id=?
		AND (cs.expires_at IS NULL OR cs.expires_at>datetime('now'))`, v["rid"], v["id"], v["cid"], v["id"]).Scan(&enc) != nil {
		h.writeError(w, 404, "run not found")
		return
	}
	var report scanner.GuidedReport
	if json.Unmarshal([]byte(secret.New(h.cfg.SessionSecret).Decrypt(enc)), &report) != nil {
		h.writeError(w, 409, "report is not ready")
		return
	}
	if h.captureAudit(r, v["rid"], "reveal_test_cases") != nil {
		h.writeError(w, 500, "could not audit reveal")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.writeSuccess(w, report)
}

func (h *Handler) handleDeleteCapture(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "could not delete capture")
		return
	}
	defer tx.Rollback()
	var active int
	if err := tx.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM guided_runs gr JOIN tasks t ON t.id=gr.task_id
		WHERE gr.target_id=? AND gr.capture_id=? AND t.status IN ('pending','running','paused')`, v["id"], v["cid"]).Scan(&active); err != nil {
		h.writeError(w, http.StatusInternalServerError, "could not inspect capture runs")
		return
	}
	if active > 0 {
		h.writeError(w, http.StatusConflict, "capture has an active guided run")
		return
	}
	res, err := tx.ExecContext(r.Context(), `DELETE FROM capture_sessions WHERE id=? AND target_id=?`, v["cid"], v["id"])
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "could not delete capture")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		h.writeError(w, http.StatusNotFound, "capture not found")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO capture_audit(target_id,resource_id,action) VALUES(?,?,'delete_capture')`, v["id"], v["cid"]); err != nil {
		h.writeError(w, http.StatusInternalServerError, "could not audit capture deletion")
		return
	}
	if err := tx.Commit(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "could not delete capture")
		return
	}
	h.writeSuccess(w, map[string]bool{"deleted": true})
}
