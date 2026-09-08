package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/agent"
)

func (h *Handler) handleImportScope(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Text) == "" {
		h.writeError(w, http.StatusBadRequest, "need text (HackerOne/Bugcrowd JSON or host list)")
		return
	}
	parsed := agent.ParseProgramScope(body.Text)
	inc := strings.Join(parsed.Include, "\n")
	exc := strings.Join(parsed.Exclude, "\n")
	var existingExc string
	_ = h.db.QueryRowContext(r.Context(), `SELECT COALESCE(exclude_scope,'') FROM targets WHERE id=?`, targetID).Scan(&existingExc)
	if existingExc != "" && exc != "" {
		exc = strings.TrimSpace(existingExc + "\n" + exc)
	} else if existingExc != "" && exc == "" {
		exc = existingExc
	}
	if _, err := h.db.ExecContext(r.Context(), `UPDATE targets SET include_scope=?, exclude_scope=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		inc, exc, targetID); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to save scope")
		return
	}
	h.writeSuccess(w, parsed)
}

func (h *Handler) handleGetScope(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	var inc, exc string
	if err := h.db.QueryRowContext(r.Context(), `SELECT COALESCE(include_scope,''), COALESCE(exclude_scope,'') FROM targets WHERE id=?`, targetID).Scan(&inc, &exc); err != nil {
		h.writeError(w, http.StatusNotFound, "target not found")
		return
	}
	h.writeSuccess(w, map[string]any{"include": scopeLines(inc), "exclude": scopeLines(exc)})
}

func scopeLines(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	out := []string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func (h *Handler) programScopeAllows(targetID, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("invalid URL")
	}
	var inc, exc string
	_ = h.db.QueryRow(`SELECT COALESCE(include_scope,''), COALESCE(exclude_scope,'') FROM targets WHERE id=?`, targetID).Scan(&inc, &exc)
	return agent.CheckProgramScope(inc, exc, u.Hostname())
}

func (h *Handler) handleListLeads(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	q := `SELECT id, title, body, severity, url, method, status_code, evidence, playbook, status, created_at, COALESCE(verify_task_id,'')
		FROM agent_leads WHERE target_id=?`
	args := []any{targetID}
	if status != "" {
		q += ` AND status=?`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC LIMIT 100`
	rows, err := h.db.QueryContext(r.Context(), q, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to list leads")
		return
	}
	defer rows.Close()
	type lead struct {
		ID           string `json:"id"`
		Title        string `json:"title"`
		Body         string `json:"body"`
		Severity     string `json:"severity"`
		URL          string `json:"url"`
		Method       string `json:"method"`
		StatusCode   int    `json:"status_code"`
		Evidence     string `json:"evidence"`
		Playbook     string `json:"playbook"`
		Status       string `json:"status"`
		CreatedAt    string `json:"created_at"`
		VerifyTaskID string `json:"verify_task_id,omitempty"`
	}
	out := []lead{}
	for rows.Next() {
		var x lead
		if rows.Scan(&x.ID, &x.Title, &x.Body, &x.Severity, &x.URL, &x.Method, &x.StatusCode, &x.Evidence, &x.Playbook, &x.Status, &x.CreatedAt, &x.VerifyTaskID) == nil {
			out = append(out, x)
		}
	}
	h.writeSuccess(w, out)
}

func (h *Handler) handleTriageLead(w http.ResponseWriter, r *http.Request) {
	targetID, lid := mux.Vars(r)["id"], mux.Vars(r)["lid"]
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	st := strings.ToLower(strings.TrimSpace(body.Status))
	if st != "confirmed" && st != "dismissed" && st != "pending" {
		h.writeError(w, http.StatusBadRequest, "status must be confirmed, dismissed, or pending")
		return
	}
	res, err := h.db.ExecContext(r.Context(), `
		UPDATE agent_leads SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=?`, st, lid, targetID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		h.writeError(w, http.StatusNotFound, "lead not found")
		return
	}
	out := map[string]any{"id": lid, "status": st}
	if st == "confirmed" {
		out["report"] = h.leadReportMarkdown(targetID, lid)
		var starter agent.LeadVerifyStarter
		if h.sched != nil {
			starter = h.sched
		}
		taskID, mods, err := agent.EnqueueLeadVerify(r.Context(), h.db, starter, targetID, lid)
		if err != nil {
			out["verify_error"] = err.Error()
		} else if taskID != "" {
			out["task_id"] = taskID
			out["modules"] = mods
		}
	}
	h.writeSuccess(w, out)
}

func (h *Handler) handleLeadReport(w http.ResponseWriter, r *http.Request) {
	targetID, lid := mux.Vars(r)["id"], mux.Vars(r)["lid"]
	md := h.leadReportMarkdown(targetID, lid)
	if md == "" {
		h.writeError(w, http.StatusNotFound, "lead not found")
		return
	}
	h.writeSuccess(w, map[string]string{"markdown": md})
}

func (h *Handler) leadReportMarkdown(targetID, lid string) string {
	var title, body, sev, urlStr, method, evidence, playbook, status string
	err := h.db.QueryRow(`SELECT COALESCE(title,''), COALESCE(body,''), COALESCE(severity,''), COALESCE(url,''),
		COALESCE(method,''), COALESCE(evidence,''), COALESCE(playbook,''), COALESCE(status,'')
		FROM agent_leads WHERE id=? AND target_id=?`, lid, targetID).
		Scan(&title, &body, &sev, &urlStr, &method, &evidence, &playbook, &status)
	if err != nil {
		return ""
	}
	return agent.LeadReportMarkdown(title, body, sev, method, urlStr, evidence, playbook, status)
}

func (h *Handler) handleHunterStatus(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		h.writeSuccess(w, map[string]any{"enabled": false, "alive": false, "recent": []any{}})
		return
	}
	snap := h.agent.HunterStatus()
	h.writeSuccess(w, map[string]any{
		"enabled": snap.Enabled, "alive": snap.Alive,
		"current_target": snap.CurrentTarget, "current_domain": snap.CurrentDomain,
		"current_playbook": snap.CurrentPlaybook,
		"last_target":      snap.LastTarget, "last_domain": snap.LastDomain,
		"last_playbook": snap.LastPlaybook, "last_summary": snap.LastSummary,
		"last_at": snap.LastAt, "cycles": snap.Cycles, "watching": snap.Watching,
		"interval_seconds": snap.IntervalSeconds, "iterations": snap.Iterations,
		"recent": h.agent.HunterLog(r.Context(), 12),
	})
}

func (h *Handler) handleAIStatus(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		h.writeSuccess(w, aiStatusFromConfig(h.cfg))
		return
	}
	h.writeSuccess(w, h.agent.Status())
}

func (h *Handler) handleAgentThread(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		h.writeError(w, http.StatusServiceUnavailable, "AI copilot is not configured")
		return
	}
	targetID := mux.Vars(r)["id"]
	threadID := strings.TrimSpace(r.URL.Query().Get("thread_id"))
	th, err := h.agent.LoadThread(r.Context(), targetID, threadID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to load thread")
		return
	}
	if th == nil {
		h.writeSuccess(w, map[string]any{
			"id": "", "messages": []any{}, "status": "idle",
			"hunter_active": h.agent.HunterHolds(targetID),
			"token_budget":  20000, "token_context": 0, "token_prompt": 0, "token_completion": 0,
		})
		return
	}
	h.writeSuccess(w, th)
}

func (h *Handler) handleAgentThreads(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		h.writeError(w, http.StatusServiceUnavailable, "AI copilot is not configured")
		return
	}
	list, err := h.agent.ListThreads(r.Context(), mux.Vars(r)["id"])
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to list chats")
		return
	}
	h.writeSuccess(w, list)
}

func (h *Handler) handleAgentNewThread(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		h.writeError(w, http.StatusServiceUnavailable, "AI copilot is not configured")
		return
	}
	var body struct {
		Title string `json:"title"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	th, err := h.agent.NewThread(r.Context(), mux.Vars(r)["id"], h.currentUserID(r), strings.TrimSpace(body.Title))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeJSON(w, http.StatusCreated, map[string]any{"data": th, "success": true})
}

func (h *Handler) handleAgentPatchThread(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		h.writeError(w, http.StatusServiceUnavailable, "AI copilot is not configured")
		return
	}
	var body struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	vars := mux.Vars(r)
	if err := h.agent.RenameThread(r.Context(), vars["id"], vars["tid"], strings.TrimSpace(body.Title)); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	th, err := h.agent.LoadThread(r.Context(), vars["id"], vars["tid"])
	if err != nil || th == nil {
		h.writeError(w, http.StatusNotFound, "thread not found")
		return
	}
	h.writeSuccess(w, th)
}

func (h *Handler) handleAgentDeleteThread(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		h.writeError(w, http.StatusServiceUnavailable, "AI copilot is not configured")
		return
	}
	vars := mux.Vars(r)
	if err := h.agent.DeleteThread(r.Context(), vars["id"], vars["tid"]); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeSuccess(w, map[string]any{"deleted": true})
}

func (h *Handler) handleAgentCompact(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		h.writeError(w, http.StatusServiceUnavailable, "AI copilot is not configured")
		return
	}
	vars := mux.Vars(r)
	res, err := h.agent.Compact(r.Context(), vars["id"], vars["tid"], true)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeSuccess(w, res)
}

func (h *Handler) handleAgentMessage(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Content  string `json:"content"`
		ThreadID string `json:"thread_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	h.startAgent(w, r, "chat", strings.TrimSpace(body.Content), "", strings.TrimSpace(body.ThreadID))
}

func (h *Handler) handleAgentHunt(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hypothesis string `json:"hypothesis"`
		ThreadID   string `json:"thread_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	h.startAgent(w, r, "hunt", "", strings.TrimSpace(body.Hypothesis), strings.TrimSpace(body.ThreadID))
}

func (h *Handler) startAgent(w http.ResponseWriter, r *http.Request, mode, content, hypothesis, threadID string) {
	if h.agent == nil {
		h.writeError(w, http.StatusServiceUnavailable, "AI copilot is not configured")
		return
	}
	targetID := mux.Vars(r)["id"]
	uid := h.currentUserID(r)
	var (
		res *agent.StartResult
		err error
	)
	if mode == "hunt" {
		res, err = h.agent.StartHuntOn(r.Context(), targetID, uid, hypothesis, threadID)
	} else {
		res, err = h.agent.StartChatOn(r.Context(), targetID, uid, content, threadID)
	}
	if err != nil {
		if agent.IsBusy(err) {
			h.writeError(w, http.StatusConflict, err.Error())
			return
		}
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeJSON(w, http.StatusAccepted, map[string]any{"data": res, "success": true})
}

func (h *Handler) handleAgentCancel(w http.ResponseWriter, r *http.Request) {
	if h.agent == nil {
		h.writeError(w, http.StatusServiceUnavailable, "AI copilot is not configured")
		return
	}
	ok := h.agent.Cancel(mux.Vars(r)["id"])
	h.writeSuccess(w, map[string]any{"cancelled": ok})
}
