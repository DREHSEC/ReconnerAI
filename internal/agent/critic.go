package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

const criticSystemPrompt = `You are a senior bug-bounty reviewer sitting on Reconner's hunter inbox. You do not hunt. You only keep, dismiss, or rewrite PENDING leads from this cycle.

Keep: authorization/object access, JS-only or undocumented APIs, GraphQL, JWT, leftovers (.git/.env/actuator/swagger), odd internal hosts, watchtower diffs that imply a new capability, chained bugs.
Dismiss: another reflected XSS on a marketing/search param, duplicate of an existing pending lead, speculation without a URL, out-of-scope noise.
Rewrite: keep the idea but make title+body operator-ready (URL, method, why it is not XSS spam).

Reply with JSON only:
{"decisions":[{"id":"...","action":"keep|dismiss|rewrite","title":"","body":"","reason":""}]}
Do not invent lead ids. Do not claim a verified finding.`

type criticDecision struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	Reason string `json:"reason"`
}

type criticPayload struct {
	Decisions []criticDecision `json:"decisions"`
}

func parseCriticJSON(raw string) []criticDecision {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if i := strings.Index(raw, "{"); i >= 0 {
		if j := strings.LastIndex(raw, "}"); j > i {
			raw = raw[i : j+1]
		}
	}
	var p criticPayload
	if json.Unmarshal([]byte(raw), &p) == nil {
		return p.Decisions
	}
	var arr []criticDecision
	if json.Unmarshal([]byte(raw), &arr) == nil {
		return arr
	}
	return nil
}

func (r *Runtime) critiqueRecentLeads(ctx context.Context, targetID, summary string) {
	if r == nil || r.client == nil || r.store == nil || r.store.db == nil {
		return
	}
	if ctx.Err() != nil {
		return
	}
	rows, err := r.store.db.QueryContext(ctx, `
		SELECT id, COALESCE(title,''), COALESCE(body,''), COALESCE(url,''), COALESCE(playbook,''), COALESCE(severity,'')
		FROM agent_leads WHERE target_id=? AND status='pending' AND created_at >= datetime('now','-20 minutes')
		ORDER BY created_at DESC LIMIT 8`, targetID)
	if err != nil {
		return
	}
	type lead struct {
		ID, Title, Body, URL, Playbook, Severity string
	}
	var leads []lead
	for rows.Next() {
		var x lead
		if rows.Scan(&x.ID, &x.Title, &x.Body, &x.URL, &x.Playbook, &x.Severity) == nil {
			leads = append(leads, x)
		}
	}
	rows.Close()
	if len(leads) == 0 {
		return
	}
	b, _ := json.Marshal(map[string]any{"summary": clip(summary, 800), "leads": leads})
	model := "GLM-5.3-Flash"
	if r.cfg != nil {
		r.cfg.NormalizeAI()
		model = r.cfg.AIModel
	}
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	resp, err := r.client.Complete(cctx, CompletionRequest{
		Model: model,
		Input: []InputItem{
			{Role: "system", Content: criticSystemPrompt},
			{Role: "user", Content: string(b)},
		},
	})
	if err != nil || resp == nil {
		return
	}
	for _, d := range parseCriticJSON(resp.Text) {
		id := strings.TrimSpace(d.ID)
		if id == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(d.Action)) {
		case "dismiss":
			_, _ = r.store.db.ExecContext(ctx, `UPDATE agent_leads SET status='dismissed', updated_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=? AND status='pending'`, id, targetID)
			_, _ = r.store.db.ExecContext(ctx, `INSERT INTO agent_hunter_notes (id, target_id, kind, content) VALUES (?,?,?,?)`,
				newNoteID(), targetID, "critic", clip("dismissed "+id+": "+d.Reason, 400))
		case "rewrite":
			title, body := strings.TrimSpace(d.Title), strings.TrimSpace(d.Body)
			if title == "" && body == "" {
				continue
			}
			if title == "" {
				title = d.Reason
			}
			_, _ = r.store.db.ExecContext(ctx, `UPDATE agent_leads SET title=COALESCE(NULLIF(?,''),title), body=COALESCE(NULLIF(?,''),body), updated_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=? AND status='pending'`,
				clip(title, 120), clip(body, 1200), id, targetID)
		default:
			// keep
		}
	}
}

func newNoteID() string { return uuid.New().String() }
