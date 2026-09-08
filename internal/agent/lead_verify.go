package agent

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scheduler"
)

// LeadVerifyStarter enqueues a URL-scoped verify without replanning recon.
type LeadVerifyStarter interface {
	CreateLeadVerifyTask(targetID string, modules []string, scopeOverride string) (*models.Task, error)
}

// ModulesForLead picks a small detector set for an operator-confirmed hunter
// lead. verify is always included. Recon is NOT expanded here — the scheduler
// call uses replan=false so this stays a focused pass on the lead URL.
func ModulesForLead(playbook, title, body string, identityCount int) []string {
	hay := strings.ToLower(playbook + " " + title + " " + body)
	seen := map[string]bool{}
	out := []string{scheduler.ModuleVerify}
	seen[scheduler.ModuleVerify] = true
	add := func(m string) {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "" || seen[m] {
			return
		}
		if m == scheduler.ModuleIDOR && identityCount < 2 {
			return
		}
		seen[m] = true
		out = append(out, m)
	}

	switch strings.ToLower(strings.TrimSpace(playbook)) {
	case "authz", "authz_surface":
		add(scheduler.ModuleIDOR)
	case "watchtower":
		add(scheduler.ModuleExposure)
	case "reflection":
		add(scheduler.ModuleXSS)
		add(scheduler.ModuleOpenRedirect)
	case "js_shadow":
		add(scheduler.ModuleJWT)
	case "leftovers":
		add(scheduler.ModuleExposure)
	}

	switch {
	case strings.Contains(hay, "sqli") || strings.Contains(hay, "sql injection"):
		add(scheduler.ModuleSQLi)
	case strings.Contains(hay, "ssrf"):
		add(scheduler.ModuleSSRF)
	case strings.Contains(hay, "ssti"):
		add(scheduler.ModuleSSTI)
	case strings.Contains(hay, "csti"):
		add(scheduler.ModuleCSTI)
	case strings.Contains(hay, "cmdi") || strings.Contains(hay, "command injection") || strings.Contains(hay, "rce"):
		add(scheduler.ModuleCmdi)
	case strings.Contains(hay, "lfi") || strings.Contains(hay, "path traversal"):
		add(scheduler.ModuleLFI)
	case strings.Contains(hay, "xss") || strings.Contains(hay, "script"):
		add(scheduler.ModuleXSS)
	case strings.Contains(hay, "redirect"):
		add(scheduler.ModuleOpenRedirect)
	case strings.Contains(hay, "idor") || strings.Contains(hay, "bola") || strings.Contains(hay, "authz"):
		add(scheduler.ModuleIDOR)
	}

	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

// EnqueueLeadVerify marks nothing — the handler already flipped status.
// It reads the lead URL and enqueues a scoped verify. Nil starter is a no-op.
func EnqueueLeadVerify(ctx context.Context, db *database.DB, start LeadVerifyStarter, targetID, leadID string) (taskID string, modules []string, err error) {
	if db == nil || strings.TrimSpace(leadID) == "" {
		return "", nil, nil
	}
	var rawURL, playbook, title, body string
	err = db.QueryRowContext(ctx, `
		SELECT COALESCE(url,''), COALESCE(playbook,''), COALESCE(title,''), COALESCE(body,'')
		FROM agent_leads WHERE id=? AND target_id=?`, leadID, targetID).
		Scan(&rawURL, &playbook, &title, &body)
	if err != nil {
		return "", nil, fmt.Errorf("lead not found")
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", nil, nil
	}
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		if !strings.Contains(rawURL, "://") {
			rawURL = "https://" + rawURL
		}
	}
	if start == nil {
		return "", nil, nil
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identities WHERE target_id=?`, targetID).Scan(&n)
	modules = ModulesForLead(playbook, title, body, n)
	task, err := start.CreateLeadVerifyTask(targetID, modules, rawURL)
	if err != nil {
		return "", modules, err
	}
	if task == nil {
		return "", modules, nil
	}
	_, _ = db.ExecContext(ctx, `UPDATE agent_leads SET verify_task_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=?`,
		task.ID, leadID, targetID)
	return task.ID, task.Modules, nil
}
