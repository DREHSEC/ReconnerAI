package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scanner"
	"github.com/recon-platform/internal/secret"
)

func (s *Scheduler) CreateGuidedTask(targetID, runID string, modules []string) (*models.Task, error) {
	return s.createTask(targetID, modules, 5, "guided_capture", runID, false)
}

func (s *Scheduler) executeGuidedTask(parent context.Context, taskID, targetID, runID string) {
	res, e := s.db.Exec(`UPDATE tasks SET status='running',started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'`, taskID)
	if e != nil {
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return
	}
	s.hub.Broadcast("task_started", map[string]string{"task_id": taskID, "target_id": targetID})
	s.refreshTargetScanStatus(targetID, "running", false)
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	box := secret.New(s.cfg.SessionSecret)
	status, message := "finished", ""
	logFn := func(level, module, message string) {
		_, _ = s.db.Exec(`INSERT INTO task_logs(task_id,level,module,message) VALUES(?,?,?,?)`, taskID, level, module, message)
	}
	var sealed string
	var input scanner.GuidedInput
	var runErr error
	if e := s.db.QueryRow(`SELECT encrypted_input FROM guided_runs WHERE id=? AND target_id=?`, runID, targetID).Scan(&sealed); e != nil {
		runErr = e
	} else if e = json.Unmarshal([]byte(box.Decrypt(sealed)), &input); e != nil {
		runErr = e
	} else {
		total := scanner.GuidedCheckCount(input)
		_, _ = s.db.Exec(`UPDATE tasks SET total=? WHERE id=?`, total, taskID)
		_, runErr = scanner.RunGuided(ctx, s.db, targetID, input, func(raw string) bool { return scanner.GuidedURLInScope(ctx, s.db, targetID, raw) }, func(report scanner.GuidedReport) {
			b, _ := json.Marshal(report)
			safe, _ := json.Marshal(scanner.PublicGuidedReport(report))
			enc := box.Encrypt(string(b))
			if !strings.HasPrefix(enc, "enc:v1:") {
				cancel()
				return
			}
			if _, e := s.db.Exec(`UPDATE guided_runs SET encrypted_report=?,redacted_report=? WHERE id=? AND target_id=?`, enc, string(safe), runID, targetID); e != nil {
				cancel()
				return
			}
			latest := report.Results[len(report.Results)-1]
			_, _ = s.db.Exec(`UPDATE tasks SET progress=?,current_module=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, len(report.Results), latest.Module, taskID)
			s.hub.Broadcast("task_progress", map[string]any{"task_id": taskID, "target_id": targetID, "progress": len(report.Results), "total": total, "current_module": latest.Module})
			logFn("info", latest.Module, fmt.Sprintf("Template %s: %s (%d requests, %d findings). %s", latest.TemplateID, latest.Status, latest.Requests, len(latest.Findings), latest.Reason))
			// Guided execution is intentionally monolithic, so its progress boundary
			// is also its module-boundary pause gate. The in-flight check completes,
			// then no next template/module starts until the operator resumes.
			s.waitIfPaused(ctx, taskID, logFn)
		})
	}
	if runErr != nil {
		status = "failed"
		message = "Guided run stopped; inspect partial results and task logs"
	}
	var persistedStatus string
	_ = s.db.QueryRow(`SELECT status FROM tasks WHERE id=?`, taskID).Scan(&persistedStatus)
	if persistedStatus == InterruptedStatus {
		status, message = InterruptedStatus, ""
	} else if persistedStatus == "cancelled" || parent.Err() != nil {
		status = "cancelled"
		message = ""
	}
	_, _ = s.db.Exec(`UPDATE tasks SET status=?,error=?,current_module='',finished_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status NOT IN ('interrupted','cancelled')`, status, message, taskID)
	s.pauseMu.Lock()
	delete(s.paused, taskID)
	s.pauseMu.Unlock()
	targetStatus := "idle"
	if status == "failed" {
		targetStatus = "failed"
	} else if status == InterruptedStatus {
		targetStatus = "paused"
	}
	s.refreshTargetScanStatus(targetID, targetStatus, status != InterruptedStatus)
	s.hub.Broadcast("task_finished", map[string]string{"task_id": taskID, "target_id": targetID, "status": status})
}
