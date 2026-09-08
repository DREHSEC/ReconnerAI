package agent

import (
	"context"
	"strings"
	"time"
)

// HunterSnapshot is the operator-facing 24/7 hunter status.
type HunterSnapshot struct {
	Enabled         bool       `json:"enabled"`
	Alive           bool       `json:"alive"`
	CurrentTarget   string     `json:"current_target,omitempty"`
	CurrentDomain   string     `json:"current_domain,omitempty"`
	CurrentPlaybook string     `json:"current_playbook,omitempty"`
	LastTarget      string     `json:"last_target,omitempty"`
	LastDomain      string     `json:"last_domain,omitempty"`
	LastPlaybook    string     `json:"last_playbook,omitempty"`
	LastSummary     string     `json:"last_summary,omitempty"`
	LastAt          *time.Time `json:"last_at,omitempty"`
	Cycles          int        `json:"cycles"`
	Watching        int        `json:"watching"`
	IntervalSeconds int        `json:"interval_seconds"`
	Iterations      int        `json:"iterations"`
}

func (r *Runtime) StartHunter() {
	if r == nil || r.cfg == nil {
		return
	}
	r.cfg.NormalizeAI()
	if !r.cfg.AIHunterEnabled {
		return
	}
	r.hunterMu.Lock()
	if r.hunterStop != nil {
		r.hunterMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.hunterStop = cancel
	r.hunterMu.Unlock()
	go r.hunterLoop(ctx)
}

func (r *Runtime) StopHunter() {
	r.hunterMu.Lock()
	cancel := r.hunterStop
	r.hunterStop = nil
	r.hunterMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *Runtime) HunterStatus() HunterSnapshot {
	r.hunterMu.Lock()
	snap := r.hunterSnap
	alive := r.hunterStop != nil
	r.hunterMu.Unlock()
	snap.Alive = alive
	if r.cfg != nil {
		r.cfg.NormalizeAI()
		snap.Enabled = r.cfg.AIHunterEnabled && r.cfg.AIEnabled
		snap.IntervalSeconds = r.cfg.AIHunterIntervalSeconds
		snap.Iterations = r.cfg.AIHunterIterations
	}
	if r.store != nil && r.store.db != nil {
		_ = r.store.db.QueryRow(`SELECT COUNT(*) FROM targets`).Scan(&snap.Watching)
	}
	return snap
}

func (r *Runtime) hunterLoop(ctx context.Context) {
	tick := time.NewTicker(8 * time.Second)
	defer tick.Stop()
	r.hunterTick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.hunterTick(ctx)
		}
	}
}

const hunterInferenceBackoff = 5 * time.Minute

func retryableInference(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "429") || strings.Contains(s, "rate limit") || strings.Contains(s, "overloaded") {
		return true
	}
	return strings.Contains(s, "inference http 502") ||
		strings.Contains(s, "inference http 503") ||
		strings.Contains(s, "inference http 504")
}

func (r *Runtime) noteHunterBackoff(d time.Duration) {
	if r == nil || d <= 0 {
		return
	}
	r.hunterMu.Lock()
	r.hunterFailUntil = time.Now().Add(d)
	r.hunterMu.Unlock()
}

func (r *Runtime) hunterBackingOff() bool {
	if r == nil {
		return false
	}
	r.hunterMu.Lock()
	defer r.hunterMu.Unlock()
	return time.Now().Before(r.hunterFailUntil)
}

func (r *Runtime) hunterTick(ctx context.Context) {
	if r.cfg == nil || !r.cfg.AIHunterEnabled || r.Ready() != nil {
		return
	}
	if r.hunterBackingOff() {
		return
	}
	r.harvestLeadsFromSummaries(ctx)
	interval := time.Duration(r.cfg.AIHunterIntervalSeconds) * time.Second
	if interval < 15*time.Second {
		interval = 15 * time.Second
	}
	r.hunterMu.Lock()
	lastPick := r.hunterLastPick
	r.hunterMu.Unlock()
	if !lastPick.IsZero() && time.Since(lastPick) < interval {
		return
	}
	id, domain := r.nextHunterTarget(ctx)
	if id == "" {
		return
	}
	if r.Busy(id) {
		return
	}
	pb := pickPlaybook(ctx, r.store.db, id)
	r.setRunEnv(id, CallEnv{Mode: modeAlwaysOn, Playbook: pb.Name, ScanAllow: pb.ScanModules})
	r.hunterMu.Lock()
	r.hunterLastPick = time.Now()
	r.hunterSnap.CurrentTarget = id
	r.hunterSnap.CurrentDomain = domain
	r.hunterSnap.CurrentPlaybook = pb.Name
	r.hunterMu.Unlock()
	r.emit(Event{
		TargetID: id, Kind: "hunter_cycle",
		Payload: map[string]string{"playbook": pb.Name, "domain": domain, "phase": "start"},
	})

	user := pb.Brief
	_, err := r.start(ctx, id, 0, modeAlwaysOn, user, "")
	if err != nil {
		r.finishHunterCycle(id, domain, pb.Name, "could not start: "+err.Error())
		return
	}
	cycleMin := 12
	if r.cfg != nil && r.cfg.AIHunterCycleMinutes > 0 {
		cycleMin = r.cfg.AIHunterCycleMinutes
	}
	deadline := time.Now().Add(time.Duration(cycleMin) * time.Minute)
	for r.Busy(id) && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	summary := r.lastHunterAssistant(ctx, id)
	if r.tools != nil {
		_, _ = r.tools.maybeFileLeadFromSummary(ctx, id, summary, pb.Name)
	}
	r.finishHunterCycle(id, domain, pb.Name, summary)
}

func (r *Runtime) nextHunterTarget(ctx context.Context) (id, domain string) {
	rows, err := r.store.db.QueryContext(ctx, `
		SELECT t.id, t.domain, COALESCE(t.scan_status,'idle'),
			COALESCE(s.last_playbook,''), COALESCE(s.last_summary,''),
			COALESCE((SELECT COUNT(*) FROM monitoring_changes mc WHERE mc.target_id=t.id
			          AND mc.detected_at > COALESCE(s.last_run,'1970-01-01')),0) AS fresh
		FROM targets t
		LEFT JOIN agent_hunter_state s ON s.target_id=t.id
		WHERE COALESCE(s.enabled,1)=1
		ORDER BY fresh DESC,
			CASE t.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
			COALESCE(s.last_run,'1970-01-01') ASC
		LIMIT 30`)
	if err != nil {
		return "", ""
	}
	defer rows.Close()
	type cand struct {
		id, domain, scan, playbook, summary string
		fresh                               int
	}
	var idle, running []cand
	for rows.Next() {
		var c cand
		if rows.Scan(&c.id, &c.domain, &c.scan, &c.playbook, &c.summary, &c.fresh) != nil {
			continue
		}
		if r.Busy(c.id) {
			continue
		}
		skipRun := true
		if r.cfg != nil {
			skipRun = r.cfg.AIHunterSkipRunning
		}
		if skipRun && strings.EqualFold(c.scan, "running") {
			running = append(running, c)
			continue
		}
		idle = append(idle, c)
	}
	pick := func(list []cand, allowLeftoversStuck bool) (string, string) {
		for _, c := range list {
			if !allowLeftoversStuck && leftoversStuck(c.playbook, c.summary) && (len(list) > 1 || len(running)+len(idle) > 1) {
				continue
			}
			return c.id, c.domain
		}
		return "", ""
	}
	if id, domain := pick(idle, false); id != "" {
		return id, domain
	}
	if id, domain := pick(idle, true); id != "" {
		return id, domain
	}
	return pick(running, true)
}

func (r *Runtime) harvestLeadsFromSummaries(ctx context.Context) {
	if r.tools == nil || r.store == nil || r.store.db == nil {
		return
	}
	rows, err := r.store.db.QueryContext(ctx, `
		SELECT target_id, COALESCE(last_playbook,''), COALESCE(last_summary,'')
		FROM agent_hunter_state WHERE COALESCE(last_summary,'') != '' LIMIT 40`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid, pb, sum string
		if rows.Scan(&tid, &pb, &sum) != nil {
			continue
		}
		_, _ = r.tools.maybeFileLeadFromSummary(ctx, tid, sum, pb)
	}
}

func leftoversStuck(playbook, summary string) bool {
	if !strings.EqualFold(strings.TrimSpace(playbook), "leftovers") {
		return false
	}
	s := strings.ToLower(summary)
	return strings.Contains(s, "iteration cap") || strings.Contains(s, "stopped at the iteration")
}

func (r *Runtime) lastHunterAssistant(ctx context.Context, targetID string) string {
	th, err := r.store.GetThreadByMode(ctx, targetID, modeAlwaysOn)
	if err != nil || th == nil {
		return ""
	}
	for i := len(th.Messages) - 1; i >= 0; i-- {
		if th.Messages[i].Role == roleAssistant && th.Messages[i].Content != "" {
			return clip(th.Messages[i].Content, 800)
		}
	}
	return ""
}

func (r *Runtime) finishHunterCycle(targetID, domain, playbook, summary string) {
	now := time.Now()
	var findings int
	if r.store != nil && r.store.db != nil {
		_ = r.store.db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='finding'`, targetID).Scan(&findings)
		_, _ = r.store.db.Exec(`
			INSERT INTO agent_hunter_state (target_id, enabled, last_run, last_playbook, last_summary, cycle_count, last_finding_count, updated_at)
			VALUES (?,1,?,?,?,1,?,CURRENT_TIMESTAMP)
			ON CONFLICT(target_id) DO UPDATE SET
				last_run=excluded.last_run,
				last_playbook=excluded.last_playbook,
				last_summary=excluded.last_summary,
				cycle_count=cycle_count+1,
				last_finding_count=excluded.last_finding_count,
				updated_at=CURRENT_TIMESTAMP`,
			targetID, now.UTC().Format("2006-01-02 15:04:05"), playbook, clip(summary, 1500), findings)
	}
	r.hunterMu.Lock()
	r.hunterSnap.LastTarget = targetID
	r.hunterSnap.LastDomain = domain
	r.hunterSnap.LastPlaybook = playbook
	r.hunterSnap.LastSummary = clip(summary, 400)
	r.hunterSnap.LastAt = &now
	r.hunterSnap.Cycles++
	r.hunterSnap.CurrentTarget = ""
	r.hunterSnap.CurrentDomain = ""
	r.hunterSnap.CurrentPlaybook = ""
	r.hunterMu.Unlock()
	r.emit(Event{
		TargetID: targetID, Kind: "hunter_cycle",
		Payload: map[string]string{"playbook": playbook, "domain": domain, "phase": "done", "summary": clip(summary, 400)},
	})
}

func (r *Runtime) HunterLog(ctx context.Context, limit int) []map[string]any {
	if limit <= 0 || limit > 40 {
		limit = 12
	}
	rows, err := r.store.db.QueryContext(ctx, `
		SELECT s.target_id, t.domain, COALESCE(s.last_playbook,''), COALESCE(s.last_summary,''),
		       COALESCE(s.cycle_count,0), s.last_run
		FROM agent_hunter_state s
		JOIN targets t ON t.id=s.target_id
		ORDER BY s.last_run DESC LIMIT ?`, limit)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var tid, domain, pb, sum, last string
		var cycles int
		if rows.Scan(&tid, &domain, &pb, &sum, &cycles, &last) != nil {
			continue
		}
		out = append(out, map[string]any{
			"target_id": tid, "domain": domain, "playbook": pb,
			"summary": clip(sum, 280), "cycles": cycles, "last_run": last,
		})
	}
	return out
}
