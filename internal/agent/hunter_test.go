package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
)

func TestEnsureThreadKeepsHunterAndCopilotSeparate(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	st := NewStore(db)
	chat, err := st.EnsureThread(context.Background(), tid, 1, modeChat)
	if err != nil {
		t.Fatal(err)
	}
	hunt, err := st.EnsureThread(context.Background(), tid, 0, modeAlwaysOn)
	if err != nil {
		t.Fatal(err)
	}
	if chat.ID == hunt.ID {
		t.Fatal("copilot and 24/7 hunter must not share a thread")
	}
	got, err := st.GetThread(context.Background(), tid)
	if err != nil || got == nil || got.ID != chat.ID {
		t.Fatalf("operator GetThread should be copilot, got %+v err=%v", got, err)
	}
}

func TestPickPlaybookSkipsClosedReflection(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	if _, err := db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, source, is_reflected) VALUES (?,?,?,?,?,?,1)`,
		uuid.New().String(), tid, "https://app.example.test/search", "q", "x", "html"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO agent_hunter_suppress (id, target_id, url, parameter, kind, until)
		VALUES (?,?,?,?, 'dead_end', datetime('now','+7 days'))`,
		uuid.New().String(), tid, "https://app.example.test/search", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO directory_findings (id, target_id, url, status_code) VALUES (?,?,?,200)`,
		uuid.New().String(), tid, "https://app.example.test/.git"); err != nil {
		t.Fatal(err)
	}
	pb := pickPlaybook(context.Background(), db, tid)
	if pb.Name == "reflection" {
		t.Fatalf("suppressed reflected params must not force reflection, got %s", pb.Name)
	}
}

func TestPickPlaybookSkipsXSSOnlyCandidates(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	if _, err := db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, status) VALUES (?,?,?,?,?, 'candidate')`,
		uuid.New().String(), tid, "xss", "high", "https://app.example.test/q"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO directory_findings (id, target_id, url, status_code) VALUES (?,?,?,200)`,
		uuid.New().String(), tid, "https://app.example.test/.git"); err != nil {
		t.Fatal(err)
	}
	pb := pickPlaybook(context.Background(), db, tid)
	if pb.Name == "candidates" {
		t.Fatalf("xss-only candidates must not lock the candidates lane, got %s", pb.Name)
	}
}

func TestPickPlaybookWatchtower(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	if _, err := db.Exec(`INSERT INTO monitoring_changes (id, target_id, url, change_type, new_value, detected_at)
		VALUES (?,?,?,?,?, CURRENT_TIMESTAMP)`, uuid.New().String(), tid, "https://app.example.test/new", "new_host", "x"); err != nil {
		t.Fatal(err)
	}
	pb := pickPlaybook(context.Background(), db, tid)
	if pb.Name != "watchtower" {
		t.Fatalf("playbook=%s", pb.Name)
	}
}

func TestRememberAndInterestingParams(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "remember", `{"kind":"dead_end","content":"search q is encoded"}`)
	if !strings.Contains(res.JSON, `"stored":true`) {
		t.Fatalf("%s", res.JSON)
	}
	if _, err := db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, source, is_reflected)
		VALUES (?,?,?,?,?,?,1)`, uuid.New().String(), tid, "https://app.example.test/", "next", "/", "crawl"); err != nil {
		t.Fatal(err)
	}
	res = tb.Dispatch(context.Background(), tid, "interesting_params", `{}`)
	if !strings.Contains(res.JSON, "next") {
		t.Fatalf("%s", res.JSON)
	}
}

func TestHunterBackoffOn502(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{
		AIEnabled: true, XAIAPIKeyField: "k",
		AIHunterEnabled: true, AIHunterIntervalSeconds: 15, AIHunterIterations: 4,
	}
	rt := New(cfg, db, nil, nil)
	rt.SetCompleter(errCompleter{err: fmt.Errorf("inference HTTP 502: bad gateway")})
	rt.hunterLastPick = time.Time{}
	rt.hunterTick(context.Background())
	if !rt.hunterBackingOff() {
		t.Fatal("502 must back the hunter off")
	}
	if rt.HunterStatus().LastTarget != tid {
		t.Fatalf("last target=%s", rt.HunterStatus().LastTarget)
	}
	cycles := rt.HunterStatus().Cycles
	rt.hunterLastPick = time.Time{}
	rt.hunterTick(context.Background())
	if rt.HunterStatus().Cycles != cycles {
		t.Fatalf("backed-off hunter started another cycle: %d -> %d", cycles, rt.HunterStatus().Cycles)
	}
	if rt.Busy(tid) {
		t.Fatal("backoff must not leave the target occupied")
	}
}

func TestHunterDoesNotStartWhenDisabled(t *testing.T) {
	db := testDB(t)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIHunterEnabled: false}
	rt := New(cfg, db, nil, nil)
	rt.SetCompleter(&scriptedCompleter{steps: []CompletionResponse{{Text: "nope"}}})
	rt.StartHunter()
	time.Sleep(20 * time.Millisecond)
	if rt.HunterStatus().Alive {
		t.Fatal("hunter should stay down when disabled")
	}
}

func TestHunterCycleRunsPlaybook(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{
		AIEnabled: true, XAIAPIKeyField: "k", AIModel: "GLM-5.3-Flash",
		AIHunterEnabled: true, AIHunterIntervalSeconds: 15, AIHunterIterations: 4,
	}
	rt := New(cfg, db, nil, nil)
	rt.SetCompleter(&scriptedCompleter{steps: []CompletionResponse{
		{Calls: []FunctionCall{{CallID: "c1", Name: "stop_hunt", Arguments: `{"reason":"nothing_to_do","summary":"cycle ok"}`}}},
	}})
	rt.hunterLastPick = time.Time{}
	rt.hunterTick(context.Background())
	st := rt.HunterStatus()
	if st.LastTarget != tid {
		t.Fatalf("last target=%s want %s summary=%s", st.LastTarget, tid, st.LastSummary)
	}
	if st.Cycles < 1 {
		t.Fatalf("cycles=%d", st.Cycles)
	}
}

func TestMaybeFileLeadFromSummary(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	sum := "Worked the PROD e-signature callback on https://posro-esignature-online.i.example.test/api/DocumentSigner/callback — unauthenticated GET mints fresh commandId UUIDs every hit; POST is 405."
	id, err := tb.maybeFileLeadFromSummary(context.Background(), tid, sum, "leftovers")
	if err != nil || id == "" {
		t.Fatalf("lead id=%s err=%v", id, err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM agent_leads WHERE target_id=? AND status='pending'`, tid).Scan(&n)
	if n != 1 {
		t.Fatalf("pending leads=%d", n)
	}
	id2, err := tb.maybeFileLeadFromSummary(context.Background(), tid, sum, "leftovers")
	if err != nil || id2 != id {
		t.Fatalf("dedup id=%s want %s err=%v", id2, id, err)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM agent_leads WHERE target_id=?`, tid).Scan(&n)
	if n != 1 {
		t.Fatalf("dedup failed, leads=%d", n)
	}
	empty, err := tb.maybeFileLeadFromSummary(context.Background(), tid, "cycle ok", "leftovers")
	if err != nil || empty != "" {
		t.Fatalf("empty summary should not file, got %s err=%v", empty, err)
	}
	capSum := "Stopped at the iteration cap (28). See https://app.example.test/admin"
	capID, err := tb.maybeFileLeadFromSummary(context.Background(), tid, capSum, "leftovers")
	if err != nil || capID != "" {
		t.Fatalf("iteration-cap summary must not file, got %s err=%v", capID, err)
	}
}

func TestNextHunterTargetPicksRunningWhenSkipOff(t *testing.T) {
	db := testDB(t)
	_ = insertTarget(t, db)
	running := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority, scan_status) VALUES (?,?, 'critical', 'running')`, running, "busy.example.test"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIHunterEnabled: true, AIHunterIntervalSeconds: 15, AIHunterSkipRunning: false}
	rt := New(cfg, db, nil, nil)
	id, _ := rt.nextHunterTarget(context.Background())
	if id != running {
		t.Fatalf("skip-running off should pick the critical running target, got %s", id)
	}
}

func TestNextHunterTargetSkipsRunningScan(t *testing.T) {
	db := testDB(t)
	idle := insertTarget(t, db)
	running := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority, scan_status) VALUES (?,?, 'high', 'running')`, running, "busy.example.test"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIHunterEnabled: true, AIHunterIntervalSeconds: 15, AIHunterSkipRunning: true}
	rt := New(cfg, db, nil, nil)
	id, _ := rt.nextHunterTarget(context.Background())
	if id != idle {
		t.Fatalf("picked %s want idle %s", id, idle)
	}
}

func TestNextHunterTargetSkipsStuckLeftovers(t *testing.T) {
	db := testDB(t)
	stuck := insertTarget(t, db)
	other := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, other, "other.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO agent_hunter_state (target_id, enabled, last_playbook, last_summary, last_run)
		VALUES (?,1,'leftovers','Stopped at the iteration cap (28). Review the trace.', '1970-01-02')`, stuck); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO agent_hunter_state (target_id, enabled, last_playbook, last_summary, last_run)
		VALUES (?,1,'reflection','pagination 404', CURRENT_TIMESTAMP)`, other); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIHunterEnabled: true, AIHunterIntervalSeconds: 15}
	rt := New(cfg, db, nil, nil)
	id, _ := rt.nextHunterTarget(context.Background())
	if id != other {
		t.Fatalf("picked %s want other %s (not leftovers-stuck %s)", id, other, stuck)
	}
}

func TestHarvestLeadsFromSummaries(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	sum := "Verified live: unauthenticated GET on https://posro-esignature-online.i.example.test/api/DocumentSigner/callback mints fresh commandId UUIDs; POST/OPTIONS are 405."
	if _, err := db.Exec(`INSERT INTO agent_hunter_state (target_id, enabled, last_playbook, last_summary)
		VALUES (?,1,'leftovers',?)`, tid, sum); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIHunterEnabled: true, AIHunterIntervalSeconds: 15}
	rt := New(cfg, db, nil, nil)
	rt.harvestLeadsFromSummaries(context.Background())
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM agent_leads WHERE target_id=? AND status='pending'`, tid).Scan(&n)
	if n != 1 {
		t.Fatalf("harvested leads=%d", n)
	}
}

func TestStopHuntFilesLeadWhenURLInSummary(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "stop_hunt",
		`{"reason":"found","summary":"Unauth GET https://app.example.test/api/callback mints commandId UUIDs; POST 405."}`,
		CallEnv{Mode: modeAlwaysOn, Playbook: "leftovers"})
	if !res.StopHunt {
		t.Fatal("expected stop")
	}
	if !strings.Contains(res.JSON, "lead_id") {
		t.Fatalf("expected lead_id in %s", res.JSON)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM agent_leads WHERE target_id=? AND status='pending'`, tid).Scan(&n)
	if n != 1 {
		t.Fatalf("pending=%d", n)
	}
}
