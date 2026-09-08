package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
)

type scriptedCompleter struct {
	mu    sync.Mutex
	steps []CompletionResponse
	n     int
	block chan struct{}
}

func (s *scriptedCompleter) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n >= len(s.steps) {
		return &CompletionResponse{Text: "done"}, nil
	}
	step := s.steps[s.n]
	s.n++
	return &step, nil
}

func TestRuntimeToolThenMessage(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIModel: "grok-4.6", AIMaxIterations: 8}
	rt := New(cfg, db, nil, nil)
	script := &scriptedCompleter{steps: []CompletionResponse{
		{Calls: []FunctionCall{{CallID: "c1", Name: "target_brief", Arguments: "{}"}}},
		{Text: "Surface looks quiet."},
	}}
	rt.SetCompleter(script)

	res, err := rt.StartChat(context.Background(), tid, 1, "summarize this target")
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt, tid)

	th, err := rt.GetThread(context.Background(), tid)
	if err != nil || th == nil {
		t.Fatalf("thread: %v %v", th, err)
	}
	if th.ID != res.ThreadID {
		t.Fatalf("thread id mismatch")
	}
	var roles []string
	for _, m := range th.Messages {
		roles = append(roles, m.Role)
	}
	if len(roles) < 4 {
		t.Fatalf("roles=%v", roles)
	}
	foundBrief := false
	for _, m := range th.Messages {
		if m.Role == roleCall && m.ToolName == "target_brief" {
			foundBrief = true
		}
		if m.Role == roleAssistant && m.Content == "Surface looks quiet." {
			foundBrief = foundBrief && true
		}
	}
	if !foundBrief {
		t.Fatalf("missing tool/message in %+v", th.Messages)
	}
}

func TestRuntimeIterationCap(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIMaxIterations: 2}
	rt := New(cfg, db, nil, nil)
	rt.SetCompleter(&scriptedCompleter{steps: []CompletionResponse{
		{Calls: []FunctionCall{{CallID: "c1", Name: "target_brief", Arguments: "{}"}}},
		{Calls: []FunctionCall{{CallID: "c2", Name: "scan_status", Arguments: "{}"}}},
		{Text: "should not reach"},
	}})
	if _, err := rt.StartChat(context.Background(), tid, 1, "go"); err != nil {
		t.Fatal(err)
	}
	waitDone(t, rt, tid)
	th, _ := rt.GetThread(context.Background(), tid)
	var last string
	for _, m := range th.Messages {
		if m.Role == roleAssistant {
			last = m.Content
		}
	}
	if last == "should not reach" {
		t.Fatal("iteration cap did not stop the loop")
	}
	if last == "" || !contains(last, "iteration cap") {
		t.Fatalf("last assistant=%q", last)
	}
}

func TestRuntimeCancel(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIMaxIterations: 8}
	rt := New(cfg, db, nil, nil)
	block := make(chan struct{})
	rt.SetCompleter(&scriptedCompleter{block: block, steps: []CompletionResponse{{Text: "late"}}})
	if _, err := rt.StartChat(context.Background(), tid, 1, "wait"); err != nil {
		t.Fatal(err)
	}
	if !rt.Busy(tid) {
		t.Fatal("expected busy")
	}
	if !rt.Cancel(tid) {
		t.Fatal("cancel returned false")
	}
	waitDone(t, rt, tid)
	close(block)
}

type errCompleter struct{ err error }

func (e errCompleter) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	return nil, e.err
}

func TestCopilotPreemptsHunter(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIMaxIterations: 8}
	rt := New(cfg, db, nil, nil)
	block := make(chan struct{})
	rt.SetCompleter(&scriptedCompleter{block: block, steps: []CompletionResponse{{Text: "ok"}}})
	if _, err := rt.start(context.Background(), tid, 0, modeAlwaysOn, "cycle", ""); err != nil {
		t.Fatal(err)
	}
	if !rt.HunterHolds(tid) {
		t.Fatal("hunter should occupy the target")
	}
	res, err := rt.StartChat(context.Background(), tid, 1, "hi")
	if err != nil {
		t.Fatalf("copilot should preempt hunter, got %v", err)
	}
	if res == nil || res.ThreadID == "" {
		t.Fatal("missing copilot thread")
	}
	if rt.HunterHolds(tid) {
		t.Fatal("hunter must yield after copilot starts")
	}
	if !rt.Busy(tid) {
		t.Fatal("copilot should be live")
	}
	th, _ := rt.GetThread(context.Background(), tid)
	if th == nil || th.HunterActive {
		t.Fatalf("operator thread hunter_active=%v", th)
	}
	rt.Cancel(tid)
	close(block)
	waitDone(t, rt, tid)
}

func TestHunterDoesNotPreemptCopilot(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k"}
	rt := New(cfg, db, nil, nil)
	block := make(chan struct{})
	rt.SetCompleter(&scriptedCompleter{block: block, steps: []CompletionResponse{{Text: "ok"}}})
	if _, err := rt.StartChat(context.Background(), tid, 1, "one"); err != nil {
		t.Fatal(err)
	}
	_, err := rt.start(context.Background(), tid, 0, modeAlwaysOn, "cycle", "")
	if !IsBusy(err) {
		t.Fatalf("hunter must not preempt copilot, got %v", err)
	}
	if rt.HunterHolds(tid) {
		t.Fatal("hunter must not hold the slot")
	}
	close(block)
	waitDone(t, rt, tid)
}

func TestGetThreadHunterActive(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k"}
	rt := New(cfg, db, nil, nil)
	block := make(chan struct{})
	rt.SetCompleter(&scriptedCompleter{block: block, steps: []CompletionResponse{{Text: "ok"}}})
	if _, err := rt.store.EnsureThread(context.Background(), tid, 1, modeChat); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.start(context.Background(), tid, 0, modeAlwaysOn, "cycle", ""); err != nil {
		t.Fatal(err)
	}
	th, err := rt.GetThread(context.Background(), tid)
	if err != nil || th == nil {
		t.Fatalf("thread: %v %v", th, err)
	}
	if !th.HunterActive {
		t.Fatal("expected hunter_active on operator thread")
	}
	rt.Cancel(tid)
	close(block)
	waitDone(t, rt, tid)
}

func TestRuntimeBusyConflict(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k"}
	rt := New(cfg, db, nil, nil)
	block := make(chan struct{})
	rt.SetCompleter(&scriptedCompleter{block: block, steps: []CompletionResponse{{Text: "ok"}}})
	if _, err := rt.StartChat(context.Background(), tid, 1, "one"); err != nil {
		t.Fatal(err)
	}
	_, err := rt.StartChat(context.Background(), tid, 1, "two")
	if !IsBusy(err) {
		t.Fatalf("want busy, got %v", err)
	}
	close(block)
	waitDone(t, rt, tid)
}

func TestRuntimeDisabled(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	rt := New(&config.Config{AIEnabled: false, XAIAPIKeyField: "k"}, db, nil, nil)
	rt.SetCompleter(&scriptedCompleter{})
	if _, err := rt.StartChat(context.Background(), tid, 1, "hi"); err == nil {
		t.Fatal("expected disabled error")
	}
}

func TestReclaimOrphansOnNew(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	st := NewStore(db)
	th, err := st.EnsureThread(context.Background(), tid, 1, modeChat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.StartRun(context.Background(), th.ID, tid); err != nil {
		t.Fatal(err)
	}
	stuck, _ := st.GetThreadByMode(context.Background(), tid, modeChat)
	if stuck == nil || stuck.Status != statusRunning {
		t.Fatalf("setup status=%v", stuck)
	}

	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k"}
	rt := New(cfg, db, nil, nil)
	got, err := rt.GetThread(context.Background(), tid)
	if err != nil || got == nil {
		t.Fatalf("thread: %v %v", got, err)
	}
	if got.Status == statusRunning {
		t.Fatalf("orphaned running status survived process start: %s", got.Status)
	}
}

func TestGetThreadReclaimsStaleRunning(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k"}
	rt := New(cfg, db, nil, nil)
	th, err := rt.store.EnsureThread(context.Background(), tid, 1, modeChat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.store.StartRun(context.Background(), th.ID, tid); err != nil {
		t.Fatal(err)
	}
	got, err := rt.GetThread(context.Background(), tid)
	if err != nil || got == nil {
		t.Fatalf("thread: %v %v", got, err)
	}
	if got.Status == statusRunning {
		t.Fatal("GetThread left a stale running status")
	}
}

func TestCancelUnsticksOrphanedThread(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k"}
	rt := New(cfg, db, nil, nil)
	th, err := rt.store.EnsureThread(context.Background(), tid, 1, modeChat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.store.StartRun(context.Background(), th.ID, tid); err != nil {
		t.Fatal(err)
	}
	if rt.Busy(tid) {
		t.Fatal("orphan must not look live")
	}
	if !rt.Cancel(tid) {
		t.Fatal("cancel should reclaim an orphaned chat thread")
	}
	got, _ := rt.store.GetThreadByMode(context.Background(), tid, modeChat)
	if got == nil || got.Status == statusRunning {
		t.Fatalf("status=%v", got)
	}
}

func waitDone(t *testing.T, rt *Runtime, targetID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !rt.Busy(targetID) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run did not finish")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}
