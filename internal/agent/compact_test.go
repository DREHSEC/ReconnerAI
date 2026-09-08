package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
)

func TestEstimateTokens(t *testing.T) {
	if estimateTokens("") != 0 {
		t.Fatal("empty")
	}
	if got := estimateTokens(strings.Repeat("a", 40)); got != 10 {
		t.Fatalf("got %d", got)
	}
	if tokenBudget != 20000 {
		t.Fatalf("budget=%d", tokenBudget)
	}
}

func TestSplitForCompactKeepsLastUserTurns(t *testing.T) {
	var msgs []Message
	for i := 0; i < 6; i++ {
		msgs = append(msgs, Message{Role: roleUser, Content: "u" + itoa(i)})
		msgs = append(msgs, Message{Role: roleAssistant, Content: "a" + itoa(i)})
	}
	old, recent := splitForCompact(msgs, 2)
	if len(old) == 0 || len(recent) == 0 {
		t.Fatalf("old=%d recent=%d", len(old), len(recent))
	}
	if recent[0].Content != "u4" {
		t.Fatalf("recent start=%q", recent[0].Content)
	}
	if old[len(old)-1].Content != "a3" {
		t.Fatalf("old end=%q", old[len(old)-1].Content)
	}
}

func TestSplitForCompactNoOpWhenShort(t *testing.T) {
	msgs := []Message{
		{Role: roleUser, Content: "hi"},
		{Role: roleAssistant, Content: "hello"},
	}
	old, recent := splitForCompact(msgs, 4)
	if old != nil || len(recent) != 2 {
		t.Fatalf("old=%v recent=%d", old, len(recent))
	}
}

func TestExtractiveCompactDropsRawDumps(t *testing.T) {
	old := []Message{
		{Role: roleUser, Content: "look at /login"},
		{Role: roleCall, ToolName: "http_request", Content: `{"url":"https://app.example.test/login"}`},
		{Role: roleTool, ToolName: "http_request", Content: strings.Repeat("HTML", 400)},
		{Role: roleAssistant, Content: "login is 200, no session"},
	}
	s := extractiveCompact(old)
	if !strings.Contains(s, "Operator: look at /login") {
		t.Fatalf("%s", s)
	}
	if !strings.Contains(s, "login is 200") {
		t.Fatalf("%s", s)
	}
	if len(s) > 2000 {
		t.Fatalf("extractive too large: %d", len(s))
	}
}

func TestCompactPersistsMemory(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIMaxIterations: 8}
	rt := New(cfg, db, nil, nil)
	rt.SetCompleter(&scriptedCompleter{steps: []CompletionResponse{{Text: "Memory: login 200, no session cookie. Next: check /admin."}}})
	th, err := rt.store.CreateThread(context.Background(), tid, 1, modeChat, "surface")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 6; i++ {
		if _, err := rt.store.Append(context.Background(), th.ID, roleUser, "turn "+itoa(i)+" "+strings.Repeat("x", 200), "", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := rt.store.Append(context.Background(), th.ID, roleAssistant, "reply "+itoa(i)+" "+strings.Repeat("y", 200), "", ""); err != nil {
			t.Fatal(err)
		}
		_ = base
	}
	got, err := rt.store.GetThreadByID(context.Background(), th.ID)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	res, err := rt.Compact(context.Background(), tid, th.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Compacted {
		t.Fatalf("not compacted: %+v", res)
	}
	if !strings.Contains(res.Summary, "login 200") && !strings.Contains(res.Summary, "Operator:") {
		t.Fatalf("summary=%q", res.Summary)
	}
	reload, _ := rt.store.GetThreadByID(context.Background(), th.ID)
	if strings.TrimSpace(reload.CompactSummary) == "" {
		t.Fatal("compact_summary not persisted")
	}
	if reload.CompactAfter.IsZero() {
		t.Fatal("compact_after not set")
	}
}

func TestListThreadsSkipsHunter(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	st := NewStore(db)
	if _, err := st.CreateThread(context.Background(), tid, 1, modeChat, "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureThread(context.Background(), tid, 0, modeAlwaysOn); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListThreads(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Title != "alpha" {
		t.Fatalf("%+v", list)
	}
}

func TestStartChatOnUsesRequestedThread(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIMaxIterations: 4}
	rt := New(cfg, db, nil, nil)
	rt.SetCompleter(&scriptedCompleter{steps: []CompletionResponse{{Text: "ok"}}})
	a, _ := rt.store.CreateThread(context.Background(), tid, 1, modeChat, "A")
	b, _ := rt.store.CreateThread(context.Background(), tid, 1, modeChat, "B")
	res, err := rt.StartChatOn(context.Background(), tid, 1, "hello B", b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.ThreadID != b.ID {
		t.Fatalf("thread=%s want %s", res.ThreadID, b.ID)
	}
	waitDone(t, rt, tid)
	got, _ := rt.store.GetThreadByID(context.Background(), b.ID)
	if len(got.Messages) < 2 {
		t.Fatalf("b messages=%d", len(got.Messages))
	}
	other, _ := rt.store.GetThreadByID(context.Background(), a.ID)
	if len(other.Messages) != 0 {
		t.Fatalf("a should stay empty, n=%d", len(other.Messages))
	}
}

func TestNewThreadThenDelete(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k"}
	rt := New(cfg, db, nil, nil)
	th, err := rt.NewThread(context.Background(), tid, 1, "scratch")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.DeleteThread(context.Background(), tid, th.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := rt.store.GetThreadByID(context.Background(), th.ID)
	if got != nil {
		t.Fatal("deleted thread still loaded")
	}
}

func TestWithCompactMemoryInjectsSummary(t *testing.T) {
	items := withCompactMemory("sys", "earlier: /login 200", []Message{{Role: roleUser, Content: "next"}})
	if len(items) < 3 {
		t.Fatalf("items=%d", len(items))
	}
	if items[0].Role != "system" || items[1].Role != "system" {
		t.Fatalf("%+v", items)
	}
	if !strings.Contains(items[1].Content.(string), "/login 200") {
		t.Fatalf("%v", items[1].Content)
	}
}
