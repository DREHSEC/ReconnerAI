package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
)

func TestIgnoreChromedpSessionNoise(t *testing.T) {
	if !ignoreChromedpSessionNoise(`executor for %q doesn't exist`) {
		t.Fatal("should ignore Obscura page-1-session detach")
	}
	if !ignoreChromedpSessionNoise(`executor for %q already exists`) {
		t.Fatal("should ignore duplicate session bookkeeping")
	}
	if ignoreChromedpSessionNoise("could not dial %q: %w") {
		t.Fatal("must still log real CDP failures")
	}
}

func TestBrowserOpenOutOfScope(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tb.cfg = &config.Config{AIBrowserEnabled: true, AIBrowserTimeoutSeconds: 5}
	tid := insertTarget(t, db)
	raw, _ := json.Marshal(map[string]string{"url": "https://evil.example/login"})
	res := tb.Dispatch(context.Background(), tid, "browser_open", string(raw), CallEnv{Mode: modeChat})
	if !strings.Contains(res.JSON, "not in scope") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestBrowserOpenOutOfScopeAlwaysOn(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tb.cfg = &config.Config{AIBrowserEnabled: true, AIBrowserTimeoutSeconds: 5}
	tid := insertTarget(t, db)
	raw, _ := json.Marshal(map[string]string{"url": "https://evil.example/login"})
	res := tb.Dispatch(context.Background(), tid, "browser_open", string(raw), CallEnv{Mode: modeAlwaysOn})
	if !strings.Contains(res.JSON, "not in scope") {
		t.Fatalf("hunter browser must stay in scope, got %s", res.JSON)
	}
}

func TestHunterBrowserOpenRateLimit(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tb.cfg = &config.Config{AIBrowserEnabled: true, AIBrowserTimeoutSeconds: 5}
	tb.limit = &hostLimiter{per: map[string]*hostWin{
		"app.example.test": {window: time.Now(), n: 2},
	}, max: 2}
	tid := insertTarget(t, db)
	raw, _ := json.Marshal(map[string]string{"url": "https://app.example.test/"})
	res := tb.Dispatch(context.Background(), tid, "browser_open", string(raw), CallEnv{Mode: modeAlwaysOn})
	if !strings.Contains(res.JSON, "budget") {
		t.Fatalf("expected hunter budget, got %s", res.JSON)
	}
}

func TestHunterBrowserRespectsDeadEnd(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tb.cfg = &config.Config{AIBrowserEnabled: true}
	tid := insertTarget(t, db)
	tb.Dispatch(context.Background(), tid, "remember",
		`{"kind":"dead_end","content":"encoded","url":"https://app.example.test/login"}`)
	raw, _ := json.Marshal(map[string]string{"url": "https://app.example.test/login"})
	res := tb.Dispatch(context.Background(), tid, "browser_open", string(raw), CallEnv{Mode: modeAlwaysOn})
	if !strings.Contains(res.JSON, "suppressed") {
		t.Fatalf("expected dead-end suppress, got %s", res.JSON)
	}
}

func TestBrowserDisabled(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tb.cfg = &config.Config{AIBrowserEnabled: false}
	tid := insertTarget(t, db)
	raw, _ := json.Marshal(map[string]string{"url": "https://app.example.test/"})
	res := tb.Dispatch(context.Background(), tid, "browser_open", string(raw), CallEnv{Mode: modeChat})
	if !strings.Contains(res.JSON, "disabled") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestBrowserInHunterToolDefs(t *testing.T) {
	defs := toolDefsFor(true, false, false)
	for _, d := range defs {
		if strings.HasPrefix(d.Name, "browser_") {
			t.Fatalf("browser must stay behind the AIBrowserEnabled flag, got %s", d.Name)
		}
	}
	defs = toolDefsFor(true, true, true)
	found := false
	for _, d := range defs {
		if d.Name == "browser_open" {
			found = true
		}
	}
	if !found {
		t.Fatal("hunter with flags on must receive browser_open")
	}
}

func TestBrowserSnapshotWithoutSession(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "browser_snapshot", `{}`, CallEnv{Mode: modeChat})
	if !strings.Contains(res.JSON, "no open browser") {
		t.Fatalf("got %s", res.JSON)
	}
}
