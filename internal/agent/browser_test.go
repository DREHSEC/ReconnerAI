package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
)

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

func TestBrowserDeniedAlwaysOn(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tb.cfg = &config.Config{AIBrowserEnabled: true}
	tid := insertTarget(t, db)
	raw, _ := json.Marshal(map[string]string{"url": "https://app.example.test/"})
	res := tb.Dispatch(context.Background(), tid, "browser_open", string(raw), CallEnv{Mode: modeAlwaysOn})
	if !strings.Contains(res.JSON, "24/7 hunter") {
		t.Fatalf("got %s", res.JSON)
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

func TestBrowserNotInHunterToolDefs(t *testing.T) {
	defs := toolDefsFor(true, false, false)
	for _, d := range defs {
		if strings.HasPrefix(d.Name, "browser_") {
			t.Fatalf("hunter has %s", d.Name)
		}
	}
	defs = toolDefsFor(false, false, true)
	found := false
	for _, d := range defs {
		if d.Name == "browser_open" {
			found = true
		}
	}
	if !found {
		t.Fatal("copilot must receive browser_open")
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
