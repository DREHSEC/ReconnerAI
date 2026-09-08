package agent

import (
	"context"
	"testing"

	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scheduler"
)

func TestModulesForLeadAlwaysVerify(t *testing.T) {
	mods := ModulesForLead("candidates", "maybe xss", "reflected param", 0)
	if mods[0] != scheduler.ModuleVerify {
		t.Fatalf("first=%v", mods)
	}
	foundXSS := false
	for _, m := range mods {
		if m == scheduler.ModuleXSS {
			foundXSS = true
		}
		if m == scheduler.ModuleIDOR {
			t.Fatal("idor without identities")
		}
	}
	if !foundXSS {
		t.Fatalf("expected xss from keywords: %v", mods)
	}
}

func TestModulesForLeadAuthzNeedsIdentities(t *testing.T) {
	none := ModulesForLead("authz", "BOLA", "cross-user read", 1)
	for _, m := range none {
		if m == scheduler.ModuleIDOR {
			t.Fatal("idor with one identity")
		}
	}
	two := ModulesForLead("authz", "BOLA", "cross-user read", 2)
	found := false
	for _, m := range two {
		if m == scheduler.ModuleIDOR {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected idor with two identities: %v", two)
	}
}

type stubLeadVerify struct {
	target, scope string
	mods          []string
}

func (s *stubLeadVerify) CreateLeadVerifyTask(targetID string, modules []string, scopeOverride string) (*models.Task, error) {
	s.target, s.mods, s.scope = targetID, append([]string(nil), modules...), scopeOverride
	return &models.Task{ID: "task-verify-1", TargetID: targetID, Modules: modules, Status: "pending", Type: "lead_verify"}, nil
}

func TestEnqueueLeadVerifyScoped(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	if _, err := db.Exec(`INSERT INTO agent_leads (id, target_id, title, body, url, playbook, status) VALUES (?,?,?,?,?,?, 'pending')`,
		"lead-1", tid, "reflected search", "q echoes", "https://app.example.test/search?q=1", "reflection"); err != nil {
		t.Fatal(err)
	}
	stub := &stubLeadVerify{}
	id, mods, err := EnqueueLeadVerify(context.Background(), db, stub, tid, "lead-1")
	if err != nil {
		t.Fatal(err)
	}
	if id != "task-verify-1" {
		t.Fatalf("task=%s", id)
	}
	if stub.scope != "https://app.example.test/search?q=1" {
		t.Fatalf("scope=%s", stub.scope)
	}
	if len(mods) == 0 || mods[0] != scheduler.ModuleVerify {
		t.Fatalf("mods=%v", mods)
	}
	var stored string
	if err := db.QueryRow(`SELECT COALESCE(verify_task_id,'') FROM agent_leads WHERE id='lead-1'`).Scan(&stored); err != nil || stored != "task-verify-1" {
		t.Fatalf("stored=%s err=%v", stored, err)
	}
}

func TestEnqueueLeadVerifyNoURL(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	if _, err := db.Exec(`INSERT INTO agent_leads (id, target_id, title, body, status) VALUES (?,?,?,?, 'pending')`,
		"lead-2", tid, "note", "no url"); err != nil {
		t.Fatal(err)
	}
	stub := &stubLeadVerify{}
	id, _, err := EnqueueLeadVerify(context.Background(), db, stub, tid, "lead-2")
	if err != nil || id != "" || stub.target != "" {
		t.Fatalf("id=%s err=%v stub=%+v", id, err, stub)
	}
}
