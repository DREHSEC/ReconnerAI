package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSurfaceDossierClustersCandidatesAndOddHosts(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	for i := 0; i < 5; i++ {
		if _, err := db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, status) VALUES (?,?,?,?,?, 'candidate')`,
			uuid.New().String(), tid, "xss", "high", "https://app.example.test/q?x="+uuid.New().String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, status) VALUES (?,?,?,?,?, 'candidate')`,
		uuid.New().String(), tid, "sqli", "high", "https://app.example.test/id"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO subdomains (id, target_id, subdomain, is_alive, status_code) VALUES (?,?,?,1,200)`,
		uuid.New().String(), tid, "ops.qect-nonprod.mo360cp.i.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, source, is_reflected) VALUES (?,?,?,?,?,?,0)`,
		uuid.New().String(), tid, "https://app.example.test/api/orders/1", "accountId", "99", "js"); err != nil {
		t.Fatal(err)
	}
	pb := pickPlaybook(context.Background(), db, tid)
	md := buildSurfaceDossier(context.Background(), db, tid, pb)
	for _, want := range []string{"xss ×5", "sqli ×1", "accountId", "ops.qect-nonprod", "Suggested lane"} {
		if !strings.Contains(md, want) {
			t.Fatalf("dossier missing %q:\n%s", want, md)
		}
	}
}

func TestRejectFloodLeadAfterThreeXSS(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	for i := 0; i < 3; i++ {
		if _, err := db.Exec(`INSERT INTO agent_leads (id, target_id, title, body, playbook, status) VALUES (?,?,?,?, 'reflection', 'pending')`,
			uuid.New().String(), tid, "xss "+uuid.New().String(), "reflected q"); err != nil {
			t.Fatal(err)
		}
	}
	err := tb.rejectFloodLead(context.Background(), tid, flagLeadArgs{Title: "maybe xss", Body: "still reflected", Playbook: "reflection"})
	if err == nil {
		t.Fatal("expected flood reject")
	}
	if !strings.Contains(err.Error(), "different class") {
		t.Fatalf("err=%v", err)
	}
	if err := tb.rejectFloodLead(context.Background(), tid, flagLeadArgs{Title: "BOLA on /orders", Body: "user B read user A", Playbook: "authz"}); err != nil {
		t.Fatalf("authz lead must pass: %v", err)
	}
}

func TestRejectFloodLeadDailyCap(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	for i := 0; i < 12; i++ {
		if _, err := db.Exec(`INSERT INTO agent_leads (id, target_id, title, body, playbook, status, created_at) VALUES (?,?,?,?, 'js_shadow', 'pending', CURRENT_TIMESTAMP)`,
			uuid.New().String(), tid, "note "+uuid.New().String(), "mapped an API"); err != nil {
			t.Fatal(err)
		}
	}
	err := tb.rejectFloodLead(context.Background(), tid, flagLeadArgs{Title: "another API", Body: "yet more endpoints", Playbook: "js_shadow"})
	if err == nil || !strings.Contains(err.Error(), "24h") {
		t.Fatalf("expected daily cap, got %v", err)
	}
	if err := tb.rejectFloodLead(context.Background(), tid, flagLeadArgs{Title: "SSRF on grpc-debug", Body: "dial oracle", Playbook: "leftovers"}); err != nil {
		t.Fatalf("high-impact must pass daily cap: %v", err)
	}
}

func TestHunterScanAllowWidensWithoutXSS(t *testing.T) {
	got := hunterScanAllow([]string{"verify"}, 0)
	join := strings.Join(got, ",")
	if !strings.Contains(join, "exposure") || !strings.Contains(join, "js_endpoints") {
		t.Fatalf("got %v", got)
	}
	for _, m := range got {
		if m == "xss" || m == "sqli" {
			t.Fatalf("must not auto-add xss/sqli: %v", got)
		}
		if m == "idor" {
			t.Fatal("idor without identities")
		}
	}
	got = hunterScanAllow([]string{"idor"}, 2)
	ok := false
	for _, m := range got {
		if m == "idor" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("idor with identities: %v", got)
	}
}
