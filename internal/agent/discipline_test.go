package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/models"
)

func TestHunterStartScanBlockedWhenNotInPlaybook(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, &stubSched{}, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "start_scan", `{"modules":["xss"]}`,
		CallEnv{Mode: modeAlwaysOn, Playbook: "authz", ScanAllow: []string{"idor", "authz"}})
	if !strings.Contains(res.JSON, "not in playbook") {
		t.Fatalf("%s", res.JSON)
	}
}

func TestHunterStartScanBlockedWhenCompleted(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, &stubSched{}, nil)
	tid := insertTarget(t, db)
	if _, err := db.Exec(`INSERT INTO tasks (id, target_id, type, status, modules, completed_modules)
		VALUES (?,?, 'full_scan', 'finished', '["xss"]', ?)`,
		uuid.New().String(), tid, models.StringSliceToJSON([]string{"xss"})); err != nil {
		t.Fatal(err)
	}
	res := tb.Dispatch(context.Background(), tid, "start_scan", `{"modules":["xss"]}`,
		CallEnv{Mode: modeAlwaysOn, Playbook: "reflection", ScanAllow: []string{"xss", "open_redirect"}})
	if !strings.Contains(res.JSON, "already completed") {
		t.Fatalf("%s", res.JSON)
	}
}

func TestCopilotStartScanNotGated(t *testing.T) {
	db := testDB(t)
	sched := &stubSched{}
	tb := NewToolbox(db, sched, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "start_scan", `{"modules":["xss"]}`, CallEnv{Mode: modeChat})
	if strings.Contains(res.JSON, "error") && !strings.Contains(res.JSON, "task_id") {
		t.Fatalf("%s", res.JSON)
	}
	if len(sched.last) == 0 {
		t.Fatalf("copilot scan should enqueue, got %s", res.JSON)
	}
}

func TestDeadEndSuppressesHTTP(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should-not-hit"))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, u.Hostname()); err != nil {
		t.Fatal(err)
	}
	tb.http = srv.Client()
	tb.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	tb.Dispatch(context.Background(), tid, "remember",
		`{"kind":"dead_end","content":"encoded","url":"`+srv.URL+`"}`)
	res := tb.Dispatch(context.Background(), tid, "http_request", `{"url":"`+srv.URL+`"}`,
		CallEnv{Mode: modeAlwaysOn, Playbook: "reflection"})
	if !strings.Contains(res.JSON, "suppressed") {
		t.Fatalf("expected suppress, got %s", res.JSON)
	}
}

func TestHunterHTTPRateLimit(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tb.limit = &hostLimiter{per: map[string]*hostWin{}, max: 2}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, u.Hostname()); err != nil {
		t.Fatal(err)
	}
	tb.http = srv.Client()
	tb.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	env := CallEnv{Mode: modeAlwaysOn, Playbook: "coverage"}
	for i := 0; i < 2; i++ {
		res := tb.Dispatch(context.Background(), tid, "http_request", `{"url":"`+srv.URL+`"}`, env)
		if strings.Contains(res.JSON, "error") && strings.Contains(res.JSON, "budget") {
			t.Fatalf("early budget: %s", res.JSON)
		}
	}
	res := tb.Dispatch(context.Background(), tid, "http_request", `{"url":"`+srv.URL+`"}`, env)
	if !strings.Contains(res.JSON, "budget") {
		t.Fatalf("expected budget error, got %s", res.JSON)
	}
}

func TestDiffIdentitiesNeedsIdentities(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "diff_identities", `{"url":"https://app.example.test/x"}`)
	if !strings.Contains(res.JSON, "needs two identities") && !strings.Contains(res.JSON, "not in scope") {
		t.Fatalf("%s", res.JSON)
	}
}

func TestDiffIdentitiesAutoPicksTwoSessions(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if strings.Contains(r.Header.Get("Cookie"), "aaa") {
			w.Write([]byte("owner-object-aaaaaaaa"))
			return
		}
		w.Write([]byte("other-user-bbbbbbbbbbbbbbbb"))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, u.Hostname()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identities (id, target_id, label, headers_json, is_baseline) VALUES (?,?,?,?,1)`,
		uuid.New().String(), tid, "userA", `{"Cookie":"sid=aaa"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identities (id, target_id, label, headers_json, is_baseline) VALUES (?,?,?,?,0)`,
		uuid.New().String(), tid, "userB", `{"Cookie":"sid=bbb"}`); err != nil {
		t.Fatal(err)
	}
	tb.http = srv.Client()
	tb.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res := tb.Dispatch(context.Background(), tid, "diff_identities", `{"url":"`+srv.URL+`"}`)
	if !strings.Contains(res.JSON, "different") {
		t.Fatalf("%s", res.JSON)
	}
	if !strings.Contains(res.JSON, "body_hash") {
		t.Fatalf("missing hash: %s", res.JSON)
	}
	if n < 2 {
		t.Fatalf("probes=%d", n)
	}
	pb := pickPlaybook(context.Background(), db, tid)
	if pb.Name != "authz_surface" && pb.Name != "authz" {
		t.Fatalf("expected authz playbook with 2 identities, got %s", pb.Name)
	}
}

func TestFlagLeadIsPendingNotFinding(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "flag_lead",
		`{"title":"IDOR on /orders","body":"user B read user A","url":"https://app.example.test/orders/1","status":200}`,
		CallEnv{Playbook: "authz"})
	if !strings.Contains(res.JSON, `"status":"pending"`) {
		t.Fatalf("%s", res.JSON)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=?`, tid).Scan(&n)
	if n != 0 {
		t.Fatal("flag_lead must not write vuln_findings")
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM agent_leads WHERE target_id=? AND status='pending'`, tid).Scan(&n)
	if n != 1 {
		t.Fatalf("leads=%d", n)
	}
}
