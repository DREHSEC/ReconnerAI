package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/models"
)

func testDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func insertTarget(t *testing.T, db *database.DB) string {
	t.Helper()
	id := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, id, "app.example.test"); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDispatchUnknownTool(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "not_a_tool", `{}`)
	if !strings.Contains(res.JSON, "unknown tool") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestStartScanRejectsUnknownModule(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "start_scan", `{"modules":["not_a_module"]}`)
	if !strings.Contains(res.JSON, "unknown module") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestStartScanIDORRequiresTwoIdentities(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, &stubSched{}, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "start_scan", `{"modules":["idor"]}`)
	if !strings.Contains(res.JSON, "two identities") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestTargetBriefOmitsIdentitySecrets(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	if _, err := db.Exec(`INSERT INTO identities (id, target_id, label, headers_json, is_baseline)
		VALUES (?,?,?,?,1)`, uuid.New().String(), tid, "victim", `{"Cookie":"session=SUPERSECRET"}`); err != nil {
		t.Fatal(err)
	}
	res := tb.Dispatch(context.Background(), tid, "target_brief", `{}`)
	if strings.Contains(res.JSON, "SUPERSECRET") || strings.Contains(res.JSON, "headers_json") {
		t.Fatalf("secret leaked: %s", res.JSON)
	}
	var brief map[string]any
	if err := json.Unmarshal([]byte(res.JSON), &brief); err != nil {
		t.Fatal(err)
	}
	if brief["identities"] != float64(1) {
		t.Fatalf("identities=%v", brief["identities"])
	}
}

func TestListFindingsRowCap(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	for i := 0; i < 50; i++ {
		if _, err := db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, status)
			VALUES (?,?, 'xss', 'high', ?, 'q', 'x', 'e', 'finding')`,
			uuid.New().String(), tid, "https://app.example.test/"+uuid.New().String()); err != nil {
			t.Fatal(err)
		}
	}
	res := tb.Dispatch(context.Background(), tid, "list_findings", `{}`)
	var out struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal([]byte(res.JSON), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != rowCap {
		t.Fatalf("count=%d want %d", out.Count, rowCap)
	}
}

func TestAllowModules(t *testing.T) {
	_, err := allowModules([]string{"xss", "sqli"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := allowModules([]string{"network_brute"}); err == nil {
		t.Fatal("network_brute must be rejected")
	}
}

type stubSched struct {
	last []string
}

func (s *stubSched) CreateTask(targetID string, modules []string, priority int) (*models.Task, error) {
	s.last = modules
	return &models.Task{ID: "task-1", TargetID: targetID, Modules: modules, Status: "pending"}, nil
}

func TestHTTPRequestRejectsOutOfScope(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "http_request", `{"url":"https://evil.example/steal"}`)
	if !strings.Contains(res.JSON, "not in scope") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestHTTPRequestAllowsInScopeHost(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok-body"))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, u.Hostname()); err != nil {
		t.Fatal(err)
	}
	tb.http = srv.Client()
	tb.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res := tb.Dispatch(context.Background(), tid, "http_request", `{"url":`+mustJSON(srv.URL)+`}`)
	if !strings.Contains(res.JSON, "ok-body") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestHTTPRequestCanReachAnotherTarget(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("other-target"))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	current := insertTarget(t, db)
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, uuid.New().String(), u.Hostname()); err != nil {
		t.Fatal(err)
	}
	tb.http = srv.Client()
	tb.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res := tb.Dispatch(context.Background(), current, "http_request", `{"url":`+mustJSON(srv.URL)+`}`)
	if !strings.Contains(res.JSON, "other-target") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestListTargets(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	insertTarget(t, db)
	res := tb.Dispatch(context.Background(), "unused", "list_targets", `{}`)
	if !strings.Contains(res.JSON, "app.example.test") {
		t.Fatalf("got %s", res.JSON)
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
