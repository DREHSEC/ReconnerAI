package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/capture"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
)

func newGuidedHandlerTestDB(t *testing.T) (*database.DB, *Handler) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "guided-api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES('target','app.example.test')`); err != nil {
		t.Fatal(err)
	}
	return db, &Handler{db: db, cfg: &config.Config{SessionSecret: "guided-test-secret"}}
}

func insertGuidedCaptureFixture(t *testing.T, db *database.DB, captureID, taskStatus string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO capture_sessions(id,target_id,source) VALUES(?,'target','test')`, captureID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO request_templates(id,target_id,capture_session_id,method,request_shape_hash,encrypted_request,source) VALUES(?,'target',?,'GET',?,'sealed','test')`, "template-"+captureID, captureID, "hash-"+captureID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO captured_responses(id,request_template_id,encrypted_response) VALUES(?,?, 'sealed')`, "response-"+captureID, "template-"+captureID); err != nil {
		t.Fatal(err)
	}
	taskID := ""
	if taskStatus != "" {
		taskID = "task-" + captureID
		if _, err := db.Exec(`INSERT INTO tasks(id,target_id,type,status) VALUES(?,'target','guided_capture',?)`, taskID, taskStatus); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO guided_runs(id,target_id,capture_id,task_id,encrypted_input,encrypted_report) VALUES(?,'target',?,?, 'sealed','sealed')`, "run-"+captureID, captureID, taskID); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteCaptureCascadesEncryptedCorpus(t *testing.T) {
	db, h := newGuidedHandlerTestDB(t)
	insertGuidedCaptureFixture(t, db, "capture", "finished")

	r := httptest.NewRequest(http.MethodDelete, "/api/targets/target/captures/capture", nil)
	r = mux.SetURLVars(r, map[string]string{"id": "target", "cid": "capture"})
	w := httptest.NewRecorder()
	h.handleDeleteCapture(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("delete failed: status=%d body=%s", w.Code, w.Body.String())
	}
	for _, table := range []string{"capture_sessions", "request_templates", "captured_responses", "guided_runs"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("capture deletion did not clear %s: count=%d err=%v", table, n, err)
		}
	}
	var audits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM capture_audit WHERE target_id='target' AND resource_id='capture' AND action='delete_capture'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("capture deletion was not audited: count=%d err=%v", audits, err)
	}
}

func TestDeleteCaptureRefusesActiveGuidedRun(t *testing.T) {
	db, h := newGuidedHandlerTestDB(t)
	insertGuidedCaptureFixture(t, db, "active", "running")

	r := httptest.NewRequest(http.MethodDelete, "/api/targets/target/captures/active", nil)
	r = mux.SetURLVars(r, map[string]string{"id": "target", "cid": "active"})
	w := httptest.NewRecorder()
	h.handleDeleteCapture(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("active capture was not protected: status=%d body=%s", w.Code, w.Body.String())
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM capture_sessions WHERE id='active'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("active capture was deleted: count=%d err=%v", n, err)
	}
}

func TestExpiredCaptureCannotRevealRequest(t *testing.T) {
	db, h := newGuidedHandlerTestDB(t)
	insertGuidedCaptureFixture(t, db, "expired", "finished")
	if _, err := db.Exec(`UPDATE capture_sessions SET expires_at=datetime('now','-1 minute') WHERE id='expired'`); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/targets/target/captures/expired/templates/template-expired/reveal", nil)
	r = mux.SetURLVars(r, map[string]string{"id": "target", "cid": "expired", "tid": "template-expired"})
	w := httptest.NewRecorder()
	h.handleRevealCaptureTemplate(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expired request was revealable: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCaptureTemplatesReturnValueFreeTestSuggestions(t *testing.T) {
	db, h := newGuidedHandlerTestDB(t)
	if _, err := db.Exec(`INSERT INTO capture_sessions(id,target_id,source) VALUES('suggestions','target','test')`); err != nil {
		t.Fatal(err)
	}
	request := capture.Request{
		Method:   http.MethodPost,
		URL:      "https://app.example.test/orders/91723?next=https%3A%2F%2Fprivate.example%2Fafter&search=private-search",
		MimeType: "application/json",
		Headers:  []capture.Header{{Name: "Cookie", Value: "sid=top-secret"}},
		Body:     []byte(`{"user_id":"507f1f77bcf86cd799439011","message":"private-message"}`),
	}
	plain, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := secret.New(h.cfg.SessionSecret).Encrypt(string(plain))
	if _, err := db.Exec(`INSERT INTO request_templates(id,target_id,capture_session_id,method,norm_url,operation_kind,preflight_status,request_shape_hash,encrypted_request,source)
		VALUES('suggested-template','target','suggestions','POST','https://app.example.test/orders/{id}','state_changing','ready','shape',?,'test')`, encrypted); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/targets/target/captures/suggestions/templates", nil)
	r = mux.SetURLVars(r, map[string]string{"id": "target", "cid": "suggestions"})
	w := httptest.NewRecorder()
	h.handleCaptureTemplates(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("templates failed: status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, expected := range []string{`"module":"idor"`, `"module":"sqli"`, `"module":"xss"`, `"module":"open_redirect"`, `"parameter":"/user_id"`} {
		if !strings.Contains(body, expected) {
			t.Errorf("missing suggestion %s in %s", expected, body)
		}
	}
	for _, sensitive := range []string{"top-secret", "private-search", "private.example", "private-message", "507f1f77bcf86cd799439011"} {
		if strings.Contains(body, sensitive) {
			t.Errorf("template list leaked captured value %q", sensitive)
		}
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q, want no-store", got)
	}
}
