package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/agent"
	"github.com/recon-platform/internal/auth"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	ws "github.com/recon-platform/internal/websocket"
	"github.com/recon-platform/pkg/logger"
)

type agentCompleter struct{ text string }

func (c agentCompleter) Complete(ctx context.Context, req agent.CompletionRequest) (*agent.CompletionResponse, error) {
	return &agent.CompletionResponse{Text: c.text}, nil
}

type blockingCompleter struct{ block chan struct{} }

func (b blockingCompleter) Complete(ctx context.Context, req agent.CompletionRequest) (*agent.CompletionResponse, error) {
	select {
	case <-b.block:
		return &agent.CompletionResponse{Text: "ok"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newAgentHandler(t *testing.T, enabled bool, key string) (*Handler, string, string) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		AdminUsername:   "admin",
		AdminPassword:   config.DefaultAdminPassword,
		SessionSecret:   "test-session-secret-32-bytes!!!!",
		AIEnabled:       enabled,
		XAIAPIKeyField:  key,
		AIModel:         "grok-4.6",
		AIMaxIterations: 8,
	}
	a := auth.New(db, cfg)
	if err := a.EnsureAdminUser(); err != nil {
		t.Fatal(err)
	}
	h := &Handler{db: db, cfg: cfg, auth: a, logger: logger.New("error"), hub: ws.NewHub()}
	h.agent = agent.New(cfg, db, nil, h.hub)
	h.agent.SetCompleter(agentCompleter{text: "hello from grok"})

	tid := "t-1"
	if _, err := db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES (?,?, (SELECT id FROM users WHERE username='admin'))`, tid, "app.example.test"); err != nil {
		t.Fatal(err)
	}
	sid, err := a.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	return h, tid, sid
}

func agentTestRouter(h *Handler) http.Handler {
	r := mux.NewRouter()
	api := r.PathPrefix("/api").Subrouter()
	api.Use(h.jsonMiddleware)
	api.Use(h.targetScopeMiddleware)
	api.HandleFunc("/targets/{id}/agent/thread", h.requireAuth(h.handleAgentThread)).Methods("GET")
	api.HandleFunc("/targets/{id}/agent/threads", h.requireAuth(h.handleAgentThreads)).Methods("GET")
	api.HandleFunc("/targets/{id}/agent/threads", h.requireAuth(h.handleAgentNewThread)).Methods("POST")
	api.HandleFunc("/targets/{id}/agent/threads/{tid}/compact", h.requireAuth(h.handleAgentCompact)).Methods("POST")
	api.HandleFunc("/targets/{id}/agent/threads/{tid}", h.requireAuth(h.handleAgentPatchThread)).Methods("PATCH")
	api.HandleFunc("/targets/{id}/agent/threads/{tid}", h.requireAuth(h.handleAgentDeleteThread)).Methods("DELETE")
	api.HandleFunc("/targets/{id}/agent/messages", h.requireAuth(h.handleAgentMessage)).Methods("POST")
	api.HandleFunc("/targets/{id}/agent/hunt", h.requireAuth(h.handleAgentHunt)).Methods("POST")
	api.HandleFunc("/targets/{id}/agent/cancel", h.requireAuth(h.handleAgentCancel)).Methods("POST")
	api.HandleFunc("/targets/{id}/agent/leads", h.requireAuth(h.handleListLeads)).Methods("GET")
	api.HandleFunc("/targets/{id}/agent/leads/{lid}", h.requireAuth(h.handleTriageLead)).Methods("POST")
	api.HandleFunc("/targets/{id}/agent/leads/{lid}/report", h.requireAuth(h.handleLeadReport)).Methods("GET")
	api.HandleFunc("/targets/{id}/scope", h.requireAuth(h.handleGetScope)).Methods("GET")
	api.HandleFunc("/targets/{id}/scope/import", h.requireAuth(h.handleImportScope)).Methods("POST")
	api.HandleFunc("/targets/{id}/replay", h.requireAuth(h.handleReplay)).Methods("POST")
	api.HandleFunc("/system/ai", h.requireAuth(h.handleAIStatus)).Methods("GET")
	return r
}

func TestAgentRoutesRequireAuth(t *testing.T) {
	h, tid, _ := newAgentHandler(t, true, "k")
	req := httptest.NewRequest(http.MethodGet, "/api/targets/"+tid+"/agent/thread", nil)
	rec := httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAgentDisabledReturns400(t *testing.T) {
	h, tid, sid := newAgentHandler(t, false, "k")
	req := httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/agent/messages", bytes.NewBufferString(`{"content":"hi"}`))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAgentMissingKeyReturns400(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "")
	req := httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/agent/messages", bytes.NewBufferString(`{"content":"hi"}`))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAgentMemberForbiddenOnForeignTarget(t *testing.T) {
	h, _, adminSID := newAgentHandler(t, true, "k")
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-bob','bob.example',?)`, bob.ID); err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/targets/t-1/agent/thread", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: bobSID})
	rec := httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bob → admin target status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/targets/t-1/agent/thread", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: adminSID})
	rec = httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAgentMessageAccepted(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "k")
	req := httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/agent/messages", bytes.NewBufferString(`{"content":"summarize"}`))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			ThreadID string `json:"thread_id"`
			RunID    string `json:"run_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.ThreadID == "" || resp.Data.RunID == "" {
		t.Fatalf("missing ids: %+v", resp.Data)
	}
}

func TestAgentConcurrentRunConflict(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "k")
	block := make(chan struct{})
	h.agent.SetCompleter(blockingCompleter{block: block})
	router := agentTestRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/agent/messages", bytes.NewBufferString(`{"content":"one"}`))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first status=%d %s", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/agent/messages", bytes.NewBufferString(`{"content":"two"}`))
	req2.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("second status=%d %s", rec2.Code, rec2.Body.String())
	}
	close(block)
}

func TestAgentWorkspaceHTTP(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "k")
	router := agentTestRouter(h)
	auth := func(req *http.Request) *http.Request {
		req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
		return req
	}

	req := auth(httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/agent/threads", bytes.NewBufferString(`{"title":"surface"}`)))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Data.ID == "" {
		t.Fatalf("create body=%s err=%v", rec.Body.String(), err)
	}

	req = auth(httptest.NewRequest(http.MethodGet, "/api/targets/"+tid+"/agent/threads", nil))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), created.Data.ID) {
		t.Fatalf("list missing id: %s", rec.Body.String())
	}

	req = auth(httptest.NewRequest(http.MethodPatch, "/api/targets/"+tid+"/agent/threads/"+created.Data.ID, bytes.NewBufferString(`{"title":"renamed"}`)))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "renamed") {
		t.Fatalf("rename status=%d %s", rec.Code, rec.Body.String())
	}

	req = auth(httptest.NewRequest(http.MethodGet, "/api/targets/"+tid+"/agent/thread?thread_id="+created.Data.ID, nil))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"token_budget"`) {
		t.Fatalf("get status=%d %s", rec.Code, rec.Body.String())
	}

	req = auth(httptest.NewRequest(http.MethodDelete, "/api/targets/"+tid+"/agent/threads/"+created.Data.ID, nil))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d %s", rec.Code, rec.Body.String())
	}
}

func TestLeadTriageHTTP(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "k")
	lid := "lead-1"
	if _, err := h.db.Exec(`INSERT INTO agent_leads (id, target_id, title, body, status) VALUES (?,?,?,?, 'pending')`,
		lid, tid, "maybe IDOR", "B read A"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/agent/leads/"+lid, bytes.NewBufferString(`{"status":"confirmed"}`))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var st string
	if err := h.db.QueryRow(`SELECT status FROM agent_leads WHERE id=?`, lid).Scan(&st); err != nil || st != "confirmed" {
		t.Fatalf("status=%s err=%v", st, err)
	}
	var resp struct {
		Data struct {
			Status string `json:"status"`
			Report string `json:"report"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Data.Report, "maybe IDOR") || !strings.Contains(resp.Data.Report, "Not a Reconner-verified finding") {
		t.Fatalf("report=%s", resp.Data.Report)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/targets/"+tid+"/agent/leads/"+lid+"/report", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("report status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestImportScopeHTTP(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "k")
	payload, err := json.Marshal(map[string]string{"text": `{
	  "data": [
	    {"attributes":{"asset_identifier":"*.example.test","eligible_for_submission":true}},
	    {"attributes":{"asset_identifier":"app.example.test","eligible_for_submission":false}}
	  ]
	}`})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/scope/import", bytes.NewBuffer(payload))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}
	var parsed struct {
		Data struct {
			Format  string   `json:"format"`
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Data.Format != "hackerone" {
		t.Fatalf("format=%s body=%s", parsed.Data.Format, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/targets/"+tid+"/scope", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/replay", bytes.NewBufferString(`{"url":"https://app.example.test/secret"}`))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("replay excluded status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "excluded") {
		t.Fatalf("expected excluded program scope, got %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/replay", bytes.NewBufferString(`{"url":"https://evil.unrelated.test/"}`))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	agentTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("replay outside engagement status=%d body=%s", rec.Code, rec.Body.String())
	}
}
