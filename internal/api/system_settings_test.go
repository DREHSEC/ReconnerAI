package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
)

func TestUpdateAgentSettingsPersists(t *testing.T) {
	h, _, sid := newAgentHandler(t, true, "k")
	h.cfg.SetPath(filepath.Join(t.TempDir(), "config.json"))
	r := mux.NewRouter()
	api := r.PathPrefix("/api").Subrouter()
	api.Use(h.jsonMiddleware)
	api.HandleFunc("/system/settings", h.requireAuth(h.handleGetSettings)).Methods("GET")
	api.HandleFunc("/system/settings", h.requireAuth(h.handleUpdateSettings)).Methods("PATCH")

	body := `{
		"ai_model":"GLM-5.3-Flash",
		"ai_base_url":"https://litellm.example/v1",
		"ai_max_iterations":"12",
		"ai_hunter_interval_seconds":"45",
		"ai_hunter_iterations":"9",
		"ai_hunter_skip_running":"false",
		"ai_max_tokens":"4096",
		"ai_timeout_seconds":"60"
	}`
	req := httptest.NewRequest(http.MethodPatch, "/api/system/settings", bytes.NewBufferString(body))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if h.cfg.AIMaxIterations != 12 || h.cfg.AIHunterIntervalSeconds != 45 || h.cfg.AIHunterIterations != 9 {
		t.Fatalf("cfg iterations=%d interval=%d hunterIt=%d", h.cfg.AIMaxIterations, h.cfg.AIHunterIntervalSeconds, h.cfg.AIHunterIterations)
	}
	if h.cfg.AIHunterSkipRunning {
		t.Fatal("skip_running should be false")
	}
	if h.cfg.AIMaxTokens != 4096 || h.cfg.AITimeoutSeconds != 60 {
		t.Fatalf("tokens=%d timeout=%d", h.cfg.AIMaxTokens, h.cfg.AITimeoutSeconds)
	}
	if h.cfg.AIBaseURL() != "https://litellm.example/v1" {
		t.Fatalf("base=%s", h.cfg.AIBaseURL())
	}
	var resp struct {
		Data struct {
			AI struct {
				MaxIterations int    `json:"max_iterations"`
				Model         string `json:"model"`
				MaxTokens     int    `json:"max_tokens"`
			} `json:"ai"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.AI.MaxIterations != 12 || resp.Data.AI.MaxTokens != 4096 {
		t.Fatalf("response %+v", resp.Data.AI)
	}
}
