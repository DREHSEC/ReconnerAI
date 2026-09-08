package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func findingsTestRouter(h *Handler) http.Handler {
	r := mux.NewRouter()
	api := r.PathPrefix("/api").Subrouter()
	api.Use(h.jsonMiddleware)
	api.Use(h.targetScopeMiddleware)
	api.HandleFunc("/findings", h.requireAuth(h.handleListAllFindings)).Methods("GET")
	api.HandleFunc("/targets/{id}/findings/{fid}/triage", h.requireAuth(h.handleSetFindingTriage)).Methods("POST", "PATCH")
	api.HandleFunc("/targets/{id}/nuclei-findings", h.requireAuth(h.handleListNucleiFindings)).Methods("GET")
	return r
}

func TestAllFindingsIncludesUnverifiedNucleiAsCandidates(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "k")
	nid := uuid.New().String()
	if _, err := h.db.Exec(`INSERT INTO nuclei_findings (id, target_id, template_id, template_name, severity, matched_url, description, verification)
		VALUES (?,?,?,?,?,?,?, 'unverified')`, nid, tid, "unix-command-injection", "Unix Command Injection", "high",
		"https://app.example.test/x?id=;id", "possible cmdi"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`UPDATE targets SET finding_count=1 WHERE id=?`, tid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/findings?status=finding", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	findingsTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed status=%d body=%s", rec.Code, rec.Body.String())
	}
	var confirmed struct {
		Data []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &confirmed); err != nil {
		t.Fatal(err)
	}
	if len(confirmed.Data) != 0 {
		t.Fatalf("unverified nuclei must not appear as confirmed: %+v", confirmed.Data)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/findings?status=candidate", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	findingsTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("candidate status=%d body=%s", rec.Code, rec.Body.String())
	}
	var cands struct {
		Data []struct {
			ID     string `json:"id"`
			Type   string `json:"type"`
			Source string `json:"source"`
			Status string `json:"status"`
			URL    string `json:"url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cands); err != nil {
		t.Fatal(err)
	}
	if len(cands.Data) != 1 || cands.Data[0].Source != "nuclei" || cands.Data[0].Type != "unix-command-injection" {
		t.Fatalf("candidate nuclei missing: %+v", cands.Data)
	}
}

func TestFindingsListScrubsCmdiWithoutProof(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "k")
	nid := uuid.New().String()
	if _, err := h.db.Exec(`INSERT INTO nuclei_findings (id, target_id, template_id, template_name, severity, matched_url, tags, request, response, verification)
		VALUES (?,?,?,?,?,?,?,?,?, 'unverified')`, nid, tid, "unix-command-injection", "Unix Command Injection - Generic Detection", "high",
		"https://app.example.test/analytics/matomo.php?idsite=;id", `["cmdi","rce","dast"]`,
		"GET /analytics/matomo.php?idsite=;id HTTP/1.1\r\nHost: app.example.test\r\n\r\n",
		"HTTP/1.1 500 500\r\nContent-Length: 11\r\n\r\nERROR (239)"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`UPDATE targets SET finding_count=1 WHERE id=?`, tid); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/findings?status=candidate", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	findingsTestRouter(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var cands struct {
		Data []any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cands); err != nil {
		t.Fatal(err)
	}
	if len(cands.Data) != 0 {
		t.Fatalf("no-proof cmdi still listed: %+v", cands.Data)
	}
	var ver string
	_ = h.db.QueryRow(`SELECT verification FROM nuclei_findings WHERE id=?`, nid).Scan(&ver)
	if ver != "rejected" {
		t.Fatalf("verification=%s want rejected", ver)
	}
	var count int
	_ = h.db.QueryRow(`SELECT finding_count FROM targets WHERE id=?`, tid).Scan(&count)
	if count != 0 {
		t.Fatalf("finding_count=%d want 0", count)
	}
}

func TestNucleiTriageConfirmAndDecline(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "k")
	router := findingsTestRouter(h)
	nid := uuid.New().String()
	if _, err := h.db.Exec(`INSERT INTO nuclei_findings (id, target_id, template_id, template_name, severity, matched_url, verification)
		VALUES (?,?,?,?,?,?, 'unverified')`, nid, tid, "windows-command-injection", "Windows Command Injection", "high",
		"https://app.example.test/x?id=|dir"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`UPDATE targets SET finding_count=1 WHERE id=?`, tid); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/findings/"+nid+"/triage",
		bytes.NewBufferString(`{"triage":"confirmed"}`))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", rec.Code, rec.Body.String())
	}
	var ver string
	if err := h.db.QueryRow(`SELECT verification FROM nuclei_findings WHERE id=?`, nid).Scan(&ver); err != nil || ver != "verified" {
		t.Fatalf("verification=%s err=%v", ver, err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/findings?status=finding", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var confirmed struct {
		Data []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &confirmed); err != nil {
		t.Fatal(err)
	}
	if len(confirmed.Data) != 1 || confirmed.Data[0].ID != nid {
		t.Fatalf("confirmed list=%+v", confirmed.Data)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/findings/"+nid+"/triage",
		bytes.NewBufferString(`{"triage":"false_positive"}`))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("decline status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := h.db.QueryRow(`SELECT verification FROM nuclei_findings WHERE id=?`, nid).Scan(&ver); err != nil || ver != "rejected" {
		t.Fatalf("after decline verification=%s err=%v", ver, err)
	}
	var count int
	if err := h.db.QueryRow(`SELECT finding_count FROM targets WHERE id=?`, tid).Scan(&count); err != nil || count != 0 {
		t.Fatalf("finding_count=%d err=%v, want 0 after decline", count, err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/findings?status=candidate", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var cands struct {
		Data []any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cands); err != nil {
		t.Fatal(err)
	}
	if len(cands.Data) != 0 {
		t.Fatalf("rejected nuclei still listed: %+v", cands.Data)
	}
}

func TestVulnCandidateConfirmPromotesToFinding(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "k")
	router := findingsTestRouter(h)
	vid := uuid.New().String()
	if _, err := h.db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, status, triage)
		VALUES (?,?,?,?,?,?, 'candidate', '')`, vid, tid, "xss", "high", "https://app.example.test/?q=1", "q"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/targets/"+tid+"/findings/"+vid+"/triage",
		bytes.NewBufferString(`{"triage":"confirmed"}`))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", rec.Code, rec.Body.String())
	}
	var status, triage string
	if err := h.db.QueryRow(`SELECT COALESCE(status,''), COALESCE(triage,'') FROM vuln_findings WHERE id=?`, vid).Scan(&status, &triage); err != nil {
		t.Fatal(err)
	}
	if status != "finding" || triage != "confirmed" {
		t.Fatalf("status=%s triage=%s", status, triage)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/findings?status=finding", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var confirmed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &confirmed); err != nil {
		t.Fatal(err)
	}
	if len(confirmed.Data) != 1 || confirmed.Data[0].ID != vid {
		t.Fatalf("confirmed list=%+v", confirmed.Data)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/findings?status=candidate", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var cands struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cands); err != nil {
		t.Fatal(err)
	}
	for _, row := range cands.Data {
		if row.ID == vid {
			t.Fatal("promoted finding still in Needs Review")
		}
	}
}

func TestConfirmedInboxIncludesLegacyTriageWithoutPromote(t *testing.T) {
	h, tid, sid := newAgentHandler(t, true, "k")
	vid := uuid.New().String()
	if _, err := h.db.Exec(`INSERT INTO vuln_findings (id, target_id, type, severity, url, status, triage)
		VALUES (?,?,?,?,?, 'candidate', 'confirmed')`, vid, tid, "xss", "high", "https://app.example.test/"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/findings?status=finding", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	findingsTestRouter(h).ServeHTTP(rec, req)
	var confirmed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &confirmed); err != nil {
		t.Fatal(err)
	}
	if len(confirmed.Data) != 1 || confirmed.Data[0].ID != vid {
		t.Fatalf("legacy confirmed candidate missing from Confirmed: %+v", confirmed.Data)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/findings?status=candidate", nil)
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec = httptest.NewRecorder()
	findingsTestRouter(h).ServeHTTP(rec, req)
	var cands struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cands); err != nil {
		t.Fatal(err)
	}
	for _, row := range cands.Data {
		if row.ID == vid {
			t.Fatal("legacy confirmed candidate still in Needs Review")
		}
	}
}
