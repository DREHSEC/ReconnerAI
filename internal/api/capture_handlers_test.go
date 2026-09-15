package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
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

func TestImportCaptureSealsSecretsAndSendsNoTraffic(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "capture-api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	const targetID = "target-capture-test"
	if _, err := db.Exec(`INSERT INTO targets (id,domain) VALUES (?,?)`, targetID, "app.example.test"); err != nil {
		t.Fatal(err)
	}

	reqRaw := "GET /private/42?token=do-not-leak HTTP/1.1\r\nHost: app.example.test\r\nAuthorization: Bearer do-not-leak\r\n\r\n"
	respRaw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=do-not-leak\r\nContent-Length: 11\r\n\r\n{\"id\":\"42\"}"
	xmlBody := `<?xml version="1.0"?><items><item>` +
		`<url>https://app.example.test/private/42?token=do-not-leak</url>` +
		`<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(reqRaw)) + `</request>` +
		`<status>200</status><mimetype>JSON</mimetype>` +
		`<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(respRaw)) + `</response>` +
		`</item></items>`

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", "history.xml")
	_, _ = part.Write([]byte(xmlBody))
	_ = mw.WriteField("source", "burp_xml")
	_ = mw.WriteField("identity_label", "User A")
	_ = mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/api/targets/"+targetID+"/captures", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r = mux.SetURLVars(r, map[string]string{"id": targetID})
	w := httptest.NewRecorder()
	h := &Handler{db: db, cfg: &config.Config{SessionSecret: "unit-test-secret"}}
	h.handleImportCapture(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("import failed: status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "do-not-leak") || !strings.Contains(w.Body.String(), `"traffic_sent":0`) {
		t.Fatalf("response leaked a secret or omitted passive proof: %s", w.Body.String())
	}

	var encrypted string
	if err := db.QueryRow(`SELECT encrypted_request FROM request_templates WHERE target_id=?`, targetID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, "enc:v1:") || strings.Contains(encrypted, "do-not-leak") {
		t.Fatalf("request was not sealed: %q", encrypted)
	}
	var ordinaryURL string
	if err := db.QueryRow(`SELECT url FROM http_interactions WHERE target_id=? AND scanner='guided-capture'`, targetID).Scan(&ordinaryURL); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ordinaryURL, "do-not-leak") {
		t.Fatalf("ordinary request intelligence leaked a query value: %s", ordinaryURL)
	}

	// Convert the sealed fixture to POST and prove preflight blocks it before any
	// request is sent. This exercises the active boundary without networking.
	var captureID, templateID, sealed string
	if err := db.QueryRow(`SELECT capture_session_id,id,encrypted_request FROM request_templates WHERE target_id=?`, targetID).Scan(&captureID, &templateID, &sealed); err != nil {
		t.Fatal(err)
	}
	box := secret.New("unit-test-secret")
	var captured capture.Request
	if err := json.Unmarshal([]byte(box.Decrypt(sealed)), &captured); err != nil {
		t.Fatal(err)
	}
	captured.Method = http.MethodPost
	updated, _ := json.Marshal(captured)
	if _, err := db.Exec(`UPDATE request_templates SET method='POST',encrypted_request=? WHERE id=?`, box.Encrypt(string(updated)), templateID); err != nil {
		t.Fatal(err)
	}
	preflightReq := httptest.NewRequest(http.MethodPost, "/api/targets/"+targetID+"/captures/"+captureID+"/preflight", bytes.NewReader([]byte(`{}`)))
	preflightReq = mux.SetURLVars(preflightReq, map[string]string{"id": targetID, "cid": captureID})
	preflightW := httptest.NewRecorder()
	h.handlePreflightCapture(preflightW, preflightReq)
	if preflightW.Code != http.StatusOK || !strings.Contains(preflightW.Body.String(), `"requests_sent":0`) || !strings.Contains(preflightW.Body.String(), `"mutations_sent":0`) || !strings.Contains(preflightW.Body.String(), `"status":"blocked"`) {
		t.Fatalf("unsafe preflight boundary failed: status=%d body=%s", preflightW.Code, preflightW.Body.String())
	}
	if strings.Contains(preflightW.Body.String(), "do-not-leak") {
		t.Fatalf("preflight response leaked a captured secret: %s", preflightW.Body.String())
	}
}

func TestPreviewCaptureIsPassiveAndRejectsOutOfScopeTraffic(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "capture-preview.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	const targetID = "target-preview-test"
	if _, err := db.Exec(`INSERT INTO targets (id,domain) VALUES (?,?)`, targetID, "app.example.test"); err != nil {
		t.Fatal(err)
	}

	reqRaw := "GET /account?token=preview-secret HTTP/1.1\r\nHost: evil.invalid\r\nCookie: sid=preview-secret\r\n\r\n"
	xmlBody := `<?xml version="1.0"?><items><item>` +
		`<url>https://evil.invalid/account?token=preview-secret</url>` +
		`<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(reqRaw)) + `</request>` +
		`</item></items>`
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", "history.xml")
	_, _ = part.Write([]byte(xmlBody))
	_ = mw.WriteField("source", "burp_xml")
	_ = mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/api/targets/"+targetID+"/captures/preview", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r = mux.SetURLVars(r, map[string]string{"id": targetID})
	w := httptest.NewRecorder()
	h := &Handler{db: db, cfg: &config.Config{SessionSecret: "unit-test-secret"}}
	h.handlePreviewCapture(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("preview failed: status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "preview-secret") ||
		!strings.Contains(w.Body.String(), `"accepted":0`) ||
		!strings.Contains(w.Body.String(), `"rejected":1`) ||
		!strings.Contains(w.Body.String(), `"traffic_sent":0`) {
		t.Fatalf("preview leaked data or admitted out-of-scope traffic: %s", w.Body.String())
	}
	for _, table := range []string{"capture_sessions", "request_templates", "captured_responses", "http_interactions"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("passive preview wrote to %s: count=%d err=%v", table, n, err)
		}
	}
}

func TestImportCaptureDeduplicatesIdenticalRequestShapes(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "capture-dedup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	const targetID = "target-dedup-test"
	if _, err := db.Exec(`INSERT INTO targets (id,domain) VALUES (?,?)`, targetID, "app.example.test"); err != nil {
		t.Fatal(err)
	}
	reqRaw := "GET /orders/42?csrf=rotating HTTP/1.1\r\nHost: app.example.test\r\nAuthorization: Bearer rotating\r\n\r\n"
	respRaw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
	item := `<item><url>https://app.example.test/orders/42?csrf=rotating</url><request base64="true">` +
		base64.StdEncoding.EncodeToString([]byte(reqRaw)) + `</request><response base64="true">` +
		base64.StdEncoding.EncodeToString([]byte(respRaw)) + `</response></item>`
	xmlBody := `<?xml version="1.0"?><items>` + item + item + `</items>`
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", "history.xml")
	_, _ = part.Write([]byte(xmlBody))
	_ = mw.WriteField("source", "burp_xml")
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/targets/"+targetID+"/captures", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r = mux.SetURLVars(r, map[string]string{"id": targetID})
	w := httptest.NewRecorder()
	h := &Handler{db: db, cfg: &config.Config{SessionSecret: "unit-test-secret"}}
	h.handleImportCapture(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"templates_stored":1`) {
		t.Fatalf("deduplicating import failed: status=%d body=%s", w.Code, w.Body.String())
	}
	for _, table := range []string{"request_templates", "captured_responses", "http_interactions"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("deduplication count for %s: count=%d err=%v", table, n, err)
		}
	}
}
