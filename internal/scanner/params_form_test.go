package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
)

func TestParseFormFieldsPreservesValidationValues(t *testing.T) {
	fields := parseFormFields(`<form method="post">
		<input type="hidden" name="csrf" value="tok&amp;123">
		<input name="lookup" value="original">
		<textarea name="note">hello</textarea>
		<select name="tenant"><option value="a">A</option><option value="acme" selected>Acme</option></select>
		<input name="ignored" value="x" disabled>
	</form>`)
	got := map[string]string{}
	for _, f := range fields {
		got[f.name] = f.value
	}
	for name, want := range map[string]string{
		"csrf": "tok&123", "lookup": "original", "note": "hello", "tenant": "acme",
	} {
		if got[name] != want {
			t.Errorf("field %s=%q, want %q (all=%#v)", name, got[name], want, got)
		}
	}
	if _, ok := got["ignored"]; ok {
		t.Fatalf("disabled control must not be replayed: %#v", got)
	}
}

func TestDiscoverFormsStoresGETAndPOSTContractsAndRejectsExternalActions(t *testing.T) {
	db, targetID := testDB(t)
	defer db.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="get" action="/search"><input name="q" value="books"><select name="lang"><option value="en" selected>English</option></select></form>
			<form method="post" action="/submit"><input type="hidden" name="csrf" value="token-1"><textarea name="note">hello</textarea></form>
			<form method="post" action="https://outside.invalid/collect"><input name="leak" value="x"></form>
		</body></html>`))
	}))
	defer srv.Close()

	if _, err := db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,content_type) VALUES(?,?,?,?,?)`,
		uuid.NewString(), targetID, srv.URL, 200, "text/html"); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	s := &ParamScanner{db: db, cfg: &config.Config{}}
	if got := s.discoverForms(context.Background(), targetID, u.Hostname(), func(string, string, string) {}); got != 4 {
		t.Fatalf("stored %d form fields, want 4", got)
	}

	type contract struct{ method, contentType, location, value string }
	got := map[string]contract{}
	rows, err := db.Query(`SELECT parameter,method,content_type,location,value FROM parameters WHERE target_id=? ORDER BY parameter`, targetID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var c contract
		if err := rows.Scan(&name, &c.method, &c.contentType, &c.location, &c.value); err != nil {
			t.Fatal(err)
		}
		got[name] = c
	}
	if _, exists := got["leak"]; exists {
		t.Fatal("out-of-scope form action was persisted")
	}
	if c := got["q"]; c.method != http.MethodGet || c.location != "query" || c.contentType != "" || c.value != "books" {
		t.Fatalf("GET form contract not preserved: %+v", c)
	}
	if c := got["csrf"]; c.method != http.MethodPost || c.location != "body" || c.contentType != "application/x-www-form-urlencoded" || c.value != "token-1" {
		t.Fatalf("POST form contract not preserved: %+v", c)
	}
}
