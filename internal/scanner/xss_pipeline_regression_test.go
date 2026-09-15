package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestXSSWithoutParametersReachesDOMPages(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	_, err := db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,content_type)
		VALUES(?,?,?,200,'text/html')`, uuid.NewString(), tid, "https://m.local/spa")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	visited := false
	err = NewDASTScanner(db, nil, nil, nil).RunXSS(ctx, tid, func(_, module, message string) {
		if module == "dom_xss" && strings.Contains(message, "1 eligible route") {
			visited = true
			// Stop before browser/network activity. This tests dispatch from the
			// actual public entry point, not browser execution semantics.
			cancel()
		}
	})
	if !visited || !errors.Is(err, context.Canceled) {
		t.Fatalf("DOM phase not dispatched or cancellation lost: visited=%v err=%v", visited, err)
	}
}

func TestXSSLoaderPreservesRequiredSiblingsBeyondPointLimit(t *testing.T) {
	for _, loc := range []string{"body", "json"} {
		t.Run(loc, func(t *testing.T) {
			db, tid := testDB(t)
			defer db.Close()
			ct := "application/x-www-form-urlencoded"
			if loc == "json" {
				ct = "application/json"
			}
			for _, f := range []struct {
				name, value, typ string
				reflected        int
			}{
				{"input", "original", "string", 1},
				{"csrf", "required-token", "string", 0},
				{"settings.count", "2", "integer", 0},
			} {
				location := loc
				if loc == "json" {
					location += ":" + f.typ
				}
				_, err := db.Exec(`INSERT INTO parameters(id,target_id,url,parameter,value,method,content_type,location,is_reflected)
					VALUES(?,?,?, ?,?,'POST',?,?,?)`, uuid.NewString(), tid, "https://m.local/search", f.name, f.value, ct, location, f.reflected)
				if err != nil {
					t.Fatal(err)
				}
			}
			points := loadXSSInsertionPoints(context.Background(), db, tid, 1)
			if len(points) != 1 || points[0].Param != "input" {
				t.Fatalf("unexpected selection: %+v", points)
			}
			req, err := buildInjectedRequest(context.Background(), points[0], "inert-marker", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer req.Body.Close()
			if req.Method != http.MethodPost {
				t.Fatal("request method lost")
			}
			if loc == "json" {
				var doc map[string]any
				if err := json.NewDecoder(req.Body).Decode(&doc); err != nil {
					t.Fatal(err)
				}
				settings, ok := doc["settings"].(map[string]any)
				if !ok || settings["count"] != float64(2) || doc["csrf"] != "required-token" || doc["input"] != "inert-marker" {
					t.Fatalf("typed JSON contract lost: %#v", doc)
				}
			} else {
				if err := req.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if req.PostForm.Get("csrf") != "required-token" || req.PostForm.Get("input") != "inert-marker" {
					t.Fatalf("required form fields lost: %v", req.PostForm)
				}
			}
		})
	}
}

func TestXSSConfirmationRejectsNonBrowserProof(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	s := NewDASTScanner(db, nil, nil, nil)
	ip := insertionPoint{URL: "https://m.local/", Param: "q", Method: "GET"}
	for _, proof := range []string{"", "differential-candidate", "inconclusive", "static"} {
		s.confirmXSS(context.Background(), tid, ip, CtxHTMLText, "inert-marker", proof, 99)
	}
	s.confirmXSS(context.Background(), tid, ip, CtxHTMLText, "", "browser", 99)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=?`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("unverified evidence became %d finding(s)", n)
	}
}
