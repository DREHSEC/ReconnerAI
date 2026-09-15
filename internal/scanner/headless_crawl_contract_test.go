package scanner

import (
	"context"
	"net/http"
	"testing"
)

func TestHeadlessStoreParamsPreservesRenderedFormContract(t *testing.T) {
	db, targetID := testDB(t)
	defer db.Close()
	crawler := &HeadlessCrawler{db: db}

	params := []paramEntry{
		{URL: "https://app.example.test/search", Param: "q", Value: "books", Source: "headless-form", Method: http.MethodGet, Location: "query"},
		{URL: "https://app.example.test/submit", Param: "csrf", Value: "token-1", Source: "headless-form", Method: http.MethodPost, ContentType: "application/x-www-form-urlencoded", Location: "body"},
		{URL: "https://app.example.test/submit", Param: "note", Value: "hello", Source: "headless-form", Method: http.MethodPost, ContentType: "application/x-www-form-urlencoded", Location: "body"},
	}
	if got := crawler.storeParams(context.Background(), targetID, params); got != len(params) {
		t.Fatalf("stored %d rendered fields, want %d", got, len(params))
	}

	rows, err := db.Query(`SELECT parameter,value,method,content_type,location FROM parameters WHERE target_id=?`, targetID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]paramEntry{}
	for rows.Next() {
		var p paramEntry
		if err := rows.Scan(&p.Param, &p.Value, &p.Method, &p.ContentType, &p.Location); err != nil {
			t.Fatal(err)
		}
		seen[p.Param] = p
	}
	if p := seen["q"]; p.Method != http.MethodGet || p.Location != "query" || p.ContentType != "" || p.Value != "books" {
		t.Fatalf("rendered GET form contract not preserved: %+v", p)
	}
	if p := seen["csrf"]; p.Method != http.MethodPost || p.Location != "body" || p.ContentType != "application/x-www-form-urlencoded" || p.Value != "token-1" {
		t.Fatalf("rendered POST form contract not preserved: %+v", p)
	}
}
