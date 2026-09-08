package agent

import (
	"context"
	"strings"
	"testing"
)

func TestParseHackerOneScope(t *testing.T) {
	raw := `{
	  "data": [
	    {"attributes":{"asset_identifier":"*.example.com","eligible_for_submission":true}},
	    {"attributes":{"asset_identifier":"admin.example.com","eligible_for_submission":false}},
	    {"attributes":{"asset_identifier":"https://app.example.com","eligible_for_submission":true}}
	  ]
	}`
	p := ParseProgramScope(raw)
	if p.Format != "hackerone" {
		t.Fatalf("format=%s", p.Format)
	}
	if !containsStr(p.Include, "*.example.com") || !containsStr(p.Include, "app.example.com") {
		t.Fatalf("include=%v", p.Include)
	}
	if !containsStr(p.Exclude, "admin.example.com") {
		t.Fatalf("exclude=%v", p.Exclude)
	}
}

func TestParseBugcrowdScope(t *testing.T) {
	raw := `{"targets":[{"name":"www.shop.test","uri":"https://www.shop.test"},{"name":"blog.shop.test","ineligible":true}]}`
	p := ParseProgramScope(raw)
	if p.Format != "bugcrowd" {
		t.Fatalf("format=%s", p.Format)
	}
	if !containsStr(p.Include, "www.shop.test") {
		t.Fatalf("include=%v", p.Include)
	}
	if !containsStr(p.Exclude, "blog.shop.test") {
		t.Fatalf("exclude=%v", p.Exclude)
	}
}

func TestHostInPatternsWildcard(t *testing.T) {
	if !hostInPatterns("api.example.com", []string{"*.example.com"}) {
		t.Fatal("wildcard miss")
	}
	if hostInPatterns("evil.com", []string{"*.example.com"}) {
		t.Fatal("wildcard over-match")
	}
	if hostInPatterns("api.example.com", []string{"admin.example.com"}) {
		t.Fatal("sibling matched as exclude/include")
	}
	if !hostInPatterns("api.example.com", []string{"example.com"}) {
		t.Fatal("parent domain should cover subdomain")
	}
}

func TestImportedScopeBlocksHTTP(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	if _, err := db.Exec(`UPDATE targets SET include_scope=?, exclude_scope=? WHERE id=?`,
		"app.example.test", "admin.example.test", tid); err != nil {
		t.Fatal(err)
	}
	res := tb.Dispatch(context.Background(), tid, "http_request", `{"url":"https://other.example.test/"}`)
	if !strings.Contains(res.JSON, "imported program scope") {
		t.Fatalf("%s", res.JSON)
	}
	res = tb.Dispatch(context.Background(), tid, "http_request", `{"url":"https://admin.example.test/"}`)
	if !strings.Contains(res.JSON, "excluded") {
		t.Fatalf("%s", res.JSON)
	}
}

func containsStr(in []string, want string) bool {
	for _, s := range in {
		if s == want {
			return true
		}
	}
	return false
}

func TestParsePlainList(t *testing.T) {
	p := ParseProgramScope("*.foo.test\nbar.foo.test")
	if p.Format != "list" || len(p.Include) != 2 {
		t.Fatalf("%+v", p)
	}
}

func TestParseHackerOneNestedProgram(t *testing.T) {
	raw := `{
	  "data": {
	    "id": "1",
	    "type": "program",
	    "relationships": {
	      "structured_scopes": {
	        "data": [
	          {"attributes":{"asset_identifier":"*.shop.test","asset_type":"WILDCARD","eligible_for_submission":true}},
	          {"attributes":{"asset_identifier":"github.com/shop/app","asset_type":"SOURCE_CODE","eligible_for_submission":true}},
	          {"attributes":{"asset_identifier":"old.shop.test","asset_type":"URL","eligible_for_submission":false}}
	        ]
	      }
	    }
	  }
	}`
	p := ParseProgramScope(raw)
	if p.Format != "hackerone" {
		t.Fatalf("format=%s", p.Format)
	}
	if !containsStr(p.Include, "*.shop.test") {
		t.Fatalf("include=%v", p.Include)
	}
	if containsStr(p.Include, "github.com/shop/app") {
		t.Fatalf("source_code leaked into include: %v", p.Include)
	}
	if !containsStr(p.Exclude, "old.shop.test") {
		t.Fatalf("exclude=%v", p.Exclude)
	}
}

func TestCheckProgramScope(t *testing.T) {
	if err := CheckProgramScope("*.example.com", "admin.example.com", "api.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := CheckProgramScope("*.example.com", "admin.example.com", "admin.example.com"); err == nil {
		t.Fatal("excluded host allowed")
	}
	if err := CheckProgramScope("app.example.com", "", "other.example.com"); err == nil {
		t.Fatal("outside include allowed")
	}
	if err := CheckProgramScope("", "admin.example.com", "app.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureInEngagementHonorsInclude(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	if _, err := db.Exec(`UPDATE targets SET include_scope=? WHERE id=?`, "app.example.test", tid); err != nil {
		t.Fatal(err)
	}
	if err := tb.ensureInEngagement(context.Background(), tid, "https://app.example.test/api"); err != nil {
		t.Fatal(err)
	}
	if err := tb.ensureInEngagement(context.Background(), tid, "https://other.example.test/"); err == nil {
		t.Fatal("expected include miss")
	}
}

func TestLeadReportMarkdown(t *testing.T) {
	md := LeadReportMarkdown("maybe IDOR", "B read A", "high", "GET", "https://app.example.test/orders/1", "200 vs 403", "authz", "confirmed")
	for _, want := range []string{"maybe IDOR", "https://app.example.test/orders/1", "Not a Reconner-verified finding", "confirmed"} {
		if !strings.Contains(md, want) {
			t.Fatalf("missing %q in %s", want, md)
		}
	}
}
