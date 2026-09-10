package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestTemplateURLNormalizesIDs(t *testing.T) {
	h, p := templateURL("https://ops.example.test/api/v1/users/550e8400-e29b-41d4-a716-446655440000/orders/99")
	if h != "ops.example.test" {
		t.Fatalf("host=%s", h)
	}
	if p != "/api/v1/users/{id}/orders/{id}" {
		t.Fatalf("path=%s", p)
	}
}

func TestObjectMapAndHostRhyme(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	hosts := []string{"a.example.test", "b.example.test", "c.example.test"}
	for i, h := range hosts {
		if _, err := db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, source, is_reflected) VALUES (?,?,?,?,?,?,0)`,
			uuid.New().String(), tid, "https://"+h+"/api/v1/orders/"+uuid.New().String(), "accountId", "x", "js"); err != nil {
			t.Fatal(err)
		}
		_ = i
	}
	if _, err := db.Exec(`INSERT INTO http_services (id, target_id, url, status_code) VALUES (?,?,?,200)`,
		uuid.New().String(), tid, "https://ops.internal.example.test/admin/graphql"); err != nil {
		t.Fatal(err)
	}
	buckets := collectPathBuckets(context.Background(), db, tid)
	objs := formatObjectMap(buckets, 20)
	join := strings.Join(objs, "\n")
	if !strings.Contains(join, "/api/v1/orders/{id}") {
		t.Fatalf("object map missing template:\n%s", join)
	}
	common, odd := formatHostRhyme(buckets, 10, 10)
	if len(common) == 0 || !strings.Contains(strings.Join(common, "\n"), "3 hosts") {
		t.Fatalf("rhyme common=%v odd=%v", common, odd)
	}
}

func TestWatchtowerStoryIncludesOldNew(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	if _, err := db.Exec(`INSERT INTO monitoring_changes (id, target_id, url, change_type, old_value, new_value) VALUES (?,?,?,?,?,?)`,
		uuid.New().String(), tid, "https://app.example.test/app.js", "js_change", "old bundle no /admin", "new bundle /internal/admin"); err != nil {
		t.Fatal(err)
	}
	lines := watchtowerStory(context.Background(), db, tid, 5)
	if len(lines) != 1 || !strings.Contains(lines[0], "old:") || !strings.Contains(lines[0], "/internal/admin") {
		t.Fatalf("%v", lines)
	}
}

func TestBuildWarRoomIncludesHypothesisAndDossier(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	md := buildWarRoom(context.Background(), db, tid, "BOLA on /api/orders/{id}")
	for _, want := range []string{"Operator hypothesis", "BOLA on /api/orders/{id}", "Surface dossier", "Identities: 0"} {
		if !strings.Contains(md, want) {
			t.Fatalf("missing %q in %s", want, md)
		}
	}
}
