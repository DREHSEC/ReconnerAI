package scanner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/database"
)

func TestGuidedURLInScopeHonorsURLSeedsAndExclusions(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "guided-scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO targets(id,domain,exclude_scope) VALUES('t','https://app.example.test:8443/api/v1/orders/42','admin.example.test')`)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for _, raw := range []string{
		"https://app.example.test:8443/api/v1/orders/99?view=full",
		"https://app.example.test:8443/api/v1/orders/history",
	} {
		if !GuidedURLInScope(ctx, db, "t", raw) {
			t.Errorf("expected URL in scope: %s", raw)
		}
	}
	for _, raw := range []string{
		"http://app.example.test:8443/api/v1/orders/42",
		"https://app.example.test/api/v1/orders/42",
		"https://api.app.example.test:8443/api/v1/orders/42",
		"https://app.example.test:8443/admin",
		"https://admin.example.test:8443/api/v1/orders/42",
	} {
		if GuidedURLInScope(ctx, db, "t", raw) {
			t.Errorf("expected URL out of scope: %s", raw)
		}
	}
}

func TestGuidedURLInScopePlainHostsAllowSubdomainsButHonorExclusions(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "guided-host.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO targets(id,domain,exclude_scope) VALUES('t','example.test','*.staging.example.test')`)
	if err != nil {
		t.Fatal(err)
	}
	if !GuidedURLInScope(context.Background(), db, "t", "https://api.example.test/orders") {
		t.Fatal("plain host scope rejected an allowed subdomain")
	}
	if GuidedURLInScope(context.Background(), db, "t", "https://api.staging.example.test/orders") {
		t.Fatal("exclude_scope did not block a guided subdomain")
	}
}
