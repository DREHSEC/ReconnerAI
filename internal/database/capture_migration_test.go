package database

import (
	"path/filepath"
	"testing"
)

func TestCaptureTablesMigrationIsIdempotent(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatalf("capture migrations are not idempotent: %v", err)
	}
	for _, table := range []string{"capture_sessions", "request_templates", "captured_responses", "guided_runs", "capture_audit"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("table %s missing: count=%d err=%v", table, n, err)
		}
	}
}
