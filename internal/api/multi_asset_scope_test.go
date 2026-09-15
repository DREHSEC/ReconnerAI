package api

import (
	"reflect"
	"sort"
	"testing"
)

func TestNormalizeScopeValuesPreservesDomainListOrderAndDeduplicates(t *testing.T) {
	raw := " Alpha.Example.com\nbeta.test\nalpha.example.com\nhttps://app.gamma.invalid/account?q=1 "
	got, err := normalizeScopeValues(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha.example.com", "beta.test", "https://app.gamma.invalid/account?q=1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized scope=%v, want %v", got, want)
	}
}

func TestReconcileManualAssetsCreatesOneRowPerDomain(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.db.Exec(`INSERT INTO targets(id,domain) VALUES('project','alpha.example,beta.test')`); err != nil {
		t.Fatal(err)
	}
	tx, err := h.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcileManualAssetsTx(tx, "project", []string{"alpha.example", "beta.test", "gamma.invalid"}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	rows, err := h.db.Query(`SELECT value FROM assets WHERE target_id='project' ORDER BY created_at,id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		got = append(got, value)
	}
	sort.Strings(got)
	want := []string{"alpha.example", "beta.test", "gamma.invalid"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("asset rows=%v, want %v", got, want)
	}
}
