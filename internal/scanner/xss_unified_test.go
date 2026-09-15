package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
)

func TestVulnScanDoesNotRunASecondXSSPipeline(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	seenXSS := false
	s := NewVulnScanner(db, nil, &config.Config{}, nil, nil)
	if err := s.Run(context.Background(), tid, "example.test", func(_, module, message string) {
		if strings.Contains(strings.ToLower(module), "xss") || strings.Contains(strings.ToLower(message), "xss scan") {
			seenXSS = true
		}
	}); err != nil {
		t.Fatal(err)
	}
	if seenXSS {
		t.Fatal("vuln_scan revived the removed parallel XSS pipeline")
	}
}

func TestLegacyVulnXSSCallerDelegatesToUnifiedEngine(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	delegated := false
	s := NewVulnScanner(db, nil, &config.Config{}, nil, nil)
	err := s.RunXSS(ctx, tid, "example.test", func(_, module, message string) {
		if module == "xss" && strings.Contains(message, "No parameter insertion points") {
			delegated = true
			cancel()
		}
	})
	if !delegated || err == nil {
		t.Fatalf("compatibility caller did not delegate to DAST XSS: delegated=%v err=%v", delegated, err)
	}
}
