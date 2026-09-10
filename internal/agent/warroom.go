package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/recon-platform/internal/database"
)

func buildWarRoom(ctx context.Context, db *database.DB, targetID, hypothesis string) string {
	if db == nil || targetID == "" {
		return huntUserMessage(hypothesis)
	}
	pb := pickPlaybook(ctx, db, targetID)
	var b strings.Builder
	b.WriteString("# Operator war room\n\n")
	b.WriteString("You have a fat recon graph and a human operator. Spend tokens on one high-impact thesis. Do not page XSS candidates.\n\n")
	if strings.TrimSpace(hypothesis) != "" {
		b.WriteString("## Operator hypothesis\n")
		b.WriteString(strings.TrimSpace(hypothesis))
		b.WriteString("\n\n")
	} else {
		b.WriteString("No operator hypothesis — form one from the dossier, preferring authz objects, JS-only APIs, odd hosts, leftovers, and watchtower diffs.\n\n")
	}
	idents := dossierLines(ctx, db, `SELECT label || CASE WHEN is_baseline=1 THEN ' (baseline)' ELSE '' END FROM identities WHERE target_id=? ORDER BY is_baseline DESC LIMIT 6`, targetID)
	if len(idents) == 0 {
		b.WriteString("Identities: 0. You can MAP objects and flag the map; you cannot prove BOLA until the operator adds two sessions.\n\n")
	} else {
		fmt.Fprintf(&b, "Identities (%d): %s. Use diff_identities. Do not print cookies.\n\n", len(idents), strings.Join(idents, ", "))
	}
	b.WriteString(buildSurfaceDossier(ctx, db, targetID, pb))
	return b.String()
}
