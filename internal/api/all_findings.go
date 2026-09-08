package api

import (
	"net/http"
	"strings"

	"github.com/recon-platform/internal/scanner"
)

// Global findings view. The per-target tabs are the detail view; a community
// operator running many targets also wants ONE place that answers "what has
// Reconner actually found, everywhere, right now". handleListAllFindings
// aggregates confirmed vuln findings across every target the caller owns (all
// targets for an admin), newest/most-severe first, with the target each belongs
// to — the backing data for the top-level Findings page.

type allFinding struct {
	ID         string `json:"id"`
	TargetID   string `json:"target_id"`
	Domain     string `json:"domain"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Confidence int    `json:"confidence"`
	Priority   int    `json:"priority"`
	Status     string `json:"status"`
	Evidence   string `json:"evidence"`
	CreatedAt  string `json:"created_at"`
	Source     string `json:"source"` // vuln | nuclei
}

// handleListAllFindings (GET /findings) returns confirmed findings across all of
// the caller's targets. Optional query params: status (finding|candidate|all,
// default finding), severity (critical|high|medium|low|info), type.
func (h *Handler) handleListAllFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	if status == "" {
		status = "finding"
	}
	_ = scanner.ScrubNucleiCmdiFPs(h.db, "")

	ownerSQL := ""
	var ownerUID any
	if uid, isAdmin := h.callerScope(r); !isAdmin {
		ownerSQL = " AND t.owner_id = ?"
		ownerUID = uid
	}

	vulnArgs := []any{}
	vuln := `SELECT f.id AS id, f.target_id AS target_id, COALESCE(t.domain,'') AS domain, f.type AS type, f.severity AS severity,
			f.url AS url, COALESCE(f.parameter,'') AS parameter,
			COALESCE(f.confidence,0) AS confidence, COALESCE(f.priority,0) AS priority, COALESCE(f.status,'finding') AS status,
			SUBSTR(COALESCE(f.evidence,''),1,2000) AS evidence, f.created_at AS created_at, 'vuln' AS source
		FROM vuln_findings f JOIN targets t ON t.id = f.target_id
		WHERE COALESCE(f.triage,'') != 'false_positive'` + ownerSQL
	if ownerUID != nil {
		vulnArgs = append(vulnArgs, ownerUID)
	}
	if status != "all" {
		vuln += " AND COALESCE(f.status,'finding') = ?"
		vulnArgs = append(vulnArgs, status)
	}

	nucleiArgs := []any{}
	nuclei := `SELECT n.id AS id, n.target_id AS target_id, COALESCE(t.domain,'') AS domain, n.template_id AS type, n.severity AS severity,
			n.matched_url AS url, '' AS parameter,
			COALESCE(n.confidence,0) AS confidence, 0 AS priority,
			CASE WHEN COALESCE(n.verification,'unverified')='verified' THEN 'finding' ELSE 'candidate' END AS status,
			SUBSTR(COALESCE(n.description,''),1,2000) AS evidence, n.created_at AS created_at, 'nuclei' AS source
		FROM (
			SELECT id, target_id, template_id, severity, matched_url, description, confidence, verification, created_at,
				ROW_NUMBER() OVER (PARTITION BY target_id, template_id ORDER BY LENGTH(matched_url) ASC, created_at DESC) AS rn
			FROM nuclei_findings
			WHERE COALESCE(verification,'unverified') NOT IN ('rejected','accepted')
		) n JOIN targets t ON t.id = n.target_id
		WHERE n.rn = 1` + ownerSQL
	if ownerUID != nil {
		nucleiArgs = append(nucleiArgs, ownerUID)
	}
	if status == "finding" {
		nuclei += " AND COALESCE(n.verification,'unverified') = 'verified'"
	} else if status == "candidate" {
		nuclei += " AND COALESCE(n.verification,'unverified') NOT IN ('verified','rejected','accepted')"
	}

	if sev := q.Get("severity"); sev != "" {
		ls := strings.ToLower(sev)
		vuln += " AND LOWER(f.severity) = ?"
		nuclei += " AND LOWER(n.severity) = ?"
		vulnArgs = append(vulnArgs, ls)
		nucleiArgs = append(nucleiArgs, ls)
	}
	if typ := q.Get("type"); typ != "" {
		vuln += " AND f.type = ?"
		nuclei += " AND n.template_id = ?"
		vulnArgs = append(vulnArgs, typ)
		nucleiArgs = append(nucleiArgs, typ)
	}

	args := append(vulnArgs, nucleiArgs...)
	query := `SELECT id, target_id, domain, type, severity, url, parameter, confidence, priority, status, evidence, created_at, source
		FROM (` + vuln + ` UNION ALL ` + nuclei + `)
		ORDER BY priority DESC,
			CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			created_at DESC LIMIT 1000`

	rows, err := h.db.Query(query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	out := []allFinding{}
	for rows.Next() {
		var f allFinding
		if err := rows.Scan(&f.ID, &f.TargetID, &f.Domain, &f.Type, &f.Severity,
			&f.URL, &f.Parameter, &f.Confidence, &f.Priority, &f.Status,
			&f.Evidence, &f.CreatedAt, &f.Source); err != nil {
			continue
		}
		out = append(out, f)
	}
	h.writeSuccess(w, out)
}
