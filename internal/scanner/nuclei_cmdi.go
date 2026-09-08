package scanner

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/models"
)

// Unix/Windows command-output signatures. A nuclei cmdi/rce template that does
// not reproduce at least one of these is almost always a 4xx/5xx error page
// (Matomo ERROR (239), generic 500) rather than a shell. Time-based / OAST
// templates are excluded — they are not expected to echo output.
var unixCmdiProof = []*regexp.Regexp{
	regexp.MustCompile(`uid=\d+\([A-Za-z0-9._-]+\)\s+gid=\d+\(`),
	regexp.MustCompile(`(?m)^uid=\d+\(`),
	regexp.MustCompile(`root:x:0:0:`),
}

var winCmdiProof = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Volume Serial Number`),
	regexp.MustCompile(`(?i)Directory of [A-Z]:\\`),
	regexp.MustCompile(`(?i)NT AUTHORITY\\`),
	regexp.MustCompile(`(?i)\[boot loader\]`),
	regexp.MustCompile(`(?i)Windows IP Configuration`),
}

func nucleiCmdiTimeOrOAST(templateID, name string, tags []string) bool {
	hay := strings.ToLower(templateID + " " + name + " " + strings.Join(tags, " "))
	for _, m := range []string{"oast", "interactsh", "time-based", "time based", "timedelay", "time-delay", "blind"} {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}

func nucleiCmdiExecutionProof(body string) bool {
	if body == "" {
		return false
	}
	for _, re := range unixCmdiProof {
		if re.MatchString(body) {
			return true
		}
	}
	for _, re := range winCmdiProof {
		if re.MatchString(body) {
			return true
		}
	}
	return false
}

func httpStatusOf(response string) int {
	line := response
	if nl := strings.IndexAny(response, "\r\n"); nl >= 0 {
		line = response[:nl]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(fields[1])
	return n
}

// nucleiCmdiLacksProof reports whether a command-injection/RCE nuclei hit has
// no shell-output proof in the captured response. Used at ingest (drop) and
// when scrubbing unverified rows so a 500 ERROR body never becomes a finding.
func nucleiCmdiLacksProof(templateID, name string, tags []string, request, response string) bool {
	if !nucleiInjectionEchoClass(templateID, name, tags) {
		return false
	}
	if nucleiCmdiTimeOrOAST(templateID, name, tags) {
		return false
	}
	if strings.TrimSpace(response) == "" {
		return false // no captured body → inconclusive, not an auto-FP
	}
	body := httpBodyOf(response)
	if nucleiCmdiExecutionProof(body) {
		return false
	}
	_ = request
	return true
}

// ScrubNucleiCmdiFPs marks unverified nuclei cmdi/rce rows that lack execution
// proof as rejected. Returns how many rows changed. Operator-confirmed
// (verification=verified) rows are left alone.
func ScrubNucleiCmdiFPs(db *database.DB, targetID string) int {
	if db == nil {
		return 0
	}
	q := `SELECT id, target_id, template_id, template_name, COALESCE(tags,''), COALESCE(request,''), COALESCE(response,'')
		FROM nuclei_findings WHERE COALESCE(verification,'unverified') = 'unverified'`
	args := []any{}
	if targetID != "" {
		q += ` AND target_id=?`
		args = append(args, targetID)
	}
	rows, err := db.Query(q, args...)
	if err != nil {
		return 0
	}
	defer rows.Close()
	type hit struct {
		id, tid, tmpl, name, tagsJSON, req, resp string
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if rows.Scan(&h.id, &h.tid, &h.tmpl, &h.name, &h.tagsJSON, &h.req, &h.resp) == nil {
			hits = append(hits, h)
		}
	}
	n := 0
	touched := map[string]bool{}
	for _, h := range hits {
		if !nucleiCmdiLacksProof(h.tmpl, h.name, models.JSONToStringSlice(h.tagsJSON), h.req, h.resp) {
			continue
		}
		res, err := db.Exec(`UPDATE nuclei_findings SET verification='rejected', confidence=0 WHERE id=? AND COALESCE(verification,'unverified')='unverified'`, h.id)
		if err != nil {
			continue
		}
		if k, _ := res.RowsAffected(); k > 0 {
			n++
			touched[h.tid] = true
		}
	}
	for tid := range touched {
		refreshTargetFindingCount(db, tid)
	}
	return n
}

func refreshTargetFindingCount(db *database.DB, targetID string) {
	var n int
	_ = db.QueryRow(`
		SELECT
			(SELECT COUNT(DISTINCT template_id) FROM nuclei_findings WHERE target_id = ? AND COALESCE(verification,'unverified') != 'rejected') +
			(SELECT COUNT(*) FROM backup_findings WHERE target_id = ?) +
			(SELECT COUNT(*) FROM open_redirect_findings WHERE target_id = ? AND COALESCE(status,'finding')='finding') +
			(SELECT COUNT(*) FROM vuln_findings WHERE target_id = ? AND COALESCE(status,'finding')='finding' AND COALESCE(triage,'') != 'false_positive')
	`, targetID, targetID, targetID, targetID).Scan(&n)
	_, _ = db.Exec(`UPDATE targets SET finding_count=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, n, targetID)
}
