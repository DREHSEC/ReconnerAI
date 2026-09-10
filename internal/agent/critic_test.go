package agent

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
)

func TestParseCriticJSON(t *testing.T) {
	raw := "Here you go\n```json\n{\"decisions\":[{\"id\":\"abc\",\"action\":\"dismiss\",\"reason\":\"xss spam\"}]}\n```"
	got := parseCriticJSON(raw)
	if len(got) != 1 || got[0].ID != "abc" || got[0].Action != "dismiss" {
		t.Fatalf("%+v", got)
	}
}

type criticCompleter struct{ text string }

func (c criticCompleter) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	return &CompletionResponse{Text: c.text}, nil
}

func TestCritiqueDismissesPendingLead(t *testing.T) {
	db := testDB(t)
	tid := insertTarget(t, db)
	lid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO agent_leads (id, target_id, title, body, playbook, status, created_at) VALUES (?,?,?,?, 'reflection', 'pending', CURRENT_TIMESTAMP)`,
		lid, tid, "xss on q", "reflected"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AIEnabled: true, XAIAPIKeyField: "k", AIModel: "GLM-5.3-Flash"}
	rt := New(cfg, db, nil, nil)
	rt.SetCompleter(criticCompleter{text: `{"decisions":[{"id":"` + lid + `","action":"dismiss","reason":"xss spam"}]}`})
	rt.critiqueRecentLeads(context.Background(), tid, "filed xss")
	var st string
	if err := db.QueryRow(`SELECT status FROM agent_leads WHERE id=?`, lid).Scan(&st); err != nil || st != "dismissed" {
		t.Fatalf("status=%s err=%v", st, err)
	}
}
