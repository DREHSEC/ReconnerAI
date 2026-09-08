package agent

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const compactSystemPrompt = `You compress an operator copilot transcript so the next turn can keep working on the SAME authorized Reconner target.

Keep: hypotheses, in-scope hosts/URLs, tool outcomes that matter (status codes, finding ids, dead ends), identities/session notes, and the next useful step.
Drop: raw dumps, repeated probes, boilerplate, secrets (cookies, Authorization).
Do not invent evidence or claim a verified finding. 400–800 words. Plain markdown.`

// splitForCompact keeps the last keepUserTurns user turns (and everything
// after that cut) as the live window. Older messages are the compact source.
func splitForCompact(msgs []Message, keepUserTurns int) (old, recent []Message) {
	if keepUserTurns < 1 {
		keepUserTurns = 1
	}
	if len(msgs) == 0 {
		return nil, nil
	}
	userIdx := make([]int, 0, 8)
	for i, m := range msgs {
		if m.Role == roleUser {
			userIdx = append(userIdx, i)
		}
	}
	if len(userIdx) <= keepUserTurns {
		return nil, msgs
	}
	cut := userIdx[len(userIdx)-keepUserTurns]
	if cut <= 0 {
		return nil, msgs
	}
	return msgs[:cut], msgs[cut:]
}

func extractiveCompact(old []Message) string {
	var b strings.Builder
	for _, m := range old {
		switch m.Role {
		case roleUser:
			fmt.Fprintf(&b, "Operator: %s\n", clip(m.Content, 600))
		case roleAssistant:
			fmt.Fprintf(&b, "Copilot: %s\n", clip(m.Content, 900))
		case roleCall:
			fmt.Fprintf(&b, "Tool %s(%s)\n", m.ToolName, clip(m.Content, 160))
		case roleTool:
			fmt.Fprintf(&b, "Result %s: %s\n", m.ToolName, clip(m.Content, 240))
		}
		if b.Len() > 12000 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func afterCompact(msgs []Message, after time.Time) []Message {
	if after.IsZero() {
		return msgs
	}
	for i, m := range msgs {
		if !m.CreatedAt.Before(after) {
			return msgs[i:]
		}
	}
	if len(msgs) > 4 {
		return msgs[len(msgs)-4:]
	}
	return msgs
}

func withCompactMemory(system, summary string, msgs []Message) []InputItem {
	items := []InputItem{{Role: "system", Content: system}}
	if strings.TrimSpace(summary) != "" {
		items = append(items, InputItem{
			Role:    "system",
			Content: "Compressed earlier conversation (not new evidence):\n" + summary,
		})
	}
	budgeted := trimTranscript(msgs, transcriptBudget)
	for _, m := range budgeted {
		switch m.Role {
		case roleUser:
			items = append(items, InputItem{Role: "user", Content: m.Content})
		case roleAssistant:
			items = append(items, InputItem{Role: "assistant", Content: m.Content})
		case roleCall:
			items = append(items, InputItem{
				Type: "function_call", CallID: m.ToolCallID, Name: m.ToolName, Arguments: m.Content,
			})
		case roleTool:
			items = append(items, InputItem{
				Type: "function_call_output", CallID: m.ToolCallID, Output: m.Content,
			})
		}
	}
	return items
}

type CompactResult struct {
	Summary      string `json:"summary"`
	BeforeTokens int    `json:"before_tokens"`
	AfterTokens  int    `json:"after_tokens"`
	SavedTokens  int    `json:"saved_tokens"`
	Compacted    bool   `json:"compacted"`
}

func (r *Runtime) Compact(ctx context.Context, targetID, threadID string, force bool) (*CompactResult, error) {
	if r == nil || r.store == nil {
		return nil, fmt.Errorf("copilot is not configured")
	}
	th, err := r.store.GetThreadByID(ctx, threadID)
	if err != nil {
		return nil, err
	}
	if th == nil || th.TargetID != targetID {
		return nil, fmt.Errorf("thread not found")
	}
	if th.Mode == modeAlwaysOn {
		return nil, fmt.Errorf("cannot compact the 24/7 hunter thread")
	}
	return r.compactThread(ctx, th, force)
}

func (r *Runtime) compactThread(ctx context.Context, th *Thread, force bool) (*CompactResult, error) {
	msgs := th.Messages
	live := afterCompact(msgs, th.CompactAfter)
	system := copilotSystemPrompt
	if th.Mode == modeHunt {
		system = huntSystemPrompt
	}
	before := contextTokens(system, th.CompactSummary, live)
	out := &CompactResult{BeforeTokens: before, AfterTokens: before, Summary: th.CompactSummary}
	if !force && before < compactThreshold() {
		return out, nil
	}
	keep := keepTurnsAuto
	if force {
		keep = keepTurnsManual
	}
	old, recent := splitForCompact(live, keep)
	if len(old) == 0 || len(recent) == 0 {
		return out, nil
	}
	src := extractiveCompact(old)
	if src == "" {
		return out, nil
	}
	summary := src
	if r.client != nil && ctx.Err() == nil {
		user := src
		if strings.TrimSpace(th.CompactSummary) != "" {
			user = "Previous compressed memory:\n" + clip(th.CompactSummary, 2500) + "\n\nAdditional turns to compress:\n" + src
		}
		resp, err := r.client.Complete(ctx, CompletionRequest{
			Model: r.compactModel(),
			Input: []InputItem{
				{Role: "system", Content: compactSystemPrompt},
				{Role: "user", Content: clip(user, 14000)},
			},
		})
		if err == nil && resp != nil && strings.TrimSpace(resp.Text) != "" {
			summary = strings.TrimSpace(resp.Text)
		}
	}
	watermark := recent[0].CreatedAt
	if err := r.store.SaveCompact(ctx, th.ID, summary, watermark); err != nil {
		return nil, err
	}
	after := contextTokens(system, summary, recent)
	out.Summary = summary
	out.AfterTokens = after
	out.SavedTokens = before - after
	if out.SavedTokens < 0 {
		out.SavedTokens = 0
	}
	out.Compacted = true
	th.CompactSummary = summary
	th.CompactAfter = watermark
	r.emit(Event{
		TargetID: th.TargetID, ThreadID: th.ID, Kind: "compact",
		Payload: map[string]any{
			"saved_tokens":  out.SavedTokens,
			"after_tokens":  after,
			"before_tokens": before,
			"token_budget":  tokenBudget,
		},
	})
	return out, nil
}

func (r *Runtime) compactModel() string {
	if r.cfg != nil {
		r.cfg.NormalizeAI()
		if r.cfg.AIModel != "" {
			return r.cfg.AIModel
		}
	}
	return "GLM-5.3-Flash"
}

func (r *Runtime) maybeCompact(ctx context.Context, threadID string) {
	th, err := r.store.GetThreadByID(ctx, threadID)
	if err != nil || th == nil || th.Mode == modeAlwaysOn {
		return
	}
	system := copilotSystemPrompt
	if th.Mode == modeHunt {
		system = huntSystemPrompt
	}
	live := afterCompact(th.Messages, th.CompactAfter)
	if contextTokens(system, th.CompactSummary, live) < compactThreshold() {
		return
	}
	_, _ = r.compactThread(ctx, th, false)
}
