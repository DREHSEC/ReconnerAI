package agent

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

const (
	modeChat     = "chat"
	modeHunt     = "hunt"
	modeAlwaysOn = "always_on"

	statusIdle      = "idle"
	statusRunning   = "running"
	statusCancelled = "cancelled"
	statusError     = "error"
	statusFinished  = "finished"

	roleUser      = "user"
	roleAssistant = "assistant"
	roleTool      = "tool"
	roleCall      = "call" // persisted function_call (name + arguments)
)

// Thread is one operator conversation (or the hidden 24/7 hunter thread).
type Thread struct {
	ID              string    `json:"id"`
	TargetID        string    `json:"target_id"`
	UserID          int64     `json:"user_id"`
	Title           string    `json:"title"`
	Mode            string    `json:"mode"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Messages        []Message `json:"messages"`
	HunterActive    bool      `json:"hunter_active"`
	CompactSummary  string    `json:"compact_summary,omitempty"`
	CompactAfter    time.Time `json:"compact_after,omitempty"`
	TokenPrompt     int       `json:"token_prompt"`
	TokenCompletion int       `json:"token_completion"`
	TokenContext    int       `json:"token_context"`
	TokenBudget     int       `json:"token_budget"`
	MessageCount    int       `json:"message_count"`
	Preview         string    `json:"preview,omitempty"`
	Live            bool      `json:"live,omitempty"`
}

// Message is one transcript row.
type Message struct {
	ID         string    `json:"id"`
	ThreadID   string    `json:"thread_id"`
	Role       string    `json:"role"`
	Content    string    `json:"content"`
	ToolName   string    `json:"tool_name,omitempty"`
	ToolCallID string    `json:"tool_call_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Run is one copilot turn or hunt loop.
type Run struct {
	ID         string     `json:"id"`
	ThreadID   string     `json:"thread_id"`
	TargetID   string     `json:"target_id"`
	Status     string     `json:"status"`
	Iterations int        `json:"iterations"`
	Error      string     `json:"error,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type Store struct {
	db *database.DB
}

func NewStore(db *database.DB) *Store {
	return &Store{db: db}
}

func (s *Store) GetThread(ctx context.Context, targetID string) (*Thread, error) {
	// Operator-facing transcript: never the 24/7 hunter thread.
	for _, mode := range []string{modeChat, modeHunt} {
		th, err := s.GetThreadByMode(ctx, targetID, mode)
		if err != nil || th != nil {
			return th, err
		}
	}
	return nil, nil
}

func (s *Store) GetThreadByMode(ctx context.Context, targetID, mode string) (*Thread, error) {
	th := &Thread{}
	var compactAfter sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, target_id, user_id, COALESCE(title,''), mode, status, created_at, updated_at,
		       COALESCE(compact_summary,''), compact_after, COALESCE(token_prompt,0), COALESCE(token_completion,0)
		FROM agent_threads WHERE target_id=? AND mode=? ORDER BY updated_at DESC LIMIT 1`, targetID, mode).
		Scan(&th.ID, &th.TargetID, &th.UserID, &th.Title, &th.Mode, &th.Status, &th.CreatedAt, &th.UpdatedAt,
			&th.CompactSummary, &compactAfter, &th.TokenPrompt, &th.TokenCompletion)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if compactAfter.Valid {
		th.CompactAfter = compactAfter.Time
	}
	return s.loadThreadMessages(ctx, th)
}

func (s *Store) GetThreadByID(ctx context.Context, threadID string) (*Thread, error) {
	if threadID == "" {
		return nil, nil
	}
	th := &Thread{}
	var compactAfter sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, target_id, user_id, COALESCE(title,''), mode, status, created_at, updated_at,
		       COALESCE(compact_summary,''), compact_after, COALESCE(token_prompt,0), COALESCE(token_completion,0)
		FROM agent_threads WHERE id=?`, threadID).
		Scan(&th.ID, &th.TargetID, &th.UserID, &th.Title, &th.Mode, &th.Status, &th.CreatedAt, &th.UpdatedAt,
			&th.CompactSummary, &compactAfter, &th.TokenPrompt, &th.TokenCompletion)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if compactAfter.Valid {
		th.CompactAfter = compactAfter.Time
	}
	return s.loadThreadMessages(ctx, th)
}

func (s *Store) loadThreadMessages(ctx context.Context, th *Thread) (*Thread, error) {
	msgs, err := s.ListMessages(ctx, th.ID)
	if err != nil {
		return nil, err
	}
	th.Messages = msgs
	th.MessageCount = len(msgs)
	th.TokenBudget = tokenBudget
	system := copilotSystemPrompt
	if th.Mode == modeHunt {
		system = huntSystemPrompt
	} else if th.Mode == modeAlwaysOn {
		system = alwaysOnSystemPrompt
	}
	live := afterCompact(msgs, th.CompactAfter)
	th.TokenContext = contextTokens(system, th.CompactSummary, live)
	return th, nil
}

func (s *Store) ListThreads(ctx context.Context, targetID string) ([]Thread, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.id, t.target_id, t.user_id, COALESCE(t.title,''), t.mode, t.status, t.created_at, t.updated_at,
		       COALESCE(t.compact_summary,''), t.compact_after, COALESCE(t.token_prompt,0), COALESCE(t.token_completion,0),
		       (SELECT COUNT(*) FROM agent_messages m WHERE m.thread_id=t.id) AS n,
		       COALESCE((SELECT content FROM agent_messages m WHERE m.thread_id=t.id AND m.role IN ('user','assistant')
		                 ORDER BY m.created_at DESC, m.rowid DESC LIMIT 1),'') AS preview
		FROM agent_threads t
		WHERE t.target_id=? AND t.mode IN ('chat','hunt')
		ORDER BY t.updated_at DESC LIMIT 80`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Thread{}
	for rows.Next() {
		var th Thread
		var compactAfter sql.NullTime
		if err := rows.Scan(&th.ID, &th.TargetID, &th.UserID, &th.Title, &th.Mode, &th.Status, &th.CreatedAt, &th.UpdatedAt,
			&th.CompactSummary, &compactAfter, &th.TokenPrompt, &th.TokenCompletion, &th.MessageCount, &th.Preview); err != nil {
			continue
		}
		if compactAfter.Valid {
			th.CompactAfter = compactAfter.Time
		}
		th.TokenBudget = tokenBudget
		th.TokenContext = estimateTokens(th.CompactSummary) + estimateTokens(th.Preview) + th.MessageCount*8
		if th.TokenPrompt > th.TokenContext {
			th.TokenContext = th.TokenPrompt
		}
		th.Preview = clip(strings.TrimSpace(strings.ReplaceAll(th.Preview, "\n", " ")), 80)
		th.Messages = []Message{}
		out = append(out, th)
	}
	return out, rows.Err()
}

func (s *Store) CreateThread(ctx context.Context, targetID string, userID int64, mode, title string) (*Thread, error) {
	if mode == "" || mode == modeAlwaysOn {
		mode = modeChat
	}
	th := &Thread{
		ID:          uuid.New().String(),
		TargetID:    targetID,
		UserID:      userID,
		Title:       clip(strings.TrimSpace(title), 80),
		Mode:        mode,
		Status:      statusIdle,
		Messages:    []Message{},
		TokenBudget: tokenBudget,
	}
	now := time.Now()
	th.CreatedAt, th.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_threads (id, target_id, user_id, title, mode, status)
		VALUES (?,?,?,?,?,?)`, th.ID, th.TargetID, th.UserID, th.Title, th.Mode, th.Status)
	if err != nil {
		return nil, fmt.Errorf("create agent thread: %w", err)
	}
	return th, nil
}

func (s *Store) DeleteThread(ctx context.Context, targetID, threadID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM agent_threads WHERE id=? AND target_id=? AND mode IN ('chat','hunt')`, threadID, targetID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("thread not found")
	}
	return nil
}

func (s *Store) SaveCompact(ctx context.Context, threadID, summary string, after time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE agent_threads SET compact_summary=?, compact_after=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		clip(summary, 8000), after.UTC().Format("2006-01-02 15:04:05.000"), threadID)
	return err
}

func (s *Store) SaveUsage(ctx context.Context, threadID string, prompt, completion int) {
	_, _ = s.db.ExecContext(ctx, `
		UPDATE agent_threads SET token_prompt=?, token_completion=?, updated_at=updated_at WHERE id=?`,
		prompt, completion, threadID)
}

func (s *Store) EnsureThread(ctx context.Context, targetID string, userID int64, mode string) (*Thread, error) {
	if mode == "" {
		mode = modeChat
	}
	if existing, err := s.GetThreadByMode(ctx, targetID, mode); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	th := &Thread{
		ID:       uuid.New().String(),
		TargetID: targetID,
		UserID:   userID,
		Mode:     mode,
		Status:   statusIdle,
		Messages: []Message{},
	}
	if th.Mode == "" {
		th.Mode = modeChat
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_threads (id, target_id, user_id, title, mode, status)
		VALUES (?,?,?,?,?,?)`, th.ID, th.TargetID, th.UserID, th.Title, th.Mode, th.Status)
	if err != nil {
		return nil, fmt.Errorf("create agent thread: %w", err)
	}
	now := time.Now()
	th.CreatedAt, th.UpdatedAt = now, now
	return th, nil
}

func (s *Store) SetThreadStatus(ctx context.Context, threadID, status string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE agent_threads SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, status, threadID)
}

func (s *Store) SetThreadTitle(ctx context.Context, threadID, title string) {
	title = clip(strings.TrimSpace(title), 80)
	if title == "" {
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE agent_threads SET title=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, title, threadID)
}

func (s *Store) ListMessages(ctx context.Context, threadID string) ([]Message, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, thread_id, role, content, COALESCE(tool_name,''), COALESCE(tool_call_id,''), created_at
		FROM agent_messages WHERE thread_id=? ORDER BY created_at ASC, rowid ASC`, threadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.ThreadID, &m.Role, &m.Content, &m.ToolName, &m.ToolCallID, &m.CreatedAt); err == nil {
			out = append(out, m)
		}
	}
	return out, rows.Err()
}

func (s *Store) Append(ctx context.Context, threadID, role, content, toolName, toolCallID string) (Message, error) {
	m := Message{
		ID:         uuid.New().String(),
		ThreadID:   threadID,
		Role:       role,
		Content:    content,
		ToolName:   toolName,
		ToolCallID: toolCallID,
		CreatedAt:  time.Now(),
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_messages (id, thread_id, role, content, tool_name, tool_call_id)
		VALUES (?,?,?,?,?,?)`, m.ID, m.ThreadID, m.Role, m.Content, m.ToolName, m.ToolCallID)
	if err != nil {
		return m, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE agent_threads SET updated_at=CURRENT_TIMESTAMP WHERE id=?`, threadID)
	return m, nil
}

func (s *Store) StartRun(ctx context.Context, threadID, targetID string) (*Run, error) {
	r := &Run{
		ID:        uuid.New().String(),
		ThreadID:  threadID,
		TargetID:  targetID,
		Status:    statusRunning,
		StartedAt: time.Now(),
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_runs (id, thread_id, target_id, status, iterations)
		VALUES (?,?,?,?,0)`, r.ID, r.ThreadID, r.TargetID, r.Status)
	if err != nil {
		return nil, err
	}
	s.SetThreadStatus(ctx, threadID, statusRunning)
	return r, nil
}

func (s *Store) FinishRun(ctx context.Context, runID, threadID, status, errMsg string) {
	_, _ = s.db.ExecContext(ctx, `
		UPDATE agent_runs SET status=?, error=?, finished_at=CURRENT_TIMESTAMP WHERE id=?`,
		status, errMsg, runID)
	s.SetThreadStatus(ctx, threadID, status)
}

// ReclaimOrphans marks every in-flight thread/run cancelled. Call on process
// start: a docker restart kills the goroutine but leaves status=running in
// SQLite, which locks the copilot composer forever.
func (s *Store) ReclaimOrphans(ctx context.Context, reason string) {
	if s == nil || s.db == nil {
		return
	}
	if strings.TrimSpace(reason) == "" {
		reason = "interrupted"
	}
	_, _ = s.db.ExecContext(ctx, `
		UPDATE agent_runs SET status=?, error=?, finished_at=CURRENT_TIMESTAMP
		WHERE status=? AND finished_at IS NULL`, statusCancelled, reason, statusRunning)
	_, _ = s.db.ExecContext(ctx, `
		UPDATE agent_threads SET status=?, updated_at=CURRENT_TIMESTAMP WHERE status=?`,
		statusIdle, statusRunning)
}

// ReclaimThread unsticks one operator-facing thread whose worker is gone.
func (s *Store) ReclaimThread(ctx context.Context, threadID, reason string) {
	if s == nil || s.db == nil || threadID == "" {
		return
	}
	if strings.TrimSpace(reason) == "" {
		reason = "interrupted"
	}
	_, _ = s.db.ExecContext(ctx, `
		UPDATE agent_runs SET status=?, error=?, finished_at=CURRENT_TIMESTAMP
		WHERE thread_id=? AND status=? AND finished_at IS NULL`,
		statusCancelled, reason, threadID, statusRunning)
	s.SetThreadStatus(ctx, threadID, statusIdle)
}

func (s *Store) BumpIterations(ctx context.Context, runID string, n int) {
	_, _ = s.db.ExecContext(ctx, `UPDATE agent_runs SET iterations=? WHERE id=?`, n, runID)
}
