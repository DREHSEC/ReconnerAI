package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
	"github.com/recon-platform/internal/websocket"
)

const (
	transcriptBudget = 80000
	huntScanWait     = 15 * time.Second
)

// Event is broadcast on the websocket hub as type "agent_event".
type Event struct {
	TargetID string `json:"target_id"`
	ThreadID string `json:"thread_id"`
	RunID    string `json:"run_id"`
	Kind     string `json:"kind"`
	Payload  any    `json:"payload"`
}

// Runtime is the shared copilot/hunt loop. One in-flight run per target.
type Runtime struct {
	cfg    *config.Config
	store  *Store
	tools  *Toolbox
	client Completer
	hub    *websocket.Hub

	mu     sync.Mutex
	active map[string]liveRun
	runEnv map[string]CallEnv

	hunterMu        sync.Mutex
	hunterStop      context.CancelFunc
	hunterSnap      HunterSnapshot
	hunterLastPick  time.Time
	hunterFailUntil time.Time
}

func New(cfg *config.Config, db *database.DB, sched ScanStarter, hub *websocket.Hub) *Runtime {
	var box *secret.Box
	if cfg != nil {
		box = secret.New(cfg.SessionSecret)
	}
	r := &Runtime{
		cfg:    cfg,
		store:  NewStore(db),
		tools:  NewToolbox(db, sched, box),
		hub:    hub,
		active: map[string]liveRun{},
		runEnv: map[string]CallEnv{},
	}
	if cfg != nil {
		r.tools.cfg = cfg
		r.client = clientFromConfig(cfg)
	}
	r.store.ReclaimOrphans(context.Background(), "interrupted (process restart)")
	return r
}

type liveRun struct {
	cancel   context.CancelFunc
	mode     string
	threadID string
}

func clientFromConfig(cfg *config.Config) Completer {
	if cfg == nil {
		return nil
	}
	c := NewClient(cfg.AIAPIKey, func() string { return cfg.AIModel }, cfg.AIBaseURL)
	c.Timeout = func() time.Duration {
		s := 180
		if cfg.AITimeoutSeconds > 0 {
			s = cfg.AITimeoutSeconds
		}
		return time.Duration(s) * time.Second
	}
	c.MaxTokens = func() int {
		if cfg.AIMaxTokens > 0 {
			return cfg.AIMaxTokens
		}
		return 8192
	}
	return c
}

// ApplyAISettings rebuilds the inference client and probe HTTP stack after
// System → Integrations saves new agent knobs.
func (r *Runtime) ApplyAISettings() {
	if r == nil || r.cfg == nil {
		return
	}
	r.cfg.NormalizeAI()
	r.client = clientFromConfig(r.cfg)
	if r.tools != nil {
		r.tools.cfg = r.cfg
		r.tools.http = newProbeClientWithTimeout(time.Duration(r.cfg.AIHTTPTimeoutSeconds) * time.Second)
		if r.tools.limit != nil {
			r.tools.limit.max = r.cfg.AIHunterHTTPPerMin
		}
	}
	if r.cfg.AIHunterEnabled {
		r.StartHunter()
	} else {
		r.StopHunter()
	}
}

func (r *Runtime) SetCompleter(c Completer) { r.client = c }

func (r *Runtime) Status() map[string]any {
	enabled, model, maxIt := false, "GLM-5.3-Flash", 40
	keySet, fromEnv := false, false
	base := "https://litellm.合.xyz/v1"
	if r.cfg != nil {
		r.cfg.NormalizeAI()
		enabled = r.cfg.AIEnabled
		model = r.cfg.AIModel
		maxIt = r.cfg.AIMaxIterations
		keySet = r.cfg.AIAPIKey() != ""
		fromEnv = r.cfg.AIKeyFromEnv()
		base = r.cfg.AIBaseURL()
	}
	out := map[string]any{
		"enabled":        enabled,
		"key_set":        keySet,
		"key_from_env":   fromEnv,
		"model":          model,
		"base_url":       base,
		"max_iterations": maxIt,
		"hunter":         r.HunterStatus(),
	}
	if r.cfg != nil {
		out["max_tokens"] = r.cfg.AIMaxTokens
		out["timeout_seconds"] = r.cfg.AITimeoutSeconds
		out["http_timeout_seconds"] = r.cfg.AIHTTPTimeoutSeconds
		out["http_body_cap"] = r.cfg.AIHTTPBodyCap
		out["hunter_http_per_min"] = r.cfg.AIHunterHTTPPerMin
		out["hunter_scan_cap"] = r.cfg.AIHunterScanCap
		out["hunter_cycle_minutes"] = r.cfg.AIHunterCycleMinutes
		out["hunter_skip_running"] = r.cfg.AIHunterSkipRunning
		out["hunter_dead_end_hours"] = r.cfg.AIHunterDeadEndHours
		out["hunter_waf_minutes"] = r.cfg.AIHunterWAFMinutes
		out["exec_enabled"] = r.cfg.AIExecEnabled
		out["exec_timeout_seconds"] = r.cfg.AIExecTimeoutSeconds
	}
	return out
}

func (r *Runtime) Ready() error {
	if r == nil || r.cfg == nil {
		return fmt.Errorf("AI copilot is not configured")
	}
	if !r.cfg.AIEnabled {
		return fmt.Errorf("AI copilot is disabled — enable it in System → Integrations")
	}
	if r.cfg.AIAPIKey() == "" {
		return fmt.Errorf("AI_API_KEY is not set")
	}
	return nil
}

func (r *Runtime) Busy(targetID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.active[targetID]
	return ok
}

func (r *Runtime) Cancel(targetID string) bool {
	r.mu.Lock()
	lr, ok := r.active[targetID]
	r.mu.Unlock()
	if ok && lr.cancel != nil {
		lr.cancel()
		return true
	}
	// No live goroutine — still unstick a leftover running chat/hunt thread
	// (typical after a container rebuild mid-turn).
	th, _ := r.store.GetThread(context.Background(), targetID)
	if th != nil && th.Status == statusRunning {
		r.store.ReclaimThread(context.Background(), th.ID, "cancelled")
		return true
	}
	return false
}

type StartResult struct {
	ThreadID string `json:"thread_id"`
	RunID    string `json:"run_id"`
	Mode     string `json:"mode"`
}

func (r *Runtime) StartChat(parent context.Context, targetID string, userID int64, content string) (*StartResult, error) {
	return r.start(parent, targetID, userID, modeChat, content, "")
}

func (r *Runtime) StartChatOn(parent context.Context, targetID string, userID int64, content, threadID string) (*StartResult, error) {
	return r.start(parent, targetID, userID, modeChat, content, threadID)
}

func (r *Runtime) StartHunt(parent context.Context, targetID string, userID int64, hypothesis string) (*StartResult, error) {
	return r.start(parent, targetID, userID, modeHunt, huntUserMessage(hypothesis), "")
}

func (r *Runtime) StartHuntOn(parent context.Context, targetID string, userID int64, hypothesis, threadID string) (*StartResult, error) {
	return r.start(parent, targetID, userID, modeHunt, huntUserMessage(hypothesis), threadID)
}

func (r *Runtime) GetThread(ctx context.Context, targetID string) (*Thread, error) {
	return r.LoadThread(ctx, targetID, "")
}

func (r *Runtime) LoadThread(ctx context.Context, targetID, threadID string) (*Thread, error) {
	var (
		th  *Thread
		err error
	)
	if threadID != "" {
		th, err = r.store.GetThreadByID(ctx, threadID)
		if err != nil {
			return nil, err
		}
		if th != nil && th.TargetID != targetID {
			return nil, fmt.Errorf("thread not found")
		}
		if th != nil && th.Mode == modeAlwaysOn {
			return nil, fmt.Errorf("thread not found")
		}
	} else {
		th, err = r.store.GetThread(ctx, targetID)
	}
	if err != nil {
		return th, err
	}
	if th != nil && th.Status == statusRunning && !r.liveFor(targetID, th.ID) {
		r.store.ReclaimThread(ctx, th.ID, "interrupted (no live worker)")
		th.Status = statusIdle
	}
	if th != nil {
		th.HunterActive = r.HunterHolds(targetID)
		th.Live = r.liveFor(targetID, th.ID)
		th.TokenBudget = tokenBudget
	}
	return th, nil
}

func (r *Runtime) ListThreads(ctx context.Context, targetID string) ([]Thread, error) {
	list, err := r.store.ListThreads(ctx, targetID)
	if err != nil {
		return nil, err
	}
	liveID, _, ok := r.liveThread(targetID)
	hunter := r.HunterHolds(targetID)
	for i := range list {
		if ok && list[i].ID == liveID {
			list[i].Live = true
		}
		list[i].HunterActive = hunter
		if list[i].Status == statusRunning && !list[i].Live {
			r.store.ReclaimThread(ctx, list[i].ID, "interrupted (no live worker)")
			list[i].Status = statusIdle
		}
	}
	return list, nil
}

func (r *Runtime) NewThread(ctx context.Context, targetID string, userID int64, title string) (*Thread, error) {
	if err := r.Ready(); err != nil {
		return nil, err
	}
	return r.store.CreateThread(ctx, targetID, userID, modeChat, title)
}

func (r *Runtime) RenameThread(ctx context.Context, targetID, threadID, title string) error {
	th, err := r.store.GetThreadByID(ctx, threadID)
	if err != nil {
		return err
	}
	if th == nil || th.TargetID != targetID || th.Mode == modeAlwaysOn {
		return fmt.Errorf("thread not found")
	}
	r.store.SetThreadTitle(ctx, threadID, title)
	return nil
}

func (r *Runtime) DeleteThread(ctx context.Context, targetID, threadID string) error {
	if r.liveFor(targetID, threadID) {
		return fmt.Errorf("cannot delete a running chat — cancel it first")
	}
	return r.store.DeleteThread(ctx, targetID, threadID)
}

func (r *Runtime) liveThread(targetID string) (id, mode string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lr, ok := r.active[targetID]
	return lr.threadID, lr.mode, ok
}

// HunterHolds reports whether the 24/7 hunter currently occupies this target.
func (r *Runtime) HunterHolds(targetID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	lr, ok := r.active[targetID]
	return ok && lr.mode == modeAlwaysOn
}

func (r *Runtime) liveFor(targetID, threadID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	lr, ok := r.active[targetID]
	return ok && lr.threadID == threadID
}

func (r *Runtime) start(parent context.Context, targetID string, userID int64, mode, userContent, threadID string) (*StartResult, error) {
	if err := r.Ready(); err != nil {
		return nil, err
	}
	if r.client == nil {
		return nil, fmt.Errorf("AI client is not configured")
	}
	userContent = clip(userContent, 8000)
	if userContent == "" {
		return nil, fmt.Errorf("message is required")
	}

	ctx, cancel, err := r.acquireSlot(parent, targetID, mode)
	if err != nil {
		return nil, err
	}
	if mode != modeAlwaysOn {
		r.setRunEnv(targetID, CallEnv{Mode: mode})
	}

	th, err := r.resolveThread(ctx, targetID, userID, mode, threadID)
	if err != nil {
		r.release(targetID)
		cancel()
		return nil, err
	}
	r.mu.Lock()
	if lr, ok := r.active[targetID]; ok {
		lr.threadID = th.ID
		lr.mode = mode
		r.active[targetID] = lr
	}
	r.mu.Unlock()
	if _, err := r.store.Append(ctx, th.ID, roleUser, userContent, "", ""); err != nil {
		r.release(targetID)
		cancel()
		return nil, err
	}
	if th.Title == "" {
		r.store.SetThreadTitle(ctx, th.ID, userContent)
	}
	run, err := r.store.StartRun(ctx, th.ID, targetID)
	if err != nil {
		r.release(targetID)
		cancel()
		return nil, err
	}

	go func() {
		defer r.release(targetID)
		defer cancel()
		err := r.loop(ctx, targetID, th.ID, run.ID, mode)
		status, msg := statusFinished, ""
		if ctx.Err() != nil {
			status, msg = statusCancelled, "cancelled"
		} else if err != nil {
			status, msg = statusError, err.Error()
			if mode == modeAlwaysOn && retryableInference(err) {
				r.noteHunterBackoff(hunterInferenceBackoff)
			}
			r.emit(Event{TargetID: targetID, ThreadID: th.ID, RunID: run.ID, Kind: "error", Payload: map[string]string{"error": msg}})
		}
		r.store.FinishRun(context.Background(), run.ID, th.ID, status, msg)
		r.emit(Event{TargetID: targetID, ThreadID: th.ID, RunID: run.ID, Kind: "done", Payload: map[string]string{"status": status, "error": msg}})
	}()

	return &StartResult{ThreadID: th.ID, RunID: run.ID, Mode: mode}, nil
}

func (r *Runtime) resolveThread(ctx context.Context, targetID string, userID int64, mode, threadID string) (*Thread, error) {
	if mode == modeAlwaysOn {
		return r.store.EnsureThread(ctx, targetID, userID, modeAlwaysOn)
	}
	if threadID != "" {
		th, err := r.store.GetThreadByID(ctx, threadID)
		if err != nil {
			return nil, err
		}
		if th == nil || th.TargetID != targetID || th.Mode == modeAlwaysOn {
			return nil, fmt.Errorf("thread not found")
		}
		return th, nil
	}
	th, err := r.store.GetThread(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if th != nil {
		return th, nil
	}
	return r.store.CreateThread(ctx, targetID, userID, mode, "")
}

// acquireSlot takes the per-target occupancy. Operator chat/hunt preempts a
// live 24/7 hunter on the same target (cancel, wait ≤5s). The hunter never
// preempts the operator — that was the "ai agent already running" 409.
func (r *Runtime) acquireSlot(parent context.Context, targetID, mode string) (context.Context, context.CancelFunc, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
		r.mu.Lock()
		lr, busy := r.active[targetID]
		if !busy {
			r.active[targetID] = liveRun{cancel: cancel, mode: mode}
			r.mu.Unlock()
			return ctx, cancel, nil
		}
		preempt := (mode == modeChat || mode == modeHunt) && lr.mode == modeAlwaysOn
		yield := lr.cancel
		held := lr.mode
		r.mu.Unlock()
		cancel()
		if !preempt {
			return nil, nil, errBusy{mode: held}
		}
		if yield != nil {
			yield()
		}
		if time.Now().After(deadline) {
			return nil, nil, errBusy{mode: modeAlwaysOn}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type errBusy struct{ mode string }

func (e errBusy) Error() string {
	switch e.mode {
	case modeHunt:
		return "a hunt is already running on this target — cancel it first"
	case modeChat:
		return "copilot is already answering — wait or cancel"
	case modeAlwaysOn:
		return "the 24/7 hunter is still yielding this target — retry in a moment"
	default:
		return "an agent run is already in progress for this target"
	}
}

func IsBusy(err error) bool {
	_, ok := err.(errBusy)
	return ok
}

func (r *Runtime) release(targetID string) {
	r.mu.Lock()
	delete(r.active, targetID)
	delete(r.runEnv, targetID)
	r.mu.Unlock()
}

func (r *Runtime) setRunEnv(targetID string, env CallEnv) {
	r.mu.Lock()
	if r.runEnv == nil {
		r.runEnv = map[string]CallEnv{}
	}
	r.runEnv[targetID] = env
	r.mu.Unlock()
}

func (r *Runtime) getRunEnv(targetID string) CallEnv {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runEnv[targetID]
}

func (r *Runtime) loop(ctx context.Context, targetID, threadID, runID, mode string) error {
	maxIt := 40
	model := "GLM-5.3-Flash"
	if r.cfg != nil {
		r.cfg.NormalizeAI()
		maxIt = r.cfg.AIMaxIterations
		model = r.cfg.AIModel
	}
	includeStop := mode == modeHunt || mode == modeAlwaysOn
	includeExec := mode != modeAlwaysOn && (r.cfg == nil || r.cfg.AIExecEnabled)
	defs := toolDefsFor(includeStop, includeExec)
	system := copilotSystemPrompt
	switch mode {
	case modeHunt:
		system = huntSystemPrompt
	case modeAlwaysOn:
		system = alwaysOnSystemPrompt
		if r.cfg != nil && r.cfg.AIHunterIterations > 0 {
			maxIt = r.cfg.AIHunterIterations
		}
	}

	for i := 0; i < maxIt; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.store.BumpIterations(ctx, runID, i+1)

		if mode != modeAlwaysOn {
			r.maybeCompact(ctx, threadID)
		}
		msgs, err := r.store.ListMessages(ctx, threadID)
		if err != nil {
			return err
		}
		summary := ""
		var compactAfter time.Time
		if th, _ := r.store.GetThreadByID(ctx, threadID); th != nil {
			summary = th.CompactSummary
			compactAfter = th.CompactAfter
		}
		if mode == modeAlwaysOn {
			msgs = sinceLastUser(msgs)
		} else {
			msgs = afterCompact(msgs, compactAfter)
		}
		var input []InputItem
		if mode == modeAlwaysOn {
			input = buildInput(system, msgs)
		} else {
			input = withCompactMemory(system, summary, msgs)
		}
		resp, err := r.client.Complete(ctx, CompletionRequest{Model: model, Input: input, Tools: defs})
		if err != nil {
			return err
		}
		if resp != nil && (resp.Usage.Prompt > 0 || resp.Usage.Completion > 0) {
			r.store.SaveUsage(ctx, threadID, resp.Usage.Prompt, resp.Usage.Completion)
			ctxTok := contextTokens(system, summary, msgs)
			r.emit(Event{
				TargetID: targetID, ThreadID: threadID, RunID: runID, Kind: "usage",
				Payload: map[string]any{
					"prompt": resp.Usage.Prompt, "completion": resp.Usage.Completion,
					"context": ctxTok, "token_budget": tokenBudget,
				},
			})
		}

		if len(resp.Calls) == 0 {
			text := resp.Text
			if text == "" {
				text = "Done."
			}
			if _, err := r.store.Append(ctx, threadID, roleAssistant, text, "", ""); err != nil {
				return err
			}
			r.emit(Event{TargetID: targetID, ThreadID: threadID, RunID: runID, Kind: "message", Payload: map[string]string{"content": text}})
			return nil
		}

		startedScan := false
		for _, call := range resp.Calls {
			if _, err := r.store.Append(ctx, threadID, roleCall, call.Arguments, call.Name, call.CallID); err != nil {
				return err
			}
			r.emit(Event{
				TargetID: targetID, ThreadID: threadID, RunID: runID, Kind: "tool_call",
				Payload: map[string]string{"name": call.Name, "arguments": clip(call.Arguments, 500), "call_id": call.CallID},
			})
			result := r.tools.Dispatch(ctx, targetID, call.Name, call.Arguments, r.getRunEnv(targetID))
			if _, err := r.store.Append(ctx, threadID, roleTool, result.JSON, call.Name, call.CallID); err != nil {
				return err
			}
			r.emit(Event{
				TargetID: targetID, ThreadID: threadID, RunID: runID, Kind: "tool_result",
				Payload: map[string]string{"name": call.Name, "call_id": call.CallID, "result": clip(result.JSON, 1500)},
			})
			if call.Name == "start_scan" {
				startedScan = true
			}
			if result.StopHunt {
				summary := result.StopMsg
				if summary == "" {
					summary = "Hunt stopped."
				}
				if _, err := r.store.Append(ctx, threadID, roleAssistant, summary, "", ""); err != nil {
					return err
				}
				r.emit(Event{TargetID: targetID, ThreadID: threadID, RunID: runID, Kind: "message", Payload: map[string]string{"content": summary}})
				return nil
			}
		}
		if includeStop && startedScan {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(huntScanWait):
			}
		}
	}
	capMsg := fmt.Sprintf("Stopped at the iteration cap (%d). Review the trace and continue from the copilot if needed.", maxIt)
	_, _ = r.store.Append(ctx, threadID, roleAssistant, capMsg, "", "")
	r.emit(Event{TargetID: targetID, ThreadID: threadID, RunID: runID, Kind: "message", Payload: map[string]string{"content": capMsg}})
	return nil
}

func buildInput(system string, msgs []Message) []InputItem {
	items := []InputItem{{Role: "system", Content: system}}
	// Drop oldest tool results first when the serialized transcript is too large.
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

func sinceLastUser(msgs []Message) []Message {
	last := -1
	for i, m := range msgs {
		if m.Role == roleUser {
			last = i
		}
	}
	if last < 0 {
		return msgs
	}
	return msgs[last:]
}

func trimTranscript(msgs []Message, budget int) []Message {
	if budget <= 0 || len(msgs) == 0 {
		return msgs
	}
	size := 0
	for _, m := range msgs {
		size += len(m.Content) + len(m.ToolName) + 8
	}
	if size <= budget {
		return msgs
	}
	out := append([]Message(nil), msgs...)
	for size > budget {
		idx := -1
		for i, m := range out {
			if m.Role == roleTool && len(m.Content) > 200 {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		old := len(out[idx].Content)
		out[idx].Content = `{"truncated":true}`
		size -= old - len(out[idx].Content)
	}
	// If still over, drop the oldest non-user prefix after the first user message.
	for size > budget && len(out) > 4 {
		out = append(out[:1], out[2:]...)
		size = 0
		for _, m := range out {
			size += len(m.Content)
		}
	}
	return out
}

func (r *Runtime) emit(ev Event) {
	if r.hub == nil {
		return
	}
	r.hub.Broadcast("agent_event", ev)
}
