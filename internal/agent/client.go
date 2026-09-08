package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://litellm.合.xyz/v1"
	defaultModel   = "GLM-5.3-Flash"
	defaultTimeout = 180 * time.Second
	maxErrorBody   = 800
	defaultMaxTok  = 8192
)

// Completer is the inference call used by the agent loop. Tests stub it.
type Completer interface {
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
}

// ToolDef is one function tool. Wire format is converted for chat/completions.
type ToolDef struct {
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// InputItem is one conversation entry (message or function call I/O).
type InputItem struct {
	Type      string `json:"type,omitempty"`
	Role      string `json:"role,omitempty"`
	Content   any    `json:"content,omitempty"`
	CallID    string `json:"call_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
	Output    string `json:"output,omitempty"`
}

// FunctionCall is a model-requested tool invocation.
type FunctionCall struct {
	CallID    string
	Name      string
	Arguments string
}

// CompletionRequest is sent to the OpenAI-compatible chat/completions endpoint.
type CompletionRequest struct {
	Model string
	Input []InputItem
	Tools []ToolDef
}

// Usage is prompt/completion tokens reported by the inference proxy.
type Usage struct {
	Prompt     int
	Completion int
	Total      int
}

// CompletionResponse is the subset of the chat completion we consume.
type CompletionResponse struct {
	ID      string
	Text    string
	Calls   []FunctionCall
	Usage   Usage
	RawJSON json.RawMessage
}

type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
}

type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function chatFn `json:"function"`
}

type chatFn struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type chatTool struct {
	Type     string     `json:"type"`
	Function chatToolFn `json:"function"`
}

type chatToolFn struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type chatRequest struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	Tools     []chatTool    `json:"tools,omitempty"`
	MaxTokens int           `json:"max_tokens,omitempty"`
}

type chatAPI struct {
	ID      string `json:"id"`
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Role      string          `json:"role"`
			Content   json.RawMessage `json:"content"`
			ToolCalls []struct {
				ID       json.RawMessage `json:"id"`
				Type     string          `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	Error *apiError `json:"error"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

type apiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// Client talks to an OpenAI-compatible proxy (LiteLLM) over net/http.
type Client struct {
	BaseURL    func() string
	APIKey     func() string
	Model      func() string
	Timeout    func() time.Duration
	MaxTokens  func() int
	HTTPClient *http.Client
}

func NewClient(apiKey, model, baseURL func() string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Model:   model,
		HTTPClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

func (c *Client) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("inference client not configured")
	}
	key := ""
	if c.APIKey != nil {
		key = strings.TrimSpace(c.APIKey())
	}
	if key == "" {
		return nil, fmt.Errorf("AI_API_KEY is not set")
	}
	model := req.Model
	if model == "" && c.Model != nil {
		model = c.Model()
	}
	if model == "" {
		model = defaultModel
	}
	base := defaultBaseURL
	if c.BaseURL != nil {
		if v := strings.TrimRight(strings.TrimSpace(c.BaseURL()), "/"); v != "" {
			base = v
		}
	}
	maxTok := defaultMaxTok
	if c.MaxTokens != nil {
		if n := c.MaxTokens(); n > 0 {
			maxTok = n
		}
	}
	body := chatRequest{
		Model:     model,
		Messages:  toChatMessages(req.Input),
		Tools:     toChatTools(req.Tools),
		MaxTokens: maxTok,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode inference request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+key)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	httpClient := c.HTTPClient
	timeout := defaultTimeout
	if c.Timeout != nil {
		if d := c.Timeout(); d > 0 {
			timeout = d
		}
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	} else if httpClient.Timeout != timeout {
		cp := *httpClient
		cp.Timeout = timeout
		httpClient = &cp
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("inference request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read inference response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("inference HTTP %d: %s", resp.StatusCode, clip(string(respBody), maxErrorBody))
	}
	var parsed chatAPI
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("decode inference response: %w", err)
	}
	if parsed.Error != nil && parsed.Error.Message != "" {
		return nil, fmt.Errorf("inference: %s", parsed.Error.Message)
	}
	out := &CompletionResponse{ID: parsed.ID, RawJSON: respBody}
	if parsed.Usage != nil {
		out.Usage = Usage{
			Prompt:     parsed.Usage.PromptTokens,
			Completion: parsed.Usage.CompletionTokens,
			Total:      parsed.Usage.TotalTokens,
		}
		if out.Usage.Total == 0 {
			out.Usage.Total = out.Usage.Prompt + out.Usage.Completion
		}
	}
	if len(parsed.Choices) == 0 {
		return out, nil
	}
	msg := parsed.Choices[0].Message
	out.Text = extractOutputText(msg.Content)
	for _, tc := range msg.ToolCalls {
		out.Calls = append(out.Calls, FunctionCall{
			CallID:    jsonString(tc.ID),
			Name:      tc.Function.Name,
			Arguments: tc.Function.Arguments,
		})
	}
	return out, nil
}

func toChatTools(defs []ToolDef) []chatTool {
	if len(defs) == 0 {
		return nil
	}
	out := make([]chatTool, 0, len(defs))
	for _, d := range defs {
		params := d.Parameters
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, chatTool{
			Type: "function",
			Function: chatToolFn{
				Name:        d.Name,
				Description: d.Description,
				Parameters:  params,
			},
		})
	}
	return out
}

func toChatMessages(items []InputItem) []chatMessage {
	out := []chatMessage{}
	var pending []chatToolCall
	flush := func() {
		if len(pending) == 0 {
			return
		}
		out = append(out, chatMessage{Role: "assistant", ToolCalls: pending})
		pending = nil
	}
	for _, it := range items {
		switch {
		case it.Type == "function_call" || (it.CallID != "" && it.Name != "" && it.Type != "function_call_output" && it.Output == ""):
			pending = append(pending, chatToolCall{
				ID:   it.CallID,
				Type: "function",
				Function: chatFn{
					Name:      it.Name,
					Arguments: it.Arguments,
				},
			})
		case it.Type == "function_call_output" || (it.CallID != "" && it.Output != ""):
			flush()
			out = append(out, chatMessage{Role: "tool", ToolCallID: it.CallID, Content: it.Output})
		default:
			flush()
			role := it.Role
			if role == "" {
				role = "user"
			}
			out = append(out, chatMessage{Role: role, Content: stringifyContent(it.Content)})
		}
	}
	flush()
	return out
}

func stringifyContent(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
}

func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.Trim(string(raw), `"`)
}

func extractOutputText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var b strings.Builder
		for _, p := range parts {
			if p.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(p.Text)
		}
		return b.String()
	}
	return ""
}

func clip(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
