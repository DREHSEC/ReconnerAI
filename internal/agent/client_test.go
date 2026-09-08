package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientCompleteParsesFunctionCallAndText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path=%s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("auth=%q", got)
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatal(err)
		}
		if req["model"] != "GLM-5.3-Flash" {
			t.Errorf("model=%v", req["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{
			"id":"resp_1",
			"choices":[{
				"finish_reason":"tool_calls",
				"message":{
					"role":"assistant",
					"content":"",
					"tool_calls":[{"id":"c1","type":"function","function":{"name":"target_brief","arguments":"{}"}}]
				}
			}]
		}`)
	}))
	defer srv.Close()

	c := NewClient(func() string { return "test-key" }, func() string { return "GLM-5.3-Flash" }, func() string { return srv.URL })
	c.HTTPClient = srv.Client()

	resp, err := c.Complete(context.Background(), CompletionRequest{
		Model: "GLM-5.3-Flash",
		Input: []InputItem{{Role: "user", Content: "hi"}},
		Tools: toolDefs(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Calls) != 1 || resp.Calls[0].Name != "target_brief" {
		t.Fatalf("calls=%v", resp.Calls)
	}
}

func TestClientCompleteParsesAssistantText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"hello"}}]}`)
	}))
	defer srv.Close()
	c := NewClient(func() string { return "x" }, func() string { return "GLM-5.3-Flash" }, func() string { return srv.URL })
	c.HTTPClient = srv.Client()
	resp, err := c.Complete(context.Background(), CompletionRequest{Input: []InputItem{{Role: "user", Content: "hi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "hello" {
		t.Fatalf("text=%q", resp.Text)
	}
}

func TestClientCompleteHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"bad key"}}`)
	}))
	defer srv.Close()
	c := NewClient(func() string { return "x" }, func() string { return "GLM-5.3-Flash" }, func() string { return srv.URL })
	c.HTTPClient = srv.Client()
	_, err := c.Complete(context.Background(), CompletionRequest{Input: []InputItem{{Role: "user", Content: "hi"}}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestToChatMessagesGroupsToolCalls(t *testing.T) {
	msgs := toChatMessages([]InputItem{
		{Role: "user", Content: "hi"},
		{Type: "function_call", CallID: "c1", Name: "target_brief", Arguments: "{}"},
		{Type: "function_call_output", CallID: "c1", Output: `{"ok":true}`},
	})
	if len(msgs) != 3 || msgs[1].Role != "assistant" || len(msgs[1].ToolCalls) != 1 {
		t.Fatalf("%+v", msgs)
	}
	if msgs[2].Role != "tool" || msgs[2].ToolCallID != "c1" {
		t.Fatalf("tool msg %+v", msgs[2])
	}
}

func TestExtractOutputTextString(t *testing.T) {
	if got := extractOutputText([]byte(`"plain"`)); got != "plain" {
		t.Fatalf("got %q", got)
	}
}
