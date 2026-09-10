package agent

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	execOutputCap    = 32000
	execCommandCap   = 8000
	execDefaultTO    = 45 * time.Second
	execWorkspaceDir = "/tmp/agent-workspace"
)

var (
	execURLRe   = regexp.MustCompile(`(?i)https?://[^\s"'\\<>]+`)
	execIPv4Re  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	execHostRe  = regexp.MustCompile(`(?i)(?:^|[\s'"=/,])((?:[a-z0-9-]+\.)+[a-z]{2,24})(?::\d{2,5})?`)
	execFileExt = map[string]bool{
		"json": true, "txt": true, "xml": true, "yaml": true, "yml": true,
		"md": true, "log": true, "conf": true, "cfg": true, "html": true,
		"htm": true, "js": true, "ts": true, "go": true, "py": true, "sh": true,
		"zip": true, "gz": true, "tgz": true, "csv": true, "svg": true, "png": true,
		"jpg": true, "css": true, "map": true, "lock": true, "sum": true, "mod": true,
	}
	execCodeHosts = map[string]bool{
		"github.com": true, "gitlab.com": true, "bitbucket.org": true,
		"gopkg.in": true, "golang.org": true, "proxy.golang.org": true,
	}
)

func (t *Toolbox) execCommand(ctx context.Context, targetID, command, cwd string) (any, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, fmt.Errorf("command is required")
	}
	if len(command) > execCommandCap {
		return nil, fmt.Errorf("command too long (%d, max %d)", len(command), execCommandCap)
	}
	if err := t.execScopeCheck(ctx, targetID, command); err != nil {
		return nil, err
	}

	dir := execWorkspaceDir
	if cwd = strings.TrimSpace(cwd); cwd != "" {
		abs, err := filepath.Abs(cwd)
		if err != nil {
			return nil, fmt.Errorf("invalid cwd")
		}
		if abs == "/data" || strings.HasPrefix(abs, "/data/") {
			return nil, fmt.Errorf("cwd /data is not allowed")
		}
		dir = abs
	}
	if err := os.MkdirAll(execWorkspaceDir, 0700); err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}

	timeout := execDefaultTO
	if t.cfg != nil {
		t.cfg.NormalizeAI()
		if t.cfg.AIExecTimeoutSeconds > 0 {
			timeout = time.Duration(t.cfg.AIExecTimeoutSeconds) * time.Second
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.Command("/bin/bash", "-lc", command)
	cmd.Dir = dir
	cmd.Env = execEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	started := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
	timedOut := false
	select {
	case waitErr = <-done:
	case <-runCtx.Done():
		timedOut = true
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		waitErr = <-done
	}

	out := redactSecrets(stdout.String() + stderr.String())
	truncated := false
	if len(out) > execOutputCap {
		out = out[:execOutputCap] + "\n…truncated"
		truncated = true
	}
	exit := 0
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else if timedOut {
			exit = -1
		} else {
			exit = -1
		}
	}
	res := map[string]any{
		"exit":        exit,
		"output":      out,
		"cwd":         dir,
		"duration_ms": time.Since(started).Milliseconds(),
		"truncated":   truncated,
	}
	if timedOut {
		res["timeout"] = true
		res["error"] = fmt.Sprintf("timed out after %s", timeout)
	}
	return res, nil
}

func (t *Toolbox) execScopeCheck(ctx context.Context, targetID, command string) error {
	for _, host := range hostsInCommand(command) {
		if isMetadataHost(host) {
			return fmt.Errorf("cloud metadata endpoints are blocked")
		}
		if err := t.ensureInEngagement(ctx, targetID, "https://"+host+"/"); err != nil {
			return fmt.Errorf("exec host %s: %w", host, err)
		}
	}
	return nil
}

func hostsInCommand(command string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(host string) {
		host = strings.ToLower(strings.TrimSpace(host))
		host = strings.TrimSuffix(host, ".")
		if host == "" || seen[host] {
			return
		}
		if skipExecHost(host) {
			return
		}
		seen[host] = true
		out = append(out, host)
	}
	for _, raw := range execURLRe.FindAllString(command, -1) {
		raw = strings.TrimRight(raw, ".,;)]}\"")
		if u, err := parseLooseURL(raw); err == nil && u != "" {
			add(u)
		}
	}
	for _, ip := range execIPv4Re.FindAllString(command, -1) {
		if net.ParseIP(ip) != nil {
			add(ip)
		}
	}
	for _, m := range execHostRe.FindAllStringSubmatchIndex(command, -1) {
		if len(m) < 4 {
			continue
		}
		host := command[m[2]:m[3]]
		// go modules: github.com/org/repo — not a network target
		if m[3] < len(command) && command[m[3]] == '/' && execCodeHosts[strings.ToLower(host)] {
			continue
		}
		add(host)
	}
	return out
}

func parseLooseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i > 0 {
		rest := raw[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		if h, _, err := net.SplitHostPort(rest); err == nil {
			return h, nil
		}
		return rest, nil
	}
	return "", fmt.Errorf("not a url")
}

func skipExecHost(host string) bool {
	if i := strings.LastIndexByte(host, '.'); i > 0 {
		if execFileExt[host[i+1:]] {
			return true
		}
	}
	return false
}

func execEnv() []string {
	secrets := map[string]string{}
	var out []string
	for _, e := range os.Environ() {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		if secretEnvName(k) {
			if v != "" {
				secrets[v] = k
			}
			continue
		}
		out = append(out, e)
	}
	_ = secrets
	out = append(out,
		"HOME="+execWorkspaceDir,
		"TMPDIR="+execWorkspaceDir,
		"PYTHONDONTWRITEBYTECODE=1",
	)
	return out
}

func secretEnvName(k string) bool {
	k = strings.ToUpper(strings.TrimSpace(k))
	switch k {
	case "AI_API_KEY", "LITELLM_API_KEY", "XAI_API_KEY", "ADMIN_PASSWORD", "ADMIN_USER",
		"RECON_SESSION_SECRET", "SESSION_SECRET", "CSRF_SECRET":
		return true
	}
	for _, n := range []string{"PASSWORD", "SECRET", "TOKEN", "API_KEY", "APIKEY"} {
		if strings.Contains(k, n) {
			return true
		}
	}
	return false
}

func redactSecrets(s string) string {
	if s == "" {
		return s
	}
	for _, e := range os.Environ() {
		k, v, ok := strings.Cut(e, "=")
		if !ok || v == "" || len(v) < 6 || !secretEnvName(k) {
			continue
		}
		if strings.Contains(s, v) {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	return s
}
