package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

const (
	browserOutputCap = 12000
	browserEvalCap   = 8000
	browserDefaultTO = 45 * time.Second
	browserWorkspace = "/tmp/agent-browser"
)

const snapshotJS = `(() => {
  const sel = 'a, button, input, textarea, select, [role="button"], [onclick], [contenteditable="true"]';
  const els = Array.from(document.querySelectorAll(sel)).slice(0, 80);
  els.forEach((el, i) => el.setAttribute('data-rcn', 'e' + (i + 1)));
  const textOf = (el) => (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.getAttribute('name') || '').trim().slice(0, 120);
  return {
    url: location.href,
    title: document.title || '',
    text: (document.body && document.body.innerText ? document.body.innerText : '').slice(0, 4000),
    elements: els.map((el, i) => ({
      ref: 'e' + (i + 1),
      tag: (el.tagName || '').toLowerCase(),
      type: el.getAttribute('type') || '',
      name: el.getAttribute('name') || '',
      text: textOf(el),
      href: el.href || ''
    }))
  };
})()`

type browserSession struct {
	cmd         *exec.Cmd
	port        int
	allocCancel context.CancelFunc
	ctxCancel   context.CancelFunc
	ctx         context.Context
}

func (t *Toolbox) browserTimeout() time.Duration {
	if t != nil && t.cfg != nil && t.cfg.AIBrowserTimeoutSeconds > 0 {
		return time.Duration(t.cfg.AIBrowserTimeoutSeconds) * time.Second
	}
	return browserDefaultTO
}

func (t *Toolbox) CloseBrowser(targetID string) {
	if t == nil {
		return
	}
	t.browserMu.Lock()
	sess := t.browsers[targetID]
	if t.browsers != nil {
		delete(t.browsers, targetID)
	}
	t.browserMu.Unlock()
	if sess != nil {
		sess.close()
	}
}

func (s *browserSession) close() {
	if s == nil {
		return
	}
	if s.ctxCancel != nil {
		s.ctxCancel()
	}
	if s.allocCancel != nil {
		s.allocCancel()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		_, _ = s.cmd.Process.Wait()
	}
}

func (t *Toolbox) ensureBrowser(parent context.Context, targetID string) (*browserSession, error) {
	t.browserMu.Lock()
	if t.browsers == nil {
		t.browsers = map[string]*browserSession{}
	}
	if sess := t.browsers[targetID]; sess != nil && sess.ctx != nil && sess.ctx.Err() == nil {
		t.browserMu.Unlock()
		return sess, nil
	}
	t.browserMu.Unlock()

	bin, err := exec.LookPath("obscura")
	if err != nil {
		return nil, fmt.Errorf("obscura is not installed — rebuild the image or put the binary on PATH")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("browser listen: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	dir := browserWorkspace + "/" + targetID
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("browser workspace: %w", err)
	}
	cmd := exec.Command(bin, "serve",
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--storage-dir", dir,
		"--allow-private-network",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start obscura: %w", err)
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 8*time.Second)
	wsURL, err := waitObscuraWS(waitCtx, port, 8*time.Second)
	waitCancel()
	if err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return nil, err
	}
	// Session lifetime is independent of a single tool-call timeout. CloseBrowser
	// (or Runtime.release) tears this down.
	allocCtx, allocCancel := chromedp.NewRemoteAllocator(context.Background(), wsURL)
	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	if err := chromedp.Run(tabCtx); err != nil {
		tabCancel()
		allocCancel()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return nil, fmt.Errorf("obscura cdp: %w", err)
	}
	sess := &browserSession{cmd: cmd, port: port, allocCancel: allocCancel, ctxCancel: tabCancel, ctx: tabCtx}
	t.browserMu.Lock()
	if old := t.browsers[targetID]; old != nil {
		old.close()
	}
	t.browsers[targetID] = sess
	t.browserMu.Unlock()
	return sess, nil
}

func waitObscuraWS(ctx context.Context, port int, d time.Duration) (string, error) {
	deadline := time.Now().Add(d)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	fallback := fmt.Sprintf("ws://127.0.0.1:%d/devtools/browser", port)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", port))
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			var v struct {
				WS string `json:"webSocketDebuggerUrl"`
			}
			if json.Unmarshal(body, &v) == nil && strings.TrimSpace(v.WS) != "" {
				return v.WS, nil
			}
			if resp.StatusCode == 200 {
				return fallback, nil
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return "", fmt.Errorf("obscura did not become ready on :%d", port)
}

func (t *Toolbox) browserOpen(ctx context.Context, targetID, rawURL, identityLabel string, env CallEnv) (any, error) {
	if t.cfg != nil && !t.cfg.AIBrowserEnabled {
		return nil, fmt.Errorf("browser is disabled — enable it in System → Integrations")
	}
	rawURL = strings.TrimSpace(rawURL)
	if err := t.ensureInEngagement(ctx, targetID, rawURL); err != nil {
		return nil, err
	}
	if why, ok := t.isSuppressed(ctx, targetID, rawURL, ""); ok {
		return nil, fmt.Errorf("suppressed (%s)", why)
	}
	if env.Mode == modeAlwaysOn {
		if err := t.limiter().allow(hostOf(rawURL)); err != nil {
			return nil, err
		}
	}
	sess, err := t.ensureBrowser(ctx, targetID)
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithTimeout(sess.ctx, t.browserTimeout())
	defer cancel()
	actions := []chromedp.Action{}
	if identityLabel != "" {
		id, err := t.loadIdentity(ctx, targetID, identityLabel)
		if err != nil {
			return nil, err
		}
		if ua := strings.TrimSpace(id.UserAgent); ua != "" {
			actions = append(actions, emulation.SetUserAgentOverride(ua))
		}
		if len(id.Headers) > 0 {
			extra := network.Headers{}
			cookieHdr := ""
			for k, v := range id.Headers {
				if strings.EqualFold(k, "Cookie") {
					cookieHdr = v
					continue
				}
				extra[k] = v
			}
			if len(extra) > 0 {
				actions = append(actions, network.SetExtraHTTPHeaders(extra))
			}
			actions = append(actions, cookiesFromHeader(cookieHdr, rawURL)...)
		}
	}
	actions = append(actions, chromedp.Navigate(rawURL))
	if err := chromedp.Run(runCtx, actions...); err != nil {
		return nil, fmt.Errorf("navigate: %w", err)
	}
	loc := ""
	_ = chromedp.Run(runCtx, chromedp.Location(&loc))
	if loc == "" {
		loc = rawURL
	}
	if err := t.ensureInEngagement(ctx, targetID, loc); err != nil {
		return nil, fmt.Errorf("redirected out of scope: %w", err)
	}
	snap, err := t.browserSnapshot(sess)
	if err != nil {
		return map[string]any{"url": loc, "opened": true}, nil
	}
	return snap, nil
}

func cookiesFromHeader(cookieHeader, rawURL string) []chromedp.Action {
	cookieHeader = strings.TrimSpace(cookieHeader)
	if cookieHeader == "" {
		return nil
	}
	host := hostOf(rawURL)
	var out []chromedp.Action
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name, val = strings.TrimSpace(name), strings.TrimSpace(val)
		if name == "" {
			continue
		}
		out = append(out, network.SetCookie(name, val).WithDomain(host).WithPath("/"))
	}
	return out
}

func (t *Toolbox) browserSnapshot(sess *browserSession) (any, error) {
	if sess == nil || sess.ctx == nil {
		return nil, fmt.Errorf("no open browser — call browser_open first")
	}
	runCtx, cancel := context.WithTimeout(sess.ctx, t.browserTimeout())
	defer cancel()
	var obj map[string]any
	if err := chromedp.Run(runCtx, chromedp.Evaluate(snapshotJS, &obj)); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	return clipBrowser(obj), nil
}

func (t *Toolbox) browserAct(ctx context.Context, targetID, name, ref, selector, value string) (any, error) {
	t.browserMu.Lock()
	sess := t.browsers[targetID]
	t.browserMu.Unlock()
	if sess == nil {
		return nil, fmt.Errorf("no open browser — call browser_open first")
	}
	css := strings.TrimSpace(selector)
	if css == "" {
		ref = strings.TrimPrefix(strings.TrimSpace(ref), "@")
		if ref == "" {
			return nil, fmt.Errorf("ref or selector is required")
		}
		css = `[data-rcn=` + strconv.Quote(ref) + `]`
	}
	runCtx, cancel := context.WithTimeout(sess.ctx, t.browserTimeout())
	defer cancel()
	switch name {
	case "browser_click":
		if err := chromedp.Run(runCtx, chromedp.Click(css, chromedp.ByQuery)); err != nil {
			js := fmt.Sprintf(`(() => { const el = document.querySelector(%s); if (!el) return 'missing'; el.click(); return 'ok'; })()`, strconv.Quote(css))
			var out string
			if err2 := chromedp.Run(runCtx, chromedp.Evaluate(js, &out)); err2 != nil {
				return nil, fmt.Errorf("click: %w", err)
			}
			if out == "missing" {
				return nil, fmt.Errorf("element %s not found — take a fresh snapshot", css)
			}
		}
	case "browser_fill":
		if err := chromedp.Run(runCtx, chromedp.SendKeys(css, value, chromedp.ByQuery)); err != nil {
			js := fmt.Sprintf(`(() => {
			  const el = document.querySelector(%s);
			  if (!el) return 'missing';
			  el.focus();
			  el.value = %s;
			  el.dispatchEvent(new Event('input', {bubbles:true}));
			  el.dispatchEvent(new Event('change', {bubbles:true}));
			  return 'ok';
			})()`, strconv.Quote(css), strconv.Quote(value))
			var out string
			if err2 := chromedp.Run(runCtx, chromedp.Evaluate(js, &out)); err2 != nil {
				return nil, fmt.Errorf("fill: %w", err)
			}
			if out == "missing" {
				return nil, fmt.Errorf("element %s not found — take a fresh snapshot", css)
			}
		}
	default:
		return nil, fmt.Errorf("unknown browser action")
	}
	loc := ""
	_ = chromedp.Run(runCtx, chromedp.Location(&loc))
	if loc != "" {
		if err := t.ensureInEngagement(ctx, targetID, loc); err != nil {
			return nil, fmt.Errorf("navigation left engagement scope: %w", err)
		}
	}
	snap, err := t.browserSnapshot(sess)
	if err != nil {
		return map[string]any{"ok": true, "url": loc}, nil
	}
	return snap, nil
}

func (t *Toolbox) browserEval(ctx context.Context, targetID, expr string) (any, error) {
	t.browserMu.Lock()
	sess := t.browsers[targetID]
	t.browserMu.Unlock()
	if sess == nil {
		return nil, fmt.Errorf("no open browser — call browser_open first")
	}
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("expression is required")
	}
	if len(expr) > 4000 {
		return nil, fmt.Errorf("expression too long")
	}
	runCtx, cancel := context.WithTimeout(sess.ctx, t.browserTimeout())
	defer cancel()
	var out any
	if err := chromedp.Run(runCtx, chromedp.Evaluate(expr, &out)); err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}
	loc := ""
	_ = chromedp.Run(runCtx, chromedp.Location(&loc))
	if loc != "" {
		if err := t.ensureInEngagement(ctx, targetID, loc); err != nil {
			return nil, fmt.Errorf("eval navigated out of scope: %w", err)
		}
	}
	return map[string]any{"result": clipAny(out, browserEvalCap), "url": loc}, nil
}

func (t *Toolbox) browserClose(targetID string) any {
	t.CloseBrowser(targetID)
	return map[string]any{"closed": true}
}

func clipBrowser(obj map[string]any) map[string]any {
	if obj == nil {
		return map[string]any{}
	}
	if s, ok := obj["text"].(string); ok {
		obj["text"] = clip(s, 4000)
	}
	return obj
}

func clipAny(v any, n int) any {
	switch t := v.(type) {
	case string:
		return clip(t, n)
	case []byte:
		return clip(string(t), n)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return clip(fmt.Sprint(t), n)
		}
		return json.RawMessage(clip(string(b), n))
	}
}
