package agent

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/models"
)

const (
	suppressDeadEnd = 7 * 24 * time.Hour
	suppressWAF     = 30 * time.Minute
	hunterMaxPerMin = 20
	hunterScanCap   = 2
)

func (t *Toolbox) deadEndDur() time.Duration {
	if t != nil && t.cfg != nil && t.cfg.AIHunterDeadEndHours > 0 {
		return time.Duration(t.cfg.AIHunterDeadEndHours) * time.Hour
	}
	return suppressDeadEnd
}

func (t *Toolbox) wafDur() time.Duration {
	if t != nil && t.cfg != nil && t.cfg.AIHunterWAFMinutes > 0 {
		return time.Duration(t.cfg.AIHunterWAFMinutes) * time.Minute
	}
	return suppressWAF
}

func (t *Toolbox) bodyCap() int {
	if t != nil && t.cfg != nil && t.cfg.AIHTTPBodyCap > 0 {
		return t.cfg.AIHTTPBodyCap
	}
	return httpBodyCap
}

// CallEnv is per-run tool policy. Copilot is unrestricted (within scope);
// always-on hunter is gated.
type CallEnv struct {
	Mode      string
	Playbook  string
	ScanAllow []string
	WarRoom   string
}

type hostWin struct {
	window time.Time
	n      int
	until  time.Time
}

func (t *Toolbox) limiter() *hostLimiter {
	if t.limit != nil {
		return t.limit
	}
	t.limitOnce.Do(func() {
		t.limit = &hostLimiter{per: map[string]*hostWin{}, max: hunterMaxPerMin}
	})
	if t.cfg != nil && t.cfg.AIHunterHTTPPerMin > 0 {
		t.limit.max = t.cfg.AIHunterHTTPPerMin
	}
	return t.limit
}

type hostLimiter struct {
	mu  sync.Mutex
	per map[string]*hostWin
	max int
}

func (l *hostLimiter) allow(host string) error {
	if l == nil || host == "" {
		return nil
	}
	if l.max <= 0 {
		l.max = hunterMaxPerMin
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.per[host]
	if st == nil {
		st = &hostWin{}
		l.per[host] = st
	}
	if !st.until.IsZero() && now.Before(st.until) {
		return fmt.Errorf("host %s is in WAF/rate backoff until %s", host, st.until.UTC().Format(time.RFC3339))
	}
	if st.window.IsZero() || now.Sub(st.window) >= time.Minute {
		st.window = now
		st.n = 0
	}
	if st.n >= l.max {
		return fmt.Errorf("host %s hit the hunter budget (%d req/min)", host, l.max)
	}
	st.n++
	return nil
}

func (l *hostLimiter) backoff(host string, d time.Duration) {
	if l == nil || host == "" {
		return
	}
	l.mu.Lock()
	st := l.per[host]
	if st == nil {
		st = &hostWin{}
		l.per[host] = st
	}
	st.until = time.Now().Add(d)
	l.mu.Unlock()
}

func (t *Toolbox) gateHunterScan(ctx context.Context, targetID string, modules []string, env CallEnv) ([]string, error) {
	if env.Mode != modeAlwaysOn {
		return modules, nil
	}
	allow := map[string]bool{}
	for _, m := range env.ScanAllow {
		allow[strings.ToLower(strings.TrimSpace(m))] = true
	}
	if len(allow) == 0 {
		return nil, fmt.Errorf("hunter playbook %s does not enqueue scans — probe with http_request/diff_identities and flag_lead", env.Playbook)
	}
	done := t.completedSet(ctx, targetID)
	var out, rejected []string
	for _, m := range modules {
		if !allow[m] {
			rejected = append(rejected, m+" (not in playbook "+env.Playbook+")")
			continue
		}
		if done[m] && m != "verify" {
			rejected = append(rejected, m+" (already completed)")
			continue
		}
		out = append(out, m)
		capN := hunterScanCap
		if t.cfg != nil && t.cfg.AIHunterScanCap > 0 {
			capN = t.cfg.AIHunterScanCap
		}
		if len(out) >= capN {
			break
		}
	}
	if len(out) == 0 {
		if len(rejected) == 0 {
			return nil, fmt.Errorf("start_scan blocked for hunter playbook %s", env.Playbook)
		}
		return nil, fmt.Errorf("start_scan blocked: %s", strings.Join(rejected, "; "))
	}
	return out, nil
}

func (t *Toolbox) completedSet(ctx context.Context, targetID string) map[string]bool {
	out := map[string]bool{}
	rows, err := t.db.QueryContext(ctx, `
		SELECT COALESCE(completed_modules,'[]') FROM tasks WHERE target_id=? ORDER BY created_at DESC LIMIT 8`, targetID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		for _, m := range models.JSONToStringSlice(raw) {
			out[m] = true
		}
	}
	return out
}

func (t *Toolbox) isSuppressed(ctx context.Context, targetID, rawURL, param string) (string, bool) {
	if t.db == nil || rawURL == "" {
		return "", false
	}
	host := hostOf(rawURL)
	var kind, until string
	err := t.db.QueryRowContext(ctx, `
		SELECT kind, until FROM agent_hunter_suppress
		WHERE target_id=? AND until > CURRENT_TIMESTAMP
		  AND (
		    (url=? AND parameter=?)
		    OR (parameter='' AND (url=? OR url=?))
		  )
		ORDER BY until DESC LIMIT 1`,
		targetID, rawURL, param, rawURL, host).Scan(&kind, &until)
	if err != nil {
		return "", false
	}
	return kind + " until " + until, true
}

func (t *Toolbox) suppress(ctx context.Context, targetID, rawURL, param, kind string, d time.Duration) {
	if t.db == nil || rawURL == "" {
		return
	}
	until := time.Now().Add(d).UTC().Format("2006-01-02 15:04:05")
	_, _ = t.db.ExecContext(ctx, `
		INSERT INTO agent_hunter_suppress (id, target_id, url, parameter, kind, until)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(target_id, url, parameter, kind) DO UPDATE SET until=excluded.until`,
		uuid.New().String(), targetID, clip(rawURL, 500), param, kind, until)
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return strings.ToLower(u.Hostname())
}
