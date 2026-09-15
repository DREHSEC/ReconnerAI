package scanner

// Guided adapters are deliberately context-local: no captured credentials or
// plaintext parameters are materialized into the project's discovery tables.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/recon-platform/internal/capture"
)

type guidedContextKey struct{}
type guidedPoint struct {
	ip         insertionPoint
	path       []string
	occurrence int
}
type guidedWire struct {
	Request capture.Request `json:"request"`
	Status  int             `json:"status"`
}
type guidedContext struct {
	request               capture.Request
	points                []guidedPoint
	mu                    sync.Mutex
	sent, failed, blocked int
	trace                 []guidedWire
	transport             http.RoundTripper // only tests inject this; never accepted by the API
}

func guidedFrom(ctx context.Context) *guidedContext {
	g, _ := ctx.Value(guidedContextKey{}).(*guidedContext)
	return g
}

func guidedPoints(r capture.Request) []guidedPoint {
	var out []guidedPoint
	addValues := func(raw, loc string) {
		seen := map[string]int{}
		for _, part := range strings.Split(raw, "&") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			k, e := url.QueryUnescape(kv[0])
			if e != nil || k == "" {
				continue
			}
			v, e := url.QueryUnescape(kv[1])
			if e != nil {
				continue
			}
			n := seen[k]
			seen[k]++
			out = append(out, guidedPoint{ip: insertionPoint{URL: r.URL, Method: r.Method, ContentType: r.MimeType, Location: loc, Param: k, Value: v, guidedOccurrence: n}, occurrence: n})
		}
	}
	u, e := url.Parse(r.URL)
	if e != nil {
		return nil
	}
	addValues(u.RawQuery, "query")
	ct := strings.ToLower(r.MimeType)
	if strings.Contains(ct, "x-www-form-urlencoded") {
		addValues(string(r.Body), "body")
	}
	if strings.Contains(ct, "json") {
		var root any
		dec := json.NewDecoder(bytes.NewReader(r.Body))
		dec.UseNumber()
		if dec.Decode(&root) == nil {
			var walk func(any, []string)
			walk = func(v any, path []string) {
				switch x := v.(type) {
				case map[string]any:
					keys := make([]string, 0, len(x))
					for k := range x {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						walk(x[k], append(append([]string{}, path...), k))
					}
				case []any:
					for i, child := range x {
						walk(child, append(append([]string{}, path...), strconv.Itoa(i)))
					}
				case string, json.Number, bool:
					name := ""
					for _, k := range path {
						name += "/" + strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
					}
					out = append(out, guidedPoint{ip: insertionPoint{URL: r.URL, Method: r.Method, ContentType: r.MimeType, Location: "body", Param: name, Value: fmt.Sprint(v)}, path: path})
				}
			}
			walk(root, nil)
		}
	}
	return out
}

func guidedIDORPoints(r capture.Request) []guidedPoint {
	points := guidedPoints(r)
	out := make([]guidedPoint, 0, len(points))
	for _, point := range points {
		if looksGuidedObjectID(point.ip.Value) {
			out = append(out, point)
		}
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		return out
	}
	parts := strings.Split(u.Path, "/")
	logicalIndex := 0
	for actualIndex, value := range parts {
		if value == "" {
			continue
		}
		if looksGuidedObjectID(value) {
			out = append(out, guidedPoint{
				ip:   insertionPoint{URL: r.URL, Method: r.Method, ContentType: r.MimeType, Location: "path", Param: "path[" + strconv.Itoa(logicalIndex) + "]", Value: value},
				path: []string{strconv.Itoa(actualIndex)},
			})
		}
		logicalIndex++
	}
	return out
}

func replaceGuidedValue(raw, key, value, operator string, occurrence int) string {
	parts := strings.Split(raw, "&")
	n := 0
	for i, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		k, _ := url.QueryUnescape(kv[0])
		if len(kv) != 2 || k != key {
			continue
		}
		if n == occurrence {
			name := kv[0]
			if operator != "" {
				name = url.QueryEscape(key + "[" + operator + "]")
			}
			parts[i] = name + "=" + url.QueryEscape(value)
			break
		}
		n++
	}
	return strings.Join(parts, "&")
}

func (g *guidedContext) injected(ctx context.Context, ip insertionPoint, value, operator string) (*http.Request, error) {
	r := g.request
	var point *guidedPoint
	// Param+location selects one field in THIS immutable template, never siblings
	// from another request sharing its URL. Duplicate names target the first value.
	for i := range g.points {
		p := &g.points[i]
		if p.ip.Param == ip.Param && p.ip.Location == ip.Location && p.occurrence == ip.guidedOccurrence {
			point = p
			break
		}
	}
	if point == nil {
		return nil, fmt.Errorf("insertion point not in captured template")
	}
	if ip.Location == "path" {
		u, _ := url.Parse(r.URL)
		parts := strings.Split(u.Path, "/")
		index, e := strconv.Atoi(point.path[0])
		if e != nil || index < 0 || index >= len(parts) {
			return nil, fmt.Errorf("path insertion point is invalid")
		}
		parts[index] = value
		u.Path = strings.Join(parts, "/")
		u.RawPath = ""
		r.URL = u.String()
	} else if ip.Location == "query" {
		u, _ := url.Parse(r.URL)
		u.RawQuery = replaceGuidedValue(u.RawQuery, ip.Param, value, operator, point.occurrence)
		r.URL = u.String()
	} else if strings.Contains(strings.ToLower(r.MimeType), "json") {
		var root any
		d := json.NewDecoder(bytes.NewReader(r.Body))
		d.UseNumber()
		if e := d.Decode(&root); e != nil {
			return nil, e
		}
		var replacement any = value
		if operator != "" {
			replacement = map[string]any{operator: value}
		}
		var replace func(any, []string) any
		replace = func(v any, p []string) any {
			if len(p) == 0 {
				return replacement
			}
			switch x := v.(type) {
			case map[string]any:
				x[p[0]] = replace(x[p[0]], p[1:])
			case []any:
				i, _ := strconv.Atoi(p[0])
				x[i] = replace(x[i], p[1:])
			}
			return v
		}
		r.Body, _ = json.Marshal(replace(root, point.path))
	} else {
		r.Body = []byte(replaceGuidedValue(string(r.Body), ip.Param, value, operator, point.occurrence))
	}
	return guidedHTTPRequest(ctx, r)
}

func guidedHTTPRequest(ctx context.Context, r capture.Request) (*http.Request, error) {
	req, e := http.NewRequestWithContext(ctx, r.Method, r.URL, bytes.NewReader(r.Body))
	if e != nil {
		return nil, e
	}
	for _, h := range r.Headers {
		if !replayHeaderAllowed(h.Name) {
			continue
		}
		if !validHTTPHeaderName(h.Name) || strings.ContainsAny(h.Value, "\r\n") || len(h.Value) > 16384 {
			return nil, fmt.Errorf("invalid captured header")
		}
		req.Header.Add(h.Name, h.Value)
	}
	if r.MimeType != "" {
		req.Header.Set("Content-Type", r.MimeType)
	}
	return req, nil
}

func (g *guidedContext) roundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(g.request.URL)
	if req.Method != g.request.Method || !strings.EqualFold(req.URL.Scheme, u.Scheme) || !strings.EqualFold(req.URL.Host, u.Host) || !g.guidedPathAllowed(u, req.URL) {
		g.mu.Lock()
		g.blocked++
		g.mu.Unlock()
		return nil, fmt.Errorf("guided request escaped its template")
	}
	g.mu.Lock()
	if g.sent >= 160 {
		g.blocked++
		g.mu.Unlock()
		return nil, fmt.Errorf("guided module request budget exhausted")
	}
	g.sent++
	g.mu.Unlock()
	var body []byte
	if req.GetBody != nil {
		b, e := req.GetBody()
		if e == nil {
			body, _ = io.ReadAll(b)
			b.Close()
		}
	}
	wire := guidedWire{Request: capture.Request{Method: req.Method, URL: req.URL.String(), MimeType: req.Header.Get("Content-Type"), Body: body}}
	for k, vs := range req.Header {
		for _, v := range vs {
			wire.Request.Headers = append(wire.Request.Headers, capture.Header{Name: k, Value: v})
		}
	}
	transport := g.transport
	if transport == nil {
		transport = guardedCredentialTransport
	}
	resp, e := transport.RoundTrip(req)
	g.mu.Lock()
	defer g.mu.Unlock()
	if e != nil {
		g.failed++
	} else {
		wire.Status = resp.StatusCode
		if len(body) <= 256*1024 {
			g.trace = append(g.trace, wire)
			if len(g.trace) > 4 {
				g.trace = g.trace[len(g.trace)-4:]
			}
		}
	}
	return resp, e
}

func (g *guidedContext) guidedPathAllowed(base, candidate *url.URL) bool {
	if candidate.EscapedPath() == base.EscapedPath() {
		return true
	}
	baseParts := strings.Split(base.Path, "/")
	candidateParts := strings.Split(candidate.Path, "/")
	if len(baseParts) != len(candidateParts) {
		return false
	}
	changed := -1
	for i := range baseParts {
		if baseParts[i] == candidateParts[i] {
			continue
		}
		if changed >= 0 {
			return false
		}
		changed = i
	}
	if changed < 0 || !looksGuidedObjectID(candidateParts[changed]) {
		return false
	}
	for _, point := range g.points {
		if point.ip.Location != "path" || len(point.path) != 1 {
			continue
		}
		index, err := strconv.Atoi(point.path[0])
		if err == nil && index == changed {
			return true
		}
	}
	return false
}

var guidedClient = &http.Client{Transport: identityRoundTripper{}, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
