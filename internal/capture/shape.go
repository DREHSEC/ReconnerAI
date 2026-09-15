package capture

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// RequestShapeBytes is a deterministic deduplication representation. It masks
// authentication and rotating anti-CSRF values but deliberately preserves
// ordinary object IDs and business values so traffic from different owned
// objects is not collapsed before authorization analysis.
func RequestShapeBytes(r Request) []byte {
	u, _ := url.Parse(r.URL)
	shapeURL := r.URL
	if u != nil {
		u.Fragment = ""
		q := u.Query()
		for name, values := range q {
			if volatileName(name) {
				for i := range values {
					values[i] = "{volatile}"
				}
				q[name] = values
			}
		}
		u.RawQuery = q.Encode()
		shapeURL = u.String()
	}
	headers := append([]Header(nil), r.Headers...)
	for i := range headers {
		headers[i].Name = http.CanonicalHeaderKey(strings.TrimSpace(headers[i].Name))
		if sensitiveHeader(headers[i].Name) {
			headers[i].Value = "{secret}"
		}
	}
	sort.Slice(headers, func(i, j int) bool {
		if strings.EqualFold(headers[i].Name, headers[j].Name) {
			return headers[i].Value < headers[j].Value
		}
		return strings.ToLower(headers[i].Name) < strings.ToLower(headers[j].Name)
	})
	body := normalizedShapeBody(r.Body, r.MimeType)
	v := struct {
		Method  string   `json:"method"`
		URL     string   `json:"url"`
		Headers []Header `json:"headers"`
		Body    []byte   `json:"body"`
	}{strings.ToUpper(strings.TrimSpace(r.Method)), shapeURL, headers, body}
	b, _ := json.Marshal(v)
	return b
}

func normalizedShapeBody(body []byte, mime string) []byte {
	lowerMime := strings.ToLower(mime)
	if strings.Contains(lowerMime, "json") {
		var value any
		if json.Unmarshal(body, &value) == nil {
			normalizeJSONSecrets(value)
			if b, err := json.Marshal(value); err == nil {
				return b
			}
		}
	}
	if strings.Contains(lowerMime, "application/x-www-form-urlencoded") {
		if form, err := url.ParseQuery(string(body)); err == nil {
			for name, values := range form {
				if volatileName(name) {
					for i := range values {
						values[i] = "{volatile}"
					}
					form[name] = values
				}
			}
			return []byte(form.Encode())
		}
	}
	return body
}

func normalizeJSONSecrets(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if volatileName(key) {
				v[key] = "{volatile}"
				continue
			}
			normalizeJSONSecrets(child)
		}
	case []any:
		for _, child := range v {
			normalizeJSONSecrets(child)
		}
	}
}

func sensitiveHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "cookie" || name == "authorization" || name == "proxy-authorization" ||
		strings.Contains(name, "csrf") || strings.Contains(name, "xsrf") ||
		strings.Contains(name, "token") || strings.Contains(name, "api-key") || strings.Contains(name, "secret")
}

func volatileName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "-", "_")
	return name == "token" || name == "nonce" || name == "timestamp" || name == "ts" ||
		name == "session" || name == "sessionid" || name == "session_id" ||
		strings.Contains(name, "csrf") || strings.Contains(name, "xsrf") ||
		strings.Contains(name, "access_token") || strings.Contains(name, "refresh_token") ||
		strings.Contains(name, "authenticity_token")
}
