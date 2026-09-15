package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const SchemaV1 = "reconner-capture/v1"

type Envelope struct {
	Schema     string     `json:"schema"`
	Source     string     `json:"source"`
	Label      string     `json:"label,omitempty"`
	ExportedAt string     `json:"exported_at,omitempty"`
	Entries    []Exchange `json:"entries"`
}

// ParseReconnerJSON reads the canonical interchange format emitted by the
// Chrome collector. Byte slices use standard JSON base64 encoding.
func ParseReconnerJSON(raw []byte) ([]Exchange, error) {
	if len(raw) > MaxImportBytes {
		return nil, ErrImportTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env Envelope
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("invalid Reconner capture JSON: %w", err)
	}
	// A second JSON value (or any non-whitespace suffix) is never part of the
	// capture envelope. Reject it instead of silently accepting an ambiguous
	// upload whose validated prefix differs from its full contents.
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("invalid Reconner capture JSON: trailing data")
		}
		return nil, fmt.Errorf("invalid Reconner capture JSON: %w", err)
	}
	if env.Schema != SchemaV1 {
		return nil, fmt.Errorf("unsupported capture schema %q", env.Schema)
	}
	if env.Source == "" {
		env.Source = "chrome-devtools"
	}
	if len(env.Entries) == 0 {
		return nil, fmt.Errorf("capture JSON contains no entries")
	}
	if len(env.Entries) > MaxItems {
		return nil, fmt.Errorf("capture contains more than %d items", MaxItems)
	}
	for i := range env.Entries {
		ex := &env.Entries[i]
		if ex.Source == "" {
			ex.Source = env.Source
		}
		if ex.Sequence == 0 {
			ex.Sequence = i + 1
		}
		u, err := url.Parse(ex.Request.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("entry %d has an invalid HTTP URL", i+1)
		}
		ex.Request.Method = strings.ToUpper(strings.TrimSpace(ex.Request.Method))
		if ex.Request.Method == "" {
			return nil, fmt.Errorf("entry %d has no request method", i+1)
		}
		if len(ex.Request.Body) > MaxMessageBytes || len(ex.Response.Body) > MaxMessageBytes {
			return nil, fmt.Errorf("entry %d HTTP body exceeds %d bytes", i+1, MaxMessageBytes)
		}
		if len(ex.Request.Headers) > 256 || len(ex.Response.Headers) > 256 {
			return nil, fmt.Errorf("entry %d has too many headers", i+1)
		}
	}
	return env.Entries, nil
}
