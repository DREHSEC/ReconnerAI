// Package capture provides tool-neutral ingestion for researcher-observed HTTP
// traffic. Importing a capture is passive: this package never sends requests.
package capture

import "time"

const (
	MaxImportBytes  = 32 << 20 // 32 MiB per uploaded capture
	MaxMessageBytes = 8 << 20  // 8 MiB per request or response; total import remains 32 MiB
	MaxItems        = 5000
)

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Request struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	HTTPVersion string   `json:"http_version"`
	Headers     []Header `json:"headers"`
	Body        []byte   `json:"body,omitempty"`
	MimeType    string   `json:"mime_type,omitempty"`
}

type Response struct {
	Status      int      `json:"status"`
	HTTPVersion string   `json:"http_version"`
	Headers     []Header `json:"headers"`
	Body        []byte   `json:"body,omitempty"`
	MimeType    string   `json:"mime_type,omitempty"`
	TimeMS      int64    `json:"time_ms,omitempty"`
}

// Exchange is the canonical boundary shared by Burp XML, HAR and future live
// adapters. Source-specific parsers must not write scanner tables directly.
type Exchange struct {
	Source         string    `json:"source"`
	SourceID       string    `json:"source_id,omitempty"`
	Sequence       int       `json:"sequence"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	IdentityLabel  string    `json:"identity_label,omitempty"`
	Request        Request   `json:"request"`
	Response       Response  `json:"response"`
	RedirectParent string    `json:"redirect_parent,omitempty"`
}
