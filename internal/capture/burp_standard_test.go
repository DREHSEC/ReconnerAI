package capture

import (
	"bytes"
	"os"
	"testing"
)

func TestStandardBurpExportDTD(t *testing.T) {
	raw := burpFixture("GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n", "", true)
	raw = bytes.Replace(raw, []byte("<items>"), []byte(standardBurpDTD+"<items>"), 1)
	if _, err := ParseBurpXML(raw); err != nil {
		t.Fatal(err)
	}
	malicious := bytes.Replace(raw, []byte("<!ELEMENT time"), []byte("<!ENTITY secret SYSTEM \"file:///etc/passwd\">\n<!ELEMENT time"), 1)
	if _, err := ParseBurpXML(malicious); err != ErrUnsafeXML {
		t.Fatalf("unsafe schema accepted: %v", err)
	}
}

func TestBurpHTTP2TextMessages(t *testing.T) {
	raw := burpFixture("POST / HTTP/2\r\nHost: app.example.test\r\nContent-Length: 2\r\n\r\n{}", "HTTP/2 200 OK\r\nContent-Length: 2\r\n\r\nOK", true)
	items, err := ParseBurpXML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(items[0].Request.Body) != "{}" || string(items[0].Response.Body) != "OK" {
		t.Fatal("body changed")
	}
}

func TestLocalBurpExport(t *testing.T) {
	path := os.Getenv("RECONNER_CAPTURE_FIXTURE")
	if path == "" {
		t.Skip("optional private local fixture")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read local fixture")
	}
	items, err := ParseBurpXML(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed %d exchanges without network traffic", len(items))
}
