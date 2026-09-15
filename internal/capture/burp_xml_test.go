package capture

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func burpFixture(request, response string, encoded bool) []byte {
	enc := "false"
	if encoded {
		enc = "true"
		request = base64.StdEncoding.EncodeToString([]byte(request))
		response = base64.StdEncoding.EncodeToString([]byte(response))
	}
	return []byte(`<?xml version="1.0"?><items><item>
<url><![CDATA[https://app.example.test/api/projects/42?view=full&token=secret]]></url>
<host>app.example.test</host><port>443</port><protocol>https</protocol>
<method>POST</method><path>/api/projects/42?view=full&amp;token=secret</path>
<request base64="` + enc + `"><![CDATA[` + request + `]]></request>
<status>200</status><mimetype>JSON</mimetype>
<response base64="` + enc + `"><![CDATA[` + response + `]]></response>
</item></items>`)
}

func TestParseReconnerJSON(t *testing.T) {
	env := Envelope{Schema: SchemaV1, Source: "chrome-devtools", Label: "deep route", Entries: []Exchange{{
		Sequence: 1,
		Request:  Request{Method: "get", URL: "https://app.example.test/api/orders/77", Body: []byte("hello")},
		Response: Response{Status: 200, Body: []byte("world")},
	}}}
	raw, _ := json.Marshal(env)
	items, err := ParseReconnerJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Source != "chrome-devtools" || items[0].Request.Method != "GET" || string(items[0].Response.Body) != "world" {
		t.Fatalf("unexpected canonical import: %+v", items)
	}
}

func TestParseReconnerJSONRejectsTrailingDataAndOversizedBodies(t *testing.T) {
	env := Envelope{Schema: SchemaV1, Entries: []Exchange{{
		Request: Request{Method: "GET", URL: "https://app.example.test/ok"},
	}}}
	raw, _ := json.Marshal(env)
	if _, err := ParseReconnerJSON(append(raw, []byte(` {"unexpected":true}`)...)); err == nil {
		t.Fatal("accepted a second JSON value after the capture envelope")
	}
	env.Entries[0].Request.Body = make([]byte, MaxMessageBytes+1)
	raw, _ = json.Marshal(env)
	if _, err := ParseReconnerJSON(raw); err == nil {
		t.Fatal("accepted an oversized decoded request body")
	}
}

func TestParseBurpXMLPlainAndBase64(t *testing.T) {
	req := "POST /api/projects/42?view=full&token=secret HTTP/1.1\r\nHost: app.example.test\r\nAuthorization: Bearer abc.def.ghi\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"name\":\"ok\"}"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=secret\r\nContent-Length: 11\r\n\r\n{\"id\":\"42\"}"
	for _, encoded := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "base64"}[encoded], func(t *testing.T) {
			items, err := ParseBurpXML(burpFixture(req, resp, encoded))
			if err != nil {
				t.Fatal(err)
			}
			if len(items) != 1 || items[0].Request.Method != "POST" || items[0].Response.Status != 200 {
				t.Fatalf("unexpected exchange: %+v", items)
			}
			if got := string(items[0].Request.Body); got != `{"name":"ok"}` {
				t.Fatalf("request body changed: %q", got)
			}
			if !ContainsSensitiveMaterial(items[0]) {
				t.Fatal("authorization/cookie material was not marked sensitive")
			}
		})
	}
}

func TestParseBurpXMLRejectsDTD(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><items></items>`)
	if _, err := ParseBurpXML(raw); err != ErrUnsafeXML {
		t.Fatalf("expected ErrUnsafeXML, got %v", err)
	}
}

func TestParseBurpXMLAbsentResponseAndInvalidBase64(t *testing.T) {
	req := "GET /health HTTP/1.1\r\nHost: app.example.test\r\n\r\n"
	items, err := ParseBurpXML(burpFixture(req, "", true))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Response.Status != 200 || len(items[0].Response.Body) != 0 {
		t.Fatalf("absent response metadata was not retained safely: %+v", items)
	}
	bad := []byte(`<?xml version="1.0"?><items><item><url>https://app.example.test/</url><request base64="true">%%%not-base64%%%</request></item></items>`)
	if _, err := ParseBurpXML(bad); err == nil {
		t.Fatal("accepted malformed base64 request data")
	}
}

func TestParseBurpXMLUsesCanonicalURLNotConflictingHostHeader(t *testing.T) {
	req := "GET /private HTTP/1.1\r\nHost: attacker.invalid\r\n\r\n"
	items, err := ParseBurpXML(burpFixture(req, "", true))
	if err != nil {
		t.Fatal(err)
	}
	if got := items[0].Request.URL; !strings.HasPrefix(got, "https://app.example.test/") {
		t.Fatalf("conflicting raw Host overrode canonical Burp URL: %s", got)
	}
}

func TestBuildPreviewRedactsValuesAndAppliesScope(t *testing.T) {
	req := "GET /account/7?token=very-secret&view=full HTTP/1.1\r\nHost: app.example.test\r\nCookie: sid=very-secret\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
	items, err := ParseBurpXML(burpFixture(req, resp, true))
	if err != nil {
		t.Fatal(err)
	}
	p := BuildPreview(items, func(raw string) bool { return strings.Contains(raw, "app.example.test") })
	if p.Accepted != 1 || p.Sensitive != 1 || p.ReadOnly != 1 {
		t.Fatalf("unexpected preview counts: %+v", p)
	}
	encodedPreview := p.Items[0].Route + strings.Join(p.Items[0].HeaderNames, ",")
	if strings.Contains(encodedPreview, "very-secret") || strings.Contains(encodedPreview, "sid=") {
		t.Fatalf("preview leaked a secret: %s", encodedPreview)
	}
	if !strings.Contains(p.Items[0].Route, "%7Bvalue%7D") {
		t.Fatalf("query values were not masked: %s", p.Items[0].Route)
	}
}

func TestOperationKindGraphQLMutation(t *testing.T) {
	r := Request{Method: "POST", URL: "https://app.example.test/graphql", MimeType: "application/json", Body: []byte(`{"query":"mutation Rename { renameProject(id: 1) }"}`)}
	if got := OperationKind(r); got != "state_changing" {
		t.Fatalf("got %q", got)
	}
}

func TestStateChangingPreviewIsNeverAutoEligible(t *testing.T) {
	ex := Exchange{Source: "test", Sequence: 1, Request: Request{
		Method: "POST", URL: "https://app.example.test/account", MimeType: "application/json", Body: []byte(`{"name":"new"}`),
	}}
	p := BuildPreview([]Exchange{ex}, func(string) bool { return true })
	if p.StateChanging != 1 || p.Items[0].AutoEligible {
		t.Fatalf("state-changing request became automatically eligible: %+v", p.Items[0])
	}
}

func TestSafeDisplayURLMasksQueryUserInfoAndSecretPath(t *testing.T) {
	got := SafeDisplayURL("https://name:pass@app.example.test/reset/abcdefghijklmnopqrstuvwxyz123456?token=secret&id=42#frag")
	for _, secret := range []string{"name", "pass", "abcdefghijklmnopqrstuvwxyz123456", "token=secret", "id=42", "frag"} {
		if strings.Contains(got, secret) {
			t.Fatalf("safe URL leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "%7Bsecret%7D") || !strings.Contains(got, "%7Bvalue%7D") {
		t.Fatalf("safe URL omitted redaction markers: %s", got)
	}
}

func TestRequestShapeMasksOnlyRotatingSecrets(t *testing.T) {
	a := Request{Method: "POST", URL: "https://app.example.test/orders/77?csrf=one&id=77", MimeType: "application/json",
		Headers: []Header{{Name: "Authorization", Value: "Bearer one"}}, Body: []byte(`{"csrf_token":"one","object_id":77}`)}
	b := Request{Method: "POST", URL: "https://app.example.test/orders/77?csrf=two&id=77", MimeType: "application/json",
		Headers: []Header{{Name: "Authorization", Value: "Bearer two"}}, Body: []byte(`{"csrf_token":"two","object_id":77}`)}
	if string(RequestShapeBytes(a)) != string(RequestShapeBytes(b)) {
		t.Fatal("rotating auth/CSRF values should not create duplicate shapes")
	}
	b.URL = "https://app.example.test/orders/88?csrf=two&id=88"
	b.Body = []byte(`{"csrf_token":"two","object_id":88}`)
	if string(RequestShapeBytes(a)) == string(RequestShapeBytes(b)) {
		t.Fatal("different business object values must remain distinct")
	}
}
