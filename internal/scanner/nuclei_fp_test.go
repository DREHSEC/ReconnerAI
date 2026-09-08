package scanner

import "testing"

func TestBlockedNoisyTemplates(t *testing.T) {
	blocked := []struct{ id, name string }{
		{"brotli-compression-oracle-attack", "Brotli Compression Oracle Attack Detection"},
		{"web-cache-poisoning-real", "Web Cache Poisoning"},
		{"some-id", "Brotli Compression Oracle Attack Detection"}, // name-only backstop
		{"web-cache-poisoning", "Web Cache Poisoning (real)"},
		{"unix-command-injection", "Unix Command Injection"},
		{"windows-command-injection", "Windows Command Injection"},
	}
	for _, b := range blocked {
		if !nucleiBlockedTemplate(b.id, b.name) {
			t.Errorf("template %q/%q should be blocked", b.id, b.name)
		}
	}
	// A real template must NOT be blocked by the new patterns.
	if nucleiBlockedTemplate("CVE-2021-44228", "Apache Log4j RCE") {
		t.Error("log4shell must not be blocked")
	}
}

func TestNucleiURLReflectionFP(t *testing.T) {
	// The tirana-airport.com case: shellshock payload in the PATH is reflected
	// verbatim into an og:url meta tag → the "echo www-data" match is a reflection.
	req := "GET /at.php%28%29%20%7B%20:;%7D;%20echo%20www-data HTTP/1.1\r\nHost: x\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<meta property="og:url" content="https://x/at.php%28%29%20%7B%20:;%7D;%20echo%20www-data" >www-data`
	if !nucleiURLReflectionFP("cmd-injection", "OS Command Injection", []string{"cmdi"}, req, resp) {
		t.Error("reflected-URL command-injection must be flagged as FP")
	}

	// A genuine RCE where output (not the URL) appears must NOT be flagged.
	req2 := "GET /ping?host=127.0.0.1;id HTTP/1.1\r\nHost: x\r\n\r\n"
	resp2 := "HTTP/1.1 200 OK\r\n\r\nuid=0(root) gid=0(root) groups=0(root)"
	if nucleiURLReflectionFP("cmd-injection", "OS Command Injection", []string{"cmdi"}, req2, resp2) {
		t.Error("a real RCE (command output, no URL echo) must NOT be flagged")
	}

	// A non-injection template is never touched by this guard.
	if nucleiURLReflectionFP("tech-detect", "Tech Detect", []string{"tech"}, req, resp) {
		t.Error("non-injection template must not be affected")
	}

	// The real tirana /player case: shellshock payload in the PATH plus a ?query,
	// sent url-ENCODED on the wire (a request-target can't contain raw spaces), and
	// reflected ENCODED into og:url. Must be flagged as an FP.
	pReqEnc := "GET /player%28%29%20%7B%20:;%7D;%20echo%20www-data?autoplay=true HTTP/1.1\r\nHost: x\r\n\r\n"
	pRespEncoded := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<meta property="og:url" content="https://x/player%28%29%20%7B%20:;%7D;%20echo%20www-data?autoplay=true">www-data`
	if !nucleiURLReflectionFP("CVE-2014-6271", "Shellshock", []string{"cve", "shellshock", "rce"}, pReqEnc, pRespEncoded) {
		t.Error("shellshock reflected into og:url (encoded body) must be flagged as FP")
	}
	// The encode/decode-robust path: request ENCODED, body reflects DECODED.
	pReqEncoded := "GET /player%28%29%20%7B%20:;%7D;%20echo%20www-data?autoplay=true HTTP/1.1\r\nHost: x\r\n\r\n"
	pRespDecoded := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<link rel="canonical" href="https://x/player() { :;}; echo www-data?autoplay=true">www-data`
	if !nucleiURLReflectionFP("CVE-2014-6271", "Shellshock", []string{"shellshock"}, pReqEncoded, pRespDecoded) {
		t.Error("shellshock reflected into canonical (decoded body, encoded request) must be flagged as FP")
	}
}

func TestNucleiCmdiLacksProofTalheim500(t *testing.T) {
	req := "GET /analytics/matomo.php?idsite=;id&rec=1 HTTP/1.1\r\nHost: ratsinformationssystem.talheim.de\r\n\r\n"
	resp := "HTTP/1.1 500 500\r\nContent-Length: 11\r\nContent-Type: text/plain;charset=UTF-8\r\n\r\nERROR (239)"
	tags := []string{"cmdi", "dast", "rce", "unix", "linux", "fuzz", "vuln"}
	if !nucleiCmdiLacksProof("unix-command-injection", "Unix Command Injection - Generic Detection", tags, req, resp) {
		t.Fatal("Matomo 500 ERROR (239) must be treated as no-proof cmdi")
	}
	winReq := "GET /analytics/matomo.php?idsite=|dir&rec=1 HTTP/1.1\r\nHost: x\r\n\r\n"
	if !nucleiCmdiLacksProof("windows-command-injection", "Windows Command Injection - Generic Detection",
		[]string{"cmdi", "dast", "rce", "windows", "fuzz", "vuln"}, winReq, resp) {
		t.Fatal("windows cmdi on the same 500 body must lack proof")
	}
}

func TestNucleiCmdiKeepsRealShellOutput(t *testing.T) {
	req := "GET /ping?host=127.0.0.1;id HTTP/1.1\r\nHost: x\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\n\r\nuid=0(root) gid=0(root) groups=0(root)"
	if nucleiCmdiLacksProof("unix-command-injection", "Unix Command Injection", []string{"cmdi", "rce"}, req, resp) {
		t.Fatal("uid= proof must not be rejected")
	}
	win := "HTTP/1.1 200 OK\r\n\r\n Volume Serial Number is 1234-ABCD\r\n Directory of C:\\\r\n"
	if nucleiCmdiLacksProof("windows-command-injection", "Windows Command Injection", []string{"cmdi", "rce"}, req, win) {
		t.Fatal("Windows dir proof must not be rejected")
	}
}

func TestNucleiCmdiLeavesOASTAlone(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\n\r\nok"
	if nucleiCmdiLacksProof("generic-blind-rce", "Blind RCE OAST", []string{"rce", "oast"}, "GET /x HTTP/1.1\r\n\r\n", resp) {
		t.Fatal("OAST/blind cmdi must not be auto-rejected for missing body proof")
	}
}

func TestScrubNucleiCmdiFPs(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	_, _ = db.Exec(`INSERT INTO nuclei_findings (id, target_id, template_id, template_name, severity, matched_url, tags, request, response, verification)
		VALUES (?,?,?,?,?,?,?,?,?, 'unverified')`,
		"n1", tid, "unix-command-injection", "Unix Command Injection - Generic Detection", "high",
		"https://app.example.test/x?id=;id", `["cmdi","rce"]`,
		"GET /x?id=;id HTTP/1.1\r\nHost: app.example.test\r\n\r\n",
		"HTTP/1.1 500 500\r\n\r\nERROR (239)")
	_, _ = db.Exec(`INSERT INTO nuclei_findings (id, target_id, template_id, template_name, severity, matched_url, tags, request, response, verification)
		VALUES (?,?,?,?,?,?,?,?,?, 'unverified')`,
		"n2", tid, "unix-command-injection", "Unix Command Injection", "high",
		"https://app.example.test/ping?h=;id", `["cmdi","rce"]`,
		"GET /ping?h=;id HTTP/1.1\r\nHost: app.example.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\nuid=33(www-data) gid=33(www-data) groups=33(www-data)")
	_, _ = db.Exec(`UPDATE targets SET finding_count=2 WHERE id=?`, tid)

	n := ScrubNucleiCmdiFPs(db, tid)
	if n != 1 {
		t.Fatalf("scrubbed=%d want 1", n)
	}
	var v1, v2 string
	_ = db.QueryRow(`SELECT verification FROM nuclei_findings WHERE id='n1'`).Scan(&v1)
	_ = db.QueryRow(`SELECT verification FROM nuclei_findings WHERE id='n2'`).Scan(&v2)
	if v1 != "rejected" {
		t.Fatalf("error-body row verification=%s", v1)
	}
	if v2 != "unverified" {
		t.Fatalf("real-output row must stay unverified, got %s", v2)
	}
	var count int
	_ = db.QueryRow(`SELECT finding_count FROM targets WHERE id=?`, tid).Scan(&count)
	if count != 1 {
		t.Fatalf("finding_count=%d want 1 after scrub", count)
	}
}

func TestLenientURLDecode(t *testing.T) {
	cases := map[string]string{
		"%28%29%20%7B":     "() {",
		"a+b":              "a b",
		"100%discount":     "100%discount", // malformed % left as-is
		"/path/no-escapes": "/path/no-escapes",
	}
	for in, want := range cases {
		if got := lenientURLDecode(in); got != want {
			t.Errorf("lenientURLDecode(%q)=%q want %q", in, got, want)
		}
	}
}
