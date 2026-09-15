package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func pfNames(hits []minedParam) []string {
	names := make([]string, 0, len(hits))
	for _, hit := range hits {
		names = append(names, hit.name)
	}
	sort.Strings(names)
	return names
}

// A catch-all endpoint that echoes every unknown name/value is the canonical
// hidden-parameter false positive. A same-shape negative control must make its
// response equivalent to the candidate response and reject the entire chunk.
func TestParamFuzzRejectsEchoAllParametersDeterministically(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		values := r.URL.Query()
		_ = r.ParseForm()
		for key, vals := range r.PostForm {
			for _, value := range vals {
				values.Add(key, value)
			}
		}
		var keys []string
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(w, "%s=%s\n", key, values.Get(key))
		}
	}))
	defer srv.Close()

	s := &ParamFuzzScanner{}
	ep := pfEndpoint{url: srv.URL, contracts: []pfContract{{loc: pfQuery, method: http.MethodGet}}}
	for run := 0; run < 2; run++ {
		if got := pfNames(s.mine(context.Background(), ep, nil, []string{"program_specific_flag"})); len(got) != 0 {
			t.Fatalf("run %d: echo-all response produced hidden parameters: %v", run+1, got)
		}
	}
	// This is intentionally generous: it guards against accidentally restoring
	// one-request-per-word behavior without coupling the test to one batch size.
	if got := requests.Load(); got > 80 {
		t.Fatalf("echo rejection used %d requests; batching/performance regressed", got)
	}
}

// Multi-sample calibration must tolerate a page whose body is genuinely noisy,
// while a stable response dimension (a header shape here) still lets a real
// hidden parameter survive two independent confirmation values.
func TestParamFuzzStableBaselineStillFindsRepeatableEffect(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		noise := []int{8, 176, 64}[int((n-1)%3)]
		if r.URL.Query().Has("debug") {
			w.Header().Set("X-Reconner-Param-Effect", "enabled")
		}
		fmt.Fprintf(w, "page:%s", strings.Repeat("n", noise))
	}))
	defer srv.Close()

	s := &ParamFuzzScanner{}
	ep := pfEndpoint{url: srv.URL, contracts: []pfContract{{loc: pfQuery, method: http.MethodGet}}}
	hits := pfNames(s.mine(context.Background(), ep, nil, nil))
	if len(hits) != 1 || hits[0] != "debug" {
		t.Fatalf("repeatable hidden parameter was lost in a noisy baseline, hits=%v", hits)
	}
}

// A one-off or alternating response change is not reproducible evidence. Even
// if it survives chunk isolation, the final single-name confirmation must reject
// it instead of persisting a flaky false positive.
func TestParamFuzzRejectsNonRepeatableSingleNameEffect(t *testing.T) {
	var debugRequests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("debug") {
			n := debugRequests.Add(1)
			if n%2 == 1 {
				w.Header().Set("X-Reconner-Transient", "one-off")
			}
		}
		_, _ = w.Write([]byte("stable"))
	}))
	defer srv.Close()

	s := &ParamFuzzScanner{}
	ep := pfEndpoint{url: srv.URL, contracts: []pfContract{{loc: pfQuery, method: http.MethodGet}}}
	if got := pfNames(s.mine(context.Background(), ep, nil, nil)); len(got) != 0 {
		t.Fatalf("non-repeatable effect produced hidden parameters: %v", got)
	}
	if debugRequests.Load() == 0 {
		t.Fatal("test did not exercise the candidate path")
	}
}

// Parameter mining must replay the real request contract. The mock endpoint
// exposes its hidden parameter only after method, content type and all required
// typed siblings pass validation; dropping any of them creates a deterministic
// false negative.
func TestParamFuzzPreservesJSONMethodAndTypedSiblings(t *testing.T) {
	var validContract, invalidContract atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// buildWordlist performs one ordinary GET before contract probes.
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("endpoint"))
			return
		}
		var doc map[string]any
		valid := r.Method == http.MethodPatch &&
			strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") &&
			json.NewDecoder(r.Body).Decode(&doc) == nil &&
			doc["tenant"] == "acme" && doc["csrf"] == "tok-123" && doc["qty"] == float64(2) && doc["action"] == "search"
		if !valid {
			invalidContract.Add(1)
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte("invalid contract"))
			return
		}
		validContract.Add(1)
		if _, ok := doc["debug"]; ok {
			w.Header().Set("X-Reconner-Param-Effect", "enabled")
		}
		_, _ = w.Write([]byte("accepted"))
	}))
	defer srv.Close()

	s := &ParamFuzzScanner{}
	ep := pfEndpoint{url: srv.URL, contracts: []pfContract{{
		loc:         pfJSON,
		method:      http.MethodPatch,
		contentType: "application/json",
		siblings:    map[string]string{"tenant": "acme", "csrf": "tok-123", "qty": "2", "action": "search"},
		siblingTypes: map[string]string{
			"tenant": "string", "csrf": "string", "qty": "integer",
		},
	}}}
	hits := pfNames(s.mine(context.Background(), ep, nil, nil))
	if len(hits) != 1 || hits[0] != "debug" {
		t.Fatalf("contract-aware mining missed the hidden JSON parameter, hits=%v", hits)
	}
	if validContract.Load() == 0 || invalidContract.Load() != 0 {
		t.Fatalf("request contract was not preserved: valid=%d invalid=%d", validContract.Load(), invalidContract.Load())
	}
}

// Endpoint selection must rank a known dynamic/API request contract above a
// large alphabetic set of generic pages, then reconstruct its sibling fields and
// JSON types. Otherwise the fixed endpoint budget silently drops the best input.
func TestParamFuzzEndpointPriorityPreservesObservedContract(t *testing.T) {
	db, targetID := testDB(t)
	defer db.Close()

	for i := 0; i < pfMaxHosts+20; i++ {
		rawURL := fmt.Sprintf("https://generic.example.test/page-%03d", i)
		if _, err := db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,content_type) VALUES(?,?,?,?,?)`,
			uuid.NewString(), targetID, rawURL, 200, "text/html"); err != nil {
			t.Fatal(err)
		}
	}
	const apiURL = "https://z-api.example.test/api/orders"
	if _, err := db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,content_type) VALUES(?,?,?,?,?)`,
		uuid.NewString(), targetID, apiURL, 200, "application/json"); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, value, location string
	}{
		{"tenant", "acme", "json:string"},
		{"csrf", "tok-123", "json:string"},
		{"qty", "2", "json:integer"},
	} {
		if _, err := db.Exec(`INSERT INTO parameters
			(id,target_id,url,parameter,value,source,method,content_type,location)
			VALUES(?,?,?,?,?,'openapi','PATCH','application/json',?)`,
			uuid.NewString(), targetID, apiURL, row.name, row.value, row.location); err != nil {
			t.Fatal(err)
		}
	}

	endpoints := (&ParamFuzzScanner{db: db}).selectEndpoints(context.Background(), targetID)
	if len(endpoints) > pfMaxHosts {
		t.Fatalf("selected %d endpoints, ceiling=%d", len(endpoints), pfMaxHosts)
	}
	var api *pfEndpoint
	for i := range endpoints {
		if endpoints[i].url == apiURL {
			api = &endpoints[i]
			break
		}
	}
	if api == nil {
		t.Fatal("high-signal API contract was crowded out by generic pages")
	}
	var contract *pfContract
	for i := range api.contracts {
		c := &api.contracts[i]
		if c.loc == pfJSON && c.method == http.MethodPatch {
			contract = c
			break
		}
	}
	if contract == nil {
		t.Fatalf("PATCH JSON contract was not reconstructed: %+v", api.contracts)
	}
	if contract.contentType != "application/json" || contract.siblings["tenant"] != "acme" ||
		contract.siblings["csrf"] != "tok-123" || contract.siblings["qty"] != "2" ||
		contract.siblingTypes["qty"] != "integer" {
		t.Fatalf("observed request contract lost siblings/types: %+v", contract)
	}
}
