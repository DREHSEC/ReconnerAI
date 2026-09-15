package scanner

import (
	"strings"
	"testing"

	"github.com/recon-platform/internal/capture"
)

func TestDiscoverGuidedOpportunitiesRanksWithoutLeakingValues(t *testing.T) {
	r := capture.Request{
		Method:   "POST",
		URL:      "https://app.example.test/api/orders/12345?redirect_url=https%3A%2F%2Fsecret.example%2Fnext&q=private-search",
		MimeType: "application/json",
		Headers:  []capture.Header{{Name: "Cookie", Value: "sid=top-secret"}},
		Body:     []byte(`{"user_id":"507f1f77bcf86cd799439011","callback_url":"https://private.example/hook","message":"private message"}`),
	}
	opportunities := DiscoverGuidedOpportunities(r)
	want := map[string]bool{"idor": false, "sqli": false, "xss": false, "nosqli": false, "ssrf": false, "open_redirect": false, "csrf": false}
	for _, opportunity := range opportunities {
		if _, ok := want[opportunity.Module]; ok {
			want[opportunity.Module] = true
		}
		encoded := opportunity.Parameter + opportunity.Location + opportunity.Reason + strings.Join(opportunity.Payloads, "")
		for _, secret := range []string{"top-secret", "private-search", "private.example", "private message", "507f1f77bcf86cd799439011"} {
			if strings.Contains(encoded, secret) {
				t.Fatalf("opportunity leaked captured value %q: %+v", secret, opportunity)
			}
		}
	}
	for module, found := range want {
		if !found {
			t.Errorf("expected %s opportunity, got %+v", module, opportunities)
		}
	}
}

func TestDiscoverGuidedOpportunitiesFindsPathIDORAndCORS(t *testing.T) {
	r := capture.Request{
		Method: "GET", URL: "https://app.example.test/users/8f14e45fceea167a5a36dedd4bea2543/profile",
		Headers: []capture.Header{{Name: "Authorization", Value: "Bearer secret"}},
	}
	var idor, cors bool
	for _, opportunity := range DiscoverGuidedOpportunities(r) {
		idor = idor || opportunity.Module == "idor" && opportunity.Location == "path"
		cors = cors || opportunity.Module == "cors" && opportunity.Automated
	}
	if !idor || !cors {
		t.Fatalf("missing path IDOR or CORS opportunity: %+v", DiscoverGuidedOpportunities(r))
	}
}

func TestDiscoverGuidedOpportunitiesKeepsNonObjectIDORManual(t *testing.T) {
	r := capture.Request{Method: "GET", URL: "https://app.example.test/profile?user=alice&account_id=91723&note=reference-2026-long-value"}
	var userFound, userAutomated, accountFound, accountAutomated bool
	for _, opportunity := range DiscoverGuidedOpportunities(r) {
		if opportunity.Module != "idor" {
			continue
		}
		switch opportunity.Parameter {
		case "user":
			userFound = true
			userAutomated = opportunity.Automated
		case "account_id":
			accountFound = true
			accountAutomated = opportunity.Automated
		}
	}
	if !userFound || userAutomated {
		t.Fatal("a name-only IDOR hint must require a manually supplied owned object")
	}
	if !accountFound || !accountAutomated {
		t.Fatal("a numeric object identifier should support the bounded automatic differential")
	}

	points := guidedIDORPoints(r)
	for _, point := range points {
		if point.ip.Param == "user" {
			t.Fatal("automatic IDOR execution included a value that is not safely mutable as an object identifier")
		}
	}
}

func TestDiscoverGuidedOpportunitiesUnderstandsCamelCaseNames(t *testing.T) {
	r := capture.Request{Method: "GET", URL: "https://app.example.test/search?destinationCallbackUrl=internal&customerSearchTerm=books"}
	want := map[string]bool{
		"ssrf:destinationCallbackUrl": false,
		"sqli:customerSearchTerm":     false,
		"xss:customerSearchTerm":      false,
	}
	for _, opportunity := range DiscoverGuidedOpportunities(r) {
		key := opportunity.Module + ":" + opportunity.Parameter
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for signal, found := range want {
		if !found {
			t.Errorf("camelCase parameter did not produce %s: %+v", signal, DiscoverGuidedOpportunities(r))
		}
	}
}

func TestGuidedChecksUseExactRequestedPlan(t *testing.T) {
	input := GuidedInput{
		Templates: []GuidedTemplate{{ID: "request-a"}, {ID: "request-b"}},
		Modules:   []string{"xss", "sqli"},
		Checks: []GuidedCheck{
			{TemplateID: "request-a", Module: "xss"},
			{TemplateID: "request-b", Module: "sqli"},
		},
	}
	checks := guidedChecks(input)
	if len(checks) != 2 || checks[0] != input.Checks[0] || checks[1] != input.Checks[1] {
		t.Fatalf("exact check plan expanded unexpectedly: %+v", checks)
	}
	if GuidedCheckCount(input) != 2 {
		t.Fatalf("guided progress count expanded exact plan: %d", GuidedCheckCount(input))
	}
}
