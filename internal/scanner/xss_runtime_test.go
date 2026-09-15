package scanner

import (
	"strings"
	"testing"
)

func TestRuntimeDOMInstrumentationCoversCoreSinks(t *testing.T) {
	script := runtimeDOMInstrumentationScript(`rcn"</script>marker`)
	for _, sink := range []string{
		"Element.innerHTML",
		"Element.outerHTML",
		"Element.insertAdjacentHTML",
		"Element.setAttribute",
		"Document.write",
		"Range.createContextualFragment",
		"DOMParser.parseFromString",
		"HTMLIFrameElement.srcdoc",
		"HTMLScriptElement.src",
		"window.setTimeout",
	} {
		if !strings.Contains(script, sink) {
			t.Errorf("runtime instrumentation is missing %s", sink)
		}
	}
	// json.Marshal must keep an attacker-controlled marker from terminating the
	// generated JavaScript string literal.
	if strings.Contains(script, `const marker="rcn"</script>`) {
		t.Fatal("marker was embedded without JSON escaping")
	}
}

func TestRuntimeDOMHitSummaryDeduplicates(t *testing.T) {
	hits := []runtimeDOMHit{
		{Sink: "Element.innerHTML"},
		{Sink: "Element.innerHTML"},
		{Sink: "Document.write"},
	}
	if got := runtimeDOMHitSummary(hits); got != "Element.innerHTML -> Document.write" {
		t.Fatalf("unexpected runtime trace: %q", got)
	}
}
