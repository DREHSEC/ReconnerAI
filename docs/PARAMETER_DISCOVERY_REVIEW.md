# Parameter discovery reliability review

## Scope of this checkpoint

This change reviews hidden-parameter mining and the HTTP/rendered-form data
feeding it. It is not an assertion that every scanner module has been audited
or that real-world false positives or false negatives are eliminated.

## Implemented changes

- Calibrate three baseline responses and compare only stable response dimensions.
- Compare positive batches with same-shape negative-control parameter names.
- Require two independently marked candidate/control rounds before storing an
  influential parameter. A discovered parameter is not a vulnerability finding.
- Reject transport failures, rate-limit responses, and server errors as evidence.
- Use bounded batches of 64 query names or 96 body names instead of 25.
- Reconstruct observed request methods, form fields, and typed JSON siblings.
  Preserve existing fields rather than replacing them during unknown-name mining.
- Prioritize observed request contracts before applying the 60-endpoint budget.
  Preserve path case, query-name shape, and method/content-type identity when
  deduplicating routes; enforce host and endpoint restrictions.
- Preserve case-sensitive parameter names and derive a small set of naming
  convention variants from observed names.
- Discover GET forms as well as POST forms. Retain rendered field values,
  method, encoding, and required siblings. Exclude unchecked/disabled controls
  from rendered form replay and refresh stored nonempty values on later crawls.
- Propagate scan cancellation to the rendered crawler's browser allocator and
  parameter-mining worker admission.

No executable payload family was added by this change. Parameter probes use
inert marker strings. Existing request methods still require operator-approved
scope and suitable test accounts/data.

## Regression coverage

Local HTTP fixtures cover generic echo-all responses, changing response bodies,
repeatable header effects, intermittent effects, typed PATCH JSON requests,
required fields whose names also occur in the static dictionary, endpoint
prioritization, and GET/POST form storage. The echo-all regression imposes a
request-count ceiling to catch accidental per-word probing.

These fixtures do not measure production precision/recall or browser execution
against a live target. Browser field extraction was changed, but no real-browser
end-to-end result should be inferred from database-only storage tests.

Validation completed: `go test ./...`, `go vet ./...`, targeted scanner tests
after the final scope/deduplication edits, and race-enabled tests for parameter
mining and form storage all passed. The full scanner suite took approximately
136 seconds on the development machine; this is test runtime, not a scan-speed
benchmark.

## Existing features inspected

- `adaptive_wordlist.go` already builds and persists ranked target vocabulary
  from collected URLs, JS endpoints, metadata, parameters and directory records;
  it consumes existing crawl output rather than starting its own crawl.
- `catalog_test.go` includes coverage for wildcard filtering of unopened catalog
  programs after indexing.
- The exact Unix/Windows command-injection Nuclei template IDs are excluded in
  `nuclei_intel.go`. This is suppression of those templates, not retuning their
  matchers. Native verification remains a separate path.

## Remaining limitations

- Endpoint and row-pool caps remain. Results are bounded coverage, not exhaustive.
- The parameter table does not identify separate forms sharing the same action
  and request shape, so siblings from distinct forms may still be combined.
- Large batches can encounter application-specific field/URL-size limits.
- Whole-body stability checks can miss subtle effects on highly dynamic pages.
- The adaptive vocabulary builder's source queries use bounded unordered pools;
  reproducibility across database layouts merits a separate follow-up.
- Whole-project monitoring, notification, and scheduler auditing remains outside
  the completed scope of this checkpoint.

## Research references

The comparison used the official source repositories for baseline learning,
negative controls, batching, and individual candidate verification:

- [Arjun](https://github.com/s0md3v/Arjun)
- [x8](https://github.com/Sh1Yo/x8)
- [Param Miner](https://github.com/PortSwigger/param-miner)
- [Katana documentation](https://docs.projectdiscovery.io/opensource/katana/running)

The algorithms here are independently implemented and should not be interpreted
as equivalent coverage or performance to those tools.
