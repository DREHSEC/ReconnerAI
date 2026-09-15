# Hybrid Guided Crawl for Reconner

## Executive decision

Reconner should add a **Hybrid Guided Crawl** mode that turns traffic produced by
an authorized researcher into a narrow, state-aware scan corpus. The researcher
uses the application normally, reaches authenticated and deeply nested routes,
and then imports those observed request/response exchanges into Reconner. The
scanner derives exact request contracts, object ownership, workflow variables,
and safe insertion points from that corpus before running selected verification
engines.

The recommended delivery order is:

1. HAR 1.2 and Burp XML file import.
2. A capture-review screen and narrow-corpus scan mode.
3. Full request-template replay with session/token refresh.
4. A small Burp Montoya extension for live, one-way synchronization.
5. Native browser capture only after the file and extension paths are stable.

Burp history is therefore a first-class input, but not the internal data model.
Burp XML and HAR must both map into a tool-neutral `CapturedExchange` model.
This prevents a permanent dependency on Burp and also admits Chrome DevTools,
Playwright, OWASP ZAP, mitmproxy, and future capture sources through adapters.

The mode is **proof-only by default**. It may automatically replay read-only
requests and use bounded, non-exfiltrating probes. Requests classified as create,
update, delete, payment, invitation, password recovery, authentication, upload,
or other state-changing actions are imported and analyzed but are not
automatically mutated or replayed.

## Why guided capture materially improves results

Traditional crawling cannot reliably reproduce all of the state that a modern
application expects. Routes may require a specific account, tenant, feature
flag, object identifier, anti-CSRF token, GraphQL operation, JSON sibling field,
or prior workflow step. A human already knows how to reach many of these states.
The hybrid mode should preserve that work rather than rediscover it with broad
traffic.

Burp Proxy records traffic even while interception is disabled, and its history
retains request and response messages plus useful metadata.^1 Burp also treats
history items as the basis of macros, including derivation of changing values
from prior responses.^2 These properties match Reconner's needs: observed traffic
is both a high-quality route corpus and a source of workflow dependencies.

The approach is especially valuable for authorization. OWASP recommends using at
least two users with distinct owned objects and privileges instead of guessing
object identifiers.^3 A guided capture by User A and User B can establish real
ownership and provide known-good request contracts. Reconner can then perform a
bounded cross-identity replay and require the attacker response to contain the
same object before confirming IDOR/BOLA.

## Capture source strategy

| Source | Role | Strengths | Limitations | Delivery |
|---|---|---|---|---|
| HAR 1.2 | Portable baseline | JSON, broadly exportable, easy preview | Sensitive headers are commonly omitted; raw HTTP/2 details and some bodies may be absent | Phase 1 |
| Burp XML | High-fidelity manual import | Raw request/response, binary-safe base64 option, Burp metadata | Burp-specific and batch-oriented | Phase 1 |
| Burp Montoya extension | Live guided capture | Sends final proxy request and paired response immediately; can expose a context-menu action | Requires a local JAR, pairing, buffering, and version maintenance | Phase 4 |
| Native Chromium/Playwright capture | Integrated UX | Browser context events, storage state, initiator and runtime data | Remote-server UI, downloads, service workers, WebSockets, and session isolation add complexity | Phase 5 |

Chrome explicitly offers sanitized and sensitive HAR exports. The sanitized form
omits headers such as `Cookie`, `Set-Cookie`, and `Authorization`; sensitive HAR
export requires a deliberate user setting.^4 Reconner must therefore show whether
an import contains usable authentication and must never silently call a sanitized
HAR an authenticated corpus.

Burp can save selected request/response items as XML with metadata and supports
base64 encoding for binary-safe storage.^5 The importer should accept this format
without assuming that every XML export contains the same optional fields.

For live capture, the maintained Montoya API is preferred over the legacy
Extender API.^6 Montoya exposes proxy request and response handlers, allowing an
extension to observe the final request sent by Proxy and its corresponding
response without modifying either.^7 The extension should remain a thin,
one-directional collector; all parsing, scope policy, encryption, and pipeline
decisions belong in Reconner.

## Existing Reconner foundations

Reconner is already close to supporting this model:

- `internal/database/migrations.go` defines encrypted identities, normalized
  `http_interactions`, objects, actions, relationships, workflow variables,
  hypotheses, evidence, and state snapshots.
- `internal/api/target_handlers.go` exposes identity import, traffic ingest,
  replay, workflow execution, and authorization review endpoints.
- `internal/scanner/identity.go` decrypts per-target identities only at replay
  time and supports authenticated/unauthenticated comparisons.
- `internal/scanner/destination.go` prevents captured credentials from reaching
  private, loopback, link-local, metadata, rebound, or redirect destinations.
- `internal/scanner/insertion.go` already reconstructs query, path, form, JSON,
  multipart, XML, GraphQL, header, and cookie insertion points.
- `internal/scanner/authz_engine.go` already confirms read-only BOLA using owner,
  unauthenticated, and attacker controls while leaving state changes for explicit
  researcher action.
- `internal/scanner/workflow_run.go` already provides variable propagation and
  validates the resolved URL against scope immediately before replay.

These foundations should be extended rather than replaced.

## Gaps in the current model

### Interaction records are not replayable contracts

`CanonRequest` currently retains method, URL, identity label, and scanner name.
`http_interactions` stores response metadata and a hash, but not request headers,
request body, exact ordering, redirect linkage, or an encrypted response body.
The existing `/capture/traffic` endpoint receives only a small metadata object;
its `body` is used transiently for semantics and is not a request contract.

This is enough for graphs and rough object discovery, but not enough to reproduce
a JSON API call, a GraphQL operation, a multipart upload shape, or a CSRF-bound
form.

### Parameter sibling grouping can mix different requests

The `parameters` table identifies a field by target, URL, parameter, method,
location, and content type. It has no request-template identifier. Multiple forms
or JSON operations sharing those dimensions can therefore be merged into one
sibling set. Guided capture needs an immutable `request_template_id` so every
scanner mutates one field while preserving the exact siblings from the same
observed request.

### Replay loses request-specific headers

`ReplaySpec` currently contains method, URL, body, and content type. Identity
headers are added globally, but headers such as `Accept`, `Origin`, custom API
version, GraphQL operation metadata, conditional headers, and per-request CSRF
values are not represented. The hybrid path requires a safe header allowlist plus
an encrypted dynamic-value layer.

### Prefix scope is broader than a captured corpus

The existing endpoint-scope mode permits paths beneath a seed directory. Hybrid
narrow recon should default to an exact set of captured route templates and
methods. Discovery of a new sibling route may be shown as a candidate for user
approval, but it must not silently broaden the active corpus.

## Canonical model

Introduce a tool-neutral boundary type:

```go
type CapturedExchange struct {
    Source          string // har | burp-xml | burp-live | browser
    SourceID        string
    Sequence        int
    StartedAt       time.Time
    IdentityLabel   string
    Request         CapturedRequest
    Response        CapturedResponse
    Initiator       string
    RedirectParent  string
}

type CapturedRequest struct {
    Method      string
    URL         string
    HTTPVersion string
    Headers     []Header
    Body        []byte
    MimeType    string
}

type CapturedResponse struct {
    Status      int
    HTTPVersion string
    Headers     []Header
    Body        []byte
    MimeType    string
    TimeMs      int64
}
```

Adapters parse into this type. No adapter writes scanner tables directly. A
single admission service validates, classifies, encrypts, deduplicates, and then
materializes accepted exchanges into the rest of Reconner.

### New persistence tables

Use new tables rather than putting secrets into `http_interactions`:

```sql
capture_sessions(
  id, target_id, source, identity_id, label, status,
  imported_count, accepted_count, rejected_count,
  created_at, expires_at
)

request_templates(
  id, target_id, capture_session_id, identity_id,
  method, url, norm_url, content_type, operation_kind,
  request_shape_hash, encrypted_request, redacted_preview,
  replay_policy, source, sequence, created_at
)

captured_responses(
  id, request_template_id, status, content_type, body_hash,
  encrypted_response, redacted_preview, response_len,
  timing_ms, created_at
)
```

`encrypted_request` and `encrypted_response` should use the existing
`secret.Box` abstraction. The normal UI, logs, findings, search index, and reports
must use only redacted previews. Full decrypted material should be available only
to the replay engine and an explicit, audited reveal action.

Add `request_template_id` to `parameters`, `actions`, `objects`, and workflow
variables where useful. Existing rows remain valid with an empty identifier.

### Retention

Full responses can contain personal and account data. Default encrypted-body
retention should be bounded, for example 7 days, while redacted metadata and
hashes can remain. Each capture session needs a delete action that removes its
encrypted request/response bodies without deleting confirmed, already-redacted
evidence.

OWASP recommends removing, masking, hashing, or encrypting session identifiers,
access tokens, passwords, keys, and sensitive personal data rather than recording
them directly in logs.^8 Reconner should treat imported histories as a secret
vault, not ordinary scan logs.

## Import admission pipeline

Every imported exchange passes these stages in order:

1. **File bounds** — reject unsupported formats, excessive total bytes, excessive
   item counts, decompression bombs, malformed base64, and oversized individual
   bodies.
2. **Safe parsing** — stream XML; reject DTD/directive content; never resolve
   external entities; parse HAR with bounded JSON decoding.
3. **URL reconstruction** — derive an absolute URL from the raw request and
   source metadata without trusting conflicting `Host` values.
4. **Scope gate before secret storage** — reject an exchange unless its final URL
   belongs to the selected target/asset scope. Never persist credentials from an
   out-of-scope request merely because it occurred in the same browser session.
5. **Header normalization** — remove hop-by-hop headers (`Connection`,
   `Proxy-Authorization`, `Transfer-Encoding`, `Content-Length`, etc.); retain
   ordering only where evidence requires it.
6. **Identity binding** — the operator chooses User A, User B, Admin, or
   unauthenticated for the import. Do not infer identity solely from token text.
7. **Secret extraction** — move Cookie, Authorization, CSRF and selected custom
   secret headers into the encrypted identity/dynamic-value vault. Do not copy
   their values into metadata or logs.
8. **State classification** — label each request `read_only`, `query_like`,
   `state_changing`, `authentication`, `payment`, `upload`, or `unknown`.
9. **Exact deduplication** — dedupe identical exchanges by a keyed shape hash,
   while preserving distinct bodies, identities, statuses, and workflow order.
10. **Semantic materialization** — record `http_services`, exact parameters,
    actions, objects, ownership relationships, response variables, JS endpoints,
    and normalized interactions.
11. **Review** — show accepted, rejected, sensitive, duplicate, out-of-scope,
    and state-changing counts before any active request is permitted.

## Request parsing requirements

The importer must preserve the contract that reached application logic:

- Query names, repeated keys, blank values, and original encoding.
- Path segments, including candidate object identifiers.
- URL-encoded forms with exact sibling membership.
- JSON scalar types, nested object paths, arrays, `null`, and duplicate-key risk.
- GraphQL operation name, operation type, query document, and variable paths.
- Multipart field names and text values; file bytes are excluded by default and
  represented as metadata placeholders.
- XML element/attribute paths without enabling entity expansion.
- Cookie names and header names as locations, with values kept in the vault.
- Required request headers that affect routing, versioning, content negotiation,
  tenant selection, or CSRF.

The pipeline should distinguish request-body fields from response fields. A
response variable can refresh a later request token, but must not be treated as
an injectable request parameter.

## Workflow and dynamic-value inference

Captured order enables a bounded dataflow graph:

```text
response A: $.csrfToken ──> request B: header X-CSRF-Token
response B: $.project.id ─> request C: path /projects/{project.id}
Set-Cookie response A ────> Cookie request B/C
```

Inference is only a proposal. The UI should show the source and destination,
allow rename/disable, and distinguish secrets from ordinary object variables.
The first implementation should support:

- Exact response JSON scalar to later request JSON/query/path/header value.
- `Set-Cookie` to later `Cookie` by RFC cookie scope.
- HTML hidden input to a later form field.
- CSRF response header to a later request header.

Burp's own session model validates the need for macros, cookie-jar updates,
session validation, and deriving changing parameters from prior responses.^2 The
same concepts fit Reconner's existing workflow variables, but Reconner should
keep inference deterministic and visible rather than silently generating a
large opaque macro.

Before an active test, the replay engine runs a **preflight**:

1. Refresh declared prerequisites.
2. Replay the unmodified baseline once.
3. Require a stable, expected status/content signature.
4. Abort the mutation if the session is expired, CSRF is invalid, a rate-limit
   response appears, or the response no longer resembles the captured baseline.

## Narrow-corpus execution

Add a scan context containing approved request-template IDs. Every hybrid-aware
loader must intersect its normal scope with that set:

```go
ctx = WithCapturedCorpus(ctx, captureSessionID, approvedTemplateIDs)
```

This is stricter than directory-prefix scope. A module receives only exact
captured methods and route shapes. The scanner may mutate one approved insertion
point at a time while retaining the original request's other fields and headers.

The scheduler should expose a `hybrid_guided` task type with this order:

1. Validate identities and capture freshness.
2. Preflight baselines and dynamic variables.
3. Materialize/refine insertion points and objects.
4. Run selected read-only detector modules.
5. Run cross-identity read authorization checks.
6. Run the central verification orchestrator.
7. Produce findings only from class-specific proof; retain all other signals as
   candidates or hypotheses.

Broad subdomain enumeration, directory brute force, port scanning, credential
spraying, race testing, request smuggling, blind stored-XSS planting, and
state-changing workflows are not part of this task type.

## Proof-only policy by vulnerability class

| Class | Automatic hybrid probe | Required finding proof | Forbidden default behavior |
|---|---|---|---|
| Reflected/DOM XSS | Context-specific payload using random title nonce plus `alert('reconner')` | Exact nonce observed after browser execution | Cookie/storage read, callbacks, or data exfiltration |
| SQL injection | Error differential, boolean controls, bounded low-delay timing | Independent stable control pair or verifier confirmation | Data/table extraction, stacked writes, destructive SQL |
| IDOR/BOLA | Owner object replayed as unauthenticated and User B | Protected owner baseline plus User B receiving the same semantic object | Sequential ID enumeration or guessed third-party objects |
| BAC/BFLA | Read-only privileged route under lower role | Stable cross-role differential proving forbidden read/function access | Role change, approval, invite acceptance, delete, purchase, or write |
| SSRF | Unique HTTPS/DNS OAST token or safe parser differential | Token-correlated callback owned by the exact request | Metadata access, internal-port scanning, or credential forwarding |
| SSTI | Arithmetic expressions with independent results | Server-computed markers such as 49 and 64 | File read, command execution, environment extraction |
| Command injection | Arithmetic/echo canary or tokenized DNS callback | Reflection-resistant computed value or exact OAST token | Shell persistence, file changes, command output extraction |
| NoSQL injection | Stable true/false query controls | Reproducible branch differential with volatility/WAF controls | Bulk extraction or write operators |
| XXE | External HTTPS/DNS canary | Exact token-correlated callback | Local file entities or internal network fetches |
| LFI/path traversal | Candidate-only unless a program-approved harmless fixture exists | Known non-sensitive fixture signature with negative controls | Reading system credential/config files |

The table is a mode-specific restriction. Existing advanced modules can remain
available outside Hybrid Guided mode under their existing operator controls, but
the hybrid task must not silently inherit a more aggressive code path.

## Authorization model

Identity must be explicit at capture-session level. A practical workflow is:

1. Create `User A` and import/bind A's history.
2. Create `User B` and import/bind B's history.
3. Optionally create a higher-privilege test identity.
4. Let Reconner correlate endpoint templates and object identifiers across those
   corpora.
5. Auto-verify only reads where A's object is known, unauthenticated access is
   denied, B has no legitimate relationship, and B receives the same object.

Different tokens in the same history must not automatically become different
identities. Tokens rotate, CSRF values change, and a browser may contact several
origins. The researcher-provided label is authoritative; token fingerprints are
used only to warn that an import appears internally inconsistent.

## Burp file-import UX

Add a **Guided Capture** panel to each target:

1. Choose identity: User A, User B, Admin, or unauthenticated.
2. Upload `.har` or Burp `.xml`.
3. Reconner performs a dry-run import and displays:
   - total and in-scope exchanges;
   - unique route/method templates;
   - requests containing authentication material;
   - read-only versus state-changing/unknown requests;
   - bodies omitted or truncated by the source;
   - out-of-scope hosts and rejection reasons;
   - inferred variables and owned object candidates.
4. The researcher selects route groups and modules.
5. `Import only` stores the corpus without traffic.
6. `Run proof-only narrow scan` starts the bounded hybrid task.

The upload endpoint should be multipart and return an import preview before
commit. Suggested API:

```text
POST /api/targets/{id}/captures/preview
POST /api/targets/{id}/captures
GET  /api/targets/{id}/captures
GET  /api/targets/{id}/captures/{captureId}
POST /api/targets/{id}/captures/{captureId}/scan
DELETE /api/targets/{id}/captures/{captureId}/sealed-bodies
```

## Live Burp extension

After file import is stable, build a minimal Java/Kotlin Montoya extension:

- A Reconner URL and one-time pairing token.
- A target/capture-session selector.
- `Send selected items to Reconner` context-menu action.
- Optional `Stream in-scope Proxy traffic` toggle.
- Observation only: return every Burp request/response unchanged.
- Pair final request with final response and preserve Burp reference/order.
- Local encrypted queue with a strict size limit for temporary network failure.
- TLS required except explicit loopback development mode.
- Backpressure and batching; never delay browser traffic waiting for Reconner.
- No scan controls in the extension initially.

Montoya exposes both proxy-specific handlers and broader HTTP handlers.^7 Use the
proxy handlers first so Reconner receives only researcher browsing traffic, not
traffic generated by every Burp tool. The extension can later expose a deliberate
context-menu action for Repeater items.

## Security boundaries

1. **Authentication:** capture APIs require the logged-in Reconner user plus a
   target-scoped capability. Live-extension pairing tokens are one-time, hashed
   at rest, expiring, and revocable.
2. **Authorization:** only target owners/admins may import, reveal, scan, or delete
   a capture.
3. **Scope:** URL host/port and exact corpus membership are checked before storing
   secrets and immediately before each credentialed replay.
4. **Destination:** retain the existing resolve-validate-pin transport and never
   follow credentialed redirects.
5. **Secrets:** encrypt full request/response data; redact previews, evidence,
   logs, WebSocket events, exports, and errors.
6. **Parser safety:** bounded streaming parsers, no XML external entities, no
   archive recursion, no automatic content execution.
7. **Request safety:** strip hop-by-hop headers and recompute length; do not replay
   browser connection headers, proxy authorization, or captured client IP
   spoofing headers by default.
8. **State safety:** unknown and state-changing requests require explicit review
   and remain excluded from automatic mutation.
9. **Operational bounds:** per-host rate limit, template cap, per-request timeout,
   cancellation, retry ceiling, and WAF/rate-limit backoff.
10. **Auditability:** record importer source, operator, identity, decisions,
    rejected reason, replay count, and verifier outcome without secret values.

## Delivery plan

### Phase A — Canonical import foundation

- Add `CapturedExchange` and bounded HAR/Burp XML parsers.
- Add capture-session/request-template/response migrations.
- Implement scope-first dry-run admission.
- Encrypt full blobs and generate redacted previews.
- Add parser fixtures for plain/base64 Burp messages and sanitized/sensitive HAR.

**Exit gate:** importing never sends traffic; out-of-scope exchanges and secrets
cannot enter ordinary logs/tables; malformed inputs cannot crash or exhaust the
service.

### Phase B — Request materialization

- Parse all supported request locations.
- Populate parameters with `request_template_id`.
- Populate interactions, actions, objects, relationships, and variables.
- Add exact corpus deduplication and review counts.

**Exit gate:** a captured JSON/GraphQL/form request reconstructs byte-equivalent
semantics with all required siblings and no cross-request sibling mixing.

### Phase C — Proof-only narrow scan

- Add `hybrid_guided` scheduler task and corpus context.
- Expand replay spec to safe request headers and template-bound bodies.
- Add baseline preflight and session-expiry abort.
- Route XSS, SQLi, SSRF, SSTI, NoSQLi, XXE and read-only authz through their
  existing class verifiers under the hybrid safety policy.

**Exit gate:** only selected captured templates receive traffic; state-changing
requests remain untouched; findings require the existing verified lifecycle.

### Phase D — Multi-identity and workflow refresh

- Correlate A/B owned objects and route templates.
- Infer CSRF/cookie/JSON variable flow with visible provenance.
- Refresh prerequisites and re-run a clean baseline before mutation.
- Add read-only BAC matrices.

**Exit gate:** deterministic two-user labs prove true IDOR/BOLA and reject public,
different-object, expired-session, and stale-token controls.

### Phase E — Product UX and live Burp sync

- Add Guided Capture preview/review UI.
- Add scan selection, progress, evidence, retention, and delete controls.
- Release the thin Montoya collector with pairing and local buffering.

**Exit gate:** file and live inputs produce the same canonical corpus and scanner
results; the extension never modifies or delays Burp traffic.

## Test strategy

### Parser and admission corpus

- Burp XML: raw and base64, absent response, binary body, edited request,
  malformed XML, DTD attempt, oversized item, conflicting host metadata.
- HAR: sanitized and sensitive, repeated headers, POST data, redirects, cached
  response, missing body, base64 content, WebSocket metadata ignored safely.
- Scope: sibling domain, lookalike, port mismatch, scheme change, path boundary,
  redirect, DNS rebinding/private answer.
- Secrets: cookies, bearer/JWT, CSRF, API keys, JSON tokens, Set-Cookie and
  sensitive response data absent from logs/previews.

### Contract fidelity

- Query/form repeated keys and blank values.
- Typed nested JSON and arrays.
- GraphQL query versus mutation.
- Multipart text siblings with file placeholders.
- CSRF refresh from an earlier response.
- Two forms sharing URL/method/content type remain separate templates.

### Safe scanner labs

Every vulnerability class needs:

- one positive fixture;
- one encoded/reflection-only/static control;
- one WAF/rate-limit/volatile control;
- request-contract assertions;
- a request-count ceiling;
- a state snapshot asserting no persistent change.

### Release gates

```bash
go test ./...
go vet ./...
go test -race ./internal/scanner ./internal/api ./internal/scheduler
go test ./internal/scanner -run 'TestHybrid' -count=1 -v
```

Fuzz the HAR/XML/raw-HTTP parsers and the redactor. Add an integration test that
imports both formats for the same traffic and asserts they materialize the same
request templates and insertion points.

## Success metrics

- Percentage of imported in-scope exchanges represented by a valid template.
- Percentage of templates passing clean baseline replay.
- Deep authenticated routes added beyond automated crawl coverage.
- Parameters tested with exact required siblings.
- Two-identity object pairs with known ownership.
- Verified findings per 100 approved templates.
- Candidate-to-verified conversion rate.
- False-positive rate in deterministic controls.
- Zero automatic state-changing requests in proof-only mode.
- Zero secret values in logs, WebSocket events, normal API responses, or reports.

## Immediate implementation recommendation

Start with **Burp XML + HAR upload and dry-run preview**, not the live extension.
This exercises the hardest and most reusable components—canonical modeling,
scope, secrets, parsing, deduplication, and request classification—without adding
pairing, network reliability, or Burp-version concerns. Once both file formats
produce identical canonical records, the Montoya extension becomes a small
transport adapter rather than a second ingestion system.

Do not feed imported items straight into the existing `parameters` table. That
shortcut would lose raw request headers/body, mix sibling fields, duplicate
credentials, and make safe state classification impossible. The request-template
layer is the critical architectural step.

## Sources

1. PortSwigger. [“HTTP history.”](https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history) Burp Suite documentation.
2. PortSwigger. [“Sessions settings.”](https://portswigger.net/burp/documentation/desktop/settings/sessions) and [“Macro editor.”](https://portswigger.net/burp/documentation/desktop/settings/sessions/macros) Burp Suite documentation.
3. OWASP Foundation. [“Testing for Insecure Direct Object References.”](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) Web Security Testing Guide.
4. Chrome for Developers. [“Network features reference — Save all network requests to a HAR file.”](https://developer.chrome.com/docs/devtools/network/reference)
5. PortSwigger. [“Burp Suite message editor — Save item.”](https://portswigger.net/burp/documentation/desktop/tools/message-editor)
6. PortSwigger. [“Creating Burp extensions.”](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating)
7. PortSwigger. [“ProxyRequestHandler.”](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/http/ProxyRequestHandler.html) Montoya API documentation.
8. OWASP Foundation. [“Logging Cheat Sheet — Data to exclude.”](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
9. Chrome DevTools Protocol. [“Network domain.”](https://chromedevtools.github.io/devtools-protocol/1-3/Network/)
10. Microsoft/Playwright. [“BrowserContext.”](https://playwright.dev/docs/api/class-browsercontext)
