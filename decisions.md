# Decisions

## PM Log

### 2026-04-02 -- Initial v1 Story Breakdown

Analyzed the full codebase to determine implemented vs stubbed/missing functionality. Created 12 GitHub issues covering all work needed to reach a working v1.

**Current state summary:**
- Domain types defined but evaluation logic stubbed (assertion engine always returns `Passed: true`)
- Config YAML types exist but no loading, validation, or conversion logic
- Engine report accumulator is functional and thread-safe
- Admin API partially working (health, JSON report, reset) but missing config endpoint, SARIF, and JUnit
- Four packages are empty shells: proxy, decoy, preset, report
- Public embedding API has only a Mode type
- CLI prints version and exits -- no flag parsing, no wiring
- Zero tests in the entire repository
- Dockerfile exists and looks correct

**Issues created (in dependency order):**

| # | Title | Dependencies | Est. Size |
|---|-------|-------------|-----------|
| 1 | Config loading: parse YAML, validate, and convert to domain types | None | 2-3 days |
| 2 | Match evaluation: implement request matching logic | None | 1-2 days |
| 3 | Condition evaluation: implement allow/deny condition checks | #2 | 2-3 days |
| 4 | Preset rule packs: implement built-in assertion sets | #1 | 2-3 days |
| 5 | Decoy endpoint mode: echo server with assertion evaluation | #3 | 1-2 days |
| 6 | Transparent proxy mode: forward traffic with assertion inspection | #3 | 2-3 days |
| 7 | CLI entrypoint: flag parsing, config loading, server wiring, and graceful shutdown | #1, #4, #5, #6 | 2-3 days |
| 8 | Report formatters: SARIF, JUnit XML, and JSON output | #3 | 2-3 days |
| 9 | Admin API: add config endpoint and wire report formatters | #4, #8 | 1-2 days |
| 10 | Public Go API: implement embedding interface in pkg/snitchproxy | #7 | 2-3 days |
| 11 | End-to-end integration tests | #5, #6, #8, #9 | 2-3 days |
| 12 | CI pipeline: GitHub Actions for test, build, and release | #11 | 1-2 days |

**Critical path:** #1 + #2 -> #3 -> #5/#6 -> #7 -> #10

**Parallelizable work:**
- #1 (config) and #2 (match eval) can be done in parallel
- #4 (presets) can start once #1 is done
- #5 (decoy) and #6 (proxy) can be done in parallel after #3
- #8 (report formatters) can be done in parallel with #5/#6

**Open questions:**
1. Should HTTPS body inspection via TLS interception (MITM) be a v1 requirement or deferred to v2? Currently scoped as out-of-scope for #6.
2. Should there be a `go.sum` tracking story or is that expected to happen naturally as dependencies are added?
3. The DSL spec mentions HTML report format -- confirmed deferred, but should we create a v1.1 backlog issue for it?
4. The `ConditionSpec.Value` field is a `string` in the domain type but `StringOrSlice` in the config type (for multi-CIDR `in-cidr`). Need architect to decide how the domain type should handle multi-value conditions.
5. Testcontainers module is mentioned in CLAUDE.md as a separate repo -- confirm this is NOT in scope for snitchproxy v1.

---

## ADR-1: Config loading -- parse YAML, validate, and convert to domain types

**Date:** 2026-04-02
**Issue:** #1
**Status:** READY_FOR_DEV

### Context

The `internal/config` package has YAML struct types (`Config`, `AssertionConfig`, `MatchConfig`, `ConditionConfig`, `StringOrSlice`) but no loading, validation, or conversion logic. Every other component depends on getting a validated `[]assertion.Assertion` from config.

### Decision

#### File layout

- `internal/config/load.go` -- `Load`, `LoadFromBytes`, YAML parsing
- `internal/config/validate.go` -- `Validate` function, validation error collection
- `internal/config/convert.go` -- `ToAssertions` conversion from config types to domain types
- `internal/config/load_test.go` -- tests for Load/LoadFromBytes
- `internal/config/validate_test.go` -- tests for Validate
- `internal/config/convert_test.go` -- tests for ToAssertions

#### Types

```go
// internal/config/validate.go

// ValidationError represents a single validation problem.
type ValidationError struct {
    Field   string // e.g. "assertions[2].deny.condition"
    Message string
}

// ValidationErrors is a collection of validation problems.
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string // implements error; joins all messages
```

#### Functions

```go
// internal/config/load.go

// Load reads a YAML config file from disk and parses it.
func Load(path string) (*Config, error)

// LoadFromBytes parses YAML config from raw bytes.
func LoadFromBytes(data []byte) (*Config, error)
```

```go
// internal/config/validate.go

// Validate checks the parsed config for structural and semantic errors.
// It collects all errors rather than failing fast.
func Validate(cfg *Config) error  // returns nil or ValidationErrors
```

```go
// internal/config/convert.go

// ToAssertions converts validated config assertions into domain types.
// Call Validate first; this function assumes valid input.
func ToAssertions(cfgAssertions []AssertionConfig) []assertion.Assertion
```

#### Sequence

1. Caller invokes `Load(path)` or `LoadFromBytes(data)`.
2. YAML bytes are unmarshalled into `*Config` via `gopkg.in/yaml.v3`.
3. Caller invokes `Validate(cfg)`. Validation checks:
   - Each assertion has a non-empty `name`.
   - Assertion names are unique.
   - Each assertion has exactly one of `deny` or `allow` (not both, not neither).
   - `severity` is one of: `critical`, `high`, `warning`, `info`.
   - `condition` is valid for the given `on` context (see DSL spec).
   - `on` values are one of: `""` (header context), `body`, `query`, `tls`, `source-ip`.
   - `all` blocks are non-empty when present.
   - `pattern` is a valid regex when provided.
4. Caller invokes `ToAssertions(cfg.Assertions)` to get `[]assertion.Assertion`.
5. Defaults applied during conversion: `fail-on` defaults to `high`, `enabled` defaults to `true`.

#### Valid condition names per context

| Context (on) | Valid conditions |
|---|---|
| `""` (header) | `present`, `equals`, `matches`, `not-matches` |
| `body` | `matches`, `contains` |
| `query` | `present`, `matches` |
| `tls` | `version-gte`, `client-cert-present` |
| `source-ip` | `in-cidr` |

#### Error cases

- File not found / unreadable: return `os.PathError`
- Invalid YAML: return yaml unmarshal error
- Validation failures: return `ValidationErrors` with all problems collected
- `ToAssertions` receives invalid input: undefined (caller must validate first)

#### Design decision on multi-value conditions (Open Question #4)

The domain type `ConditionSpec.Value` stays as `string` for simple conditions. Add a `Values []string` field for multi-value conditions like `in-cidr`. During conversion, `StringOrSlice` maps to `Values` when len > 1, or to `Value` when len == 1. The condition evaluator (issue #3) checks `Values` first, falls back to `Value`.

```go
// Addition to assertion.ConditionSpec
type ConditionSpec struct {
    // ... existing fields ...
    Value  string   // single value
    Values []string // multi-value (e.g., multiple CIDRs)
    // ...
}
```

#### Test strategy

- **load_test.go**: Table-driven tests for `Load` (valid file, missing file, invalid YAML) and `LoadFromBytes` (valid bytes, empty bytes, invalid YAML). Use `testdata/` fixtures.
- **validate_test.go**: Table-driven tests for each validation rule. One test case per error type. Test that all errors are collected (send config with multiple errors, verify all are returned).
- **convert_test.go**: Table-driven tests mapping config types to domain types. Verify defaults (`enabled=true`, `fail-on=high`). Verify `StringOrSlice` -> `Value`/`Values` conversion.

---

## ADR-2: Match evaluation -- implement request matching logic

**Date:** 2026-04-02
**Issue:** #2
**Status:** READY_FOR_DEV

### Context

`MatchSpec` is defined in `internal/assertion/assertion.go` but there is no logic to evaluate whether a `*http.Request` matches. This is a prerequisite for condition evaluation.

### Decision

#### File layout

- `internal/assertion/match.go` -- `Matches` function and glob helpers
- `internal/assertion/match_test.go` -- table-driven tests

#### Functions

```go
// internal/assertion/match.go

// Matches reports whether the request matches the given spec.
// A nil spec matches all requests.
func Matches(spec *MatchSpec, r *http.Request) bool

// matchHost checks if the request host matches any of the glob patterns.
func matchHost(patterns []string, host string) bool

// matchPath checks if the request path matches any of the glob patterns (supports **).
func matchPath(patterns []string, path string) bool

// matchMethod checks if the request method matches any of the methods (case-insensitive).
func matchMethod(methods []string, method string) bool

// matchHeaders checks if all specified header patterns match (AND'd).
func matchHeaders(specs map[string]string, headers http.Header) bool

// globMatch performs glob pattern matching with * support (single segment).
func globMatch(pattern, value string) bool

// pathGlobMatch performs glob pattern matching with ** support (multi-segment).
func pathGlobMatch(pattern, path string) bool
```

#### Sequence

1. If `spec` is nil, return `true`.
2. If `spec.Hosts` is non-empty, check host match (OR). If no match, return `false`.
3. If `spec.Paths` is non-empty, check path match (OR). If no match, return `false`.
4. If `spec.Methods` is non-empty, check method match (OR, case-insensitive). If no match, return `false`.
5. If `spec.Headers` is non-empty, check all header patterns (AND). If any fails, return `false`.
6. Return `true`.

#### Glob semantics

- `*` matches any sequence of non-`.` characters in host context (e.g., `*.stripe.com` matches `api.stripe.com` but not `a.b.stripe.com`).
- `*` matches any sequence of non-`/` characters in path context.
- `**` in path context matches zero or more path segments (e.g., `/api/**` matches `/api/v1/users/123`).
- No `**` in host patterns.
- Exact strings are literal match.

#### Implementation note

Use `path.Match` from stdlib for simple glob matching where possible. For `**` support, implement a custom recursive matcher. Do NOT use `filepath.Match` (OS-specific separators).

#### Error cases

None -- `Matches` is a pure boolean predicate. Invalid patterns in config should be caught by validation (ADR-1).

#### Test strategy

Table-driven tests in `match_test.go` covering:
- nil spec (matches everything)
- Single host glob, multiple host globs, no-match host
- Path exact, path with `*`, path with `**`, no-match path
- Single method, multiple methods, case insensitivity
- Header exact match, header glob match, multiple headers AND'd
- Combined fields (host AND path AND method AND header)
- Edge cases: empty host in request, root path, trailing slashes

---

## ADR-3: Condition evaluation -- implement allow/deny condition checks

**Date:** 2026-04-02
**Issue:** #3
**Status:** READY_FOR_DEV

### Context

The `evaluate()` function in `internal/assertion/assertion.go` is stubbed to always return `Passed: true`. All condition types from the DSL spec must be implemented, along with `deny`/`allow` inversion semantics and compound `all` blocks.

### Decision

#### File layout

- `internal/assertion/condition.go` -- condition evaluation functions
- `internal/assertion/condition_test.go` -- table-driven tests
- `internal/assertion/body.go` -- body reading/buffering helper
- `internal/assertion/body_test.go` -- body helper tests

Update `internal/assertion/assertion.go` to fill in `evaluate()`.

#### Types

```go
// internal/assertion/condition.go

// conditionResult holds the outcome of a single condition check.
type conditionResult struct {
    met    bool   // whether the condition was met
    detail string // human-readable explanation
}
```

#### Functions

```go
// internal/assertion/condition.go

// evalCondition evaluates a single ConditionSpec against a request.
func evalCondition(spec *ConditionSpec, r *http.Request) conditionResult

// evalHeaderCondition handles header-based conditions (present, equals, matches, not-matches).
func evalHeaderCondition(spec *ConditionSpec, r *http.Request) conditionResult

// evalBodyCondition handles body-based conditions (matches, contains).
func evalBodyCondition(spec *ConditionSpec, r *http.Request) conditionResult

// evalQueryCondition handles query parameter conditions (present, matches).
func evalQueryCondition(spec *ConditionSpec, r *http.Request) conditionResult

// evalTLSCondition handles TLS conditions (version-gte, client-cert-present).
func evalTLSCondition(spec *ConditionSpec, r *http.Request) conditionResult

// evalSourceIPCondition handles source IP conditions (in-cidr).
func evalSourceIPCondition(spec *ConditionSpec, r *http.Request) conditionResult

// evalAll evaluates a compound all block (AND, short-circuit on first failure).
func evalAll(specs []ConditionSpec, r *http.Request) conditionResult
```

```go
// internal/assertion/body.go

// readBody reads the request body and replaces it with a new reader
// so downstream handlers can still read it.
func readBody(r *http.Request) ([]byte, error)
```

#### Updated evaluate function

```go
// internal/assertion/assertion.go

func evaluate(a Assertion, r *http.Request, requestID string) Result {
    // 1. Check match scope
    if !Matches(a.Match, r) {
        return Result{Assertion: a.Name, Passed: true} // not in scope, auto-pass
    }

    // 2. Evaluate condition
    var cond *ConditionSpec
    var isDeny bool
    if a.Deny != nil {
        cond = a.Deny
        isDeny = true
    } else {
        cond = a.Allow
        isDeny = false
    }

    cr := evalCondition(cond, r)

    // 3. Apply deny/allow semantics
    var violated bool
    if isDeny {
        violated = cr.met   // deny: condition true = violation
    } else {
        violated = !cr.met  // allow: condition false = violation
    }

    if violated {
        return Result{
            Assertion: a.Name,
            Passed:    false,
            Violation: &Violation{
                Assertion:   a.Name,
                Description: a.Description,
                Severity:    a.Severity,
                Detail:      cr.detail,
                RequestID:   requestID,
            },
        }
    }
    return Result{Assertion: a.Name, Passed: true}
}
```

#### Body buffering

`readBody` uses `io.ReadAll` to consume the body, then replaces `r.Body` with `io.NopCloser(bytes.NewReader(data))` so downstream handlers (proxy forwarding, decoy echo) can re-read it. The body bytes should be cached per-request to avoid re-reading for multiple body conditions.

Strategy: read body once on first body condition, store in a `sync.OnceValue`-style closure or just read eagerly at the start of `evaluate()` only if any condition references body. Simpler approach: read body at the start of evaluate if any condition has `On == "body"`, stash the bytes, and use them for all body conditions.

#### Condition logic summary

| Context | Condition | Logic |
|---|---|---|
| header | `present` | `r.Header.Get(header) != ""` |
| header | `equals` | `r.Header.Get(header) == value` |
| header | `matches` | `regexp.MatchString(pattern, r.Header.Get(header))` |
| header | `not-matches` | `!regexp.MatchString(pattern, r.Header.Get(header))` |
| body | `matches` | `regexp.Match(pattern, bodyBytes)` |
| body | `contains` | `bytes.Contains(bodyBytes, []byte(value))` |
| query | `present` | `r.URL.Query().Has(param)` |
| query | `matches` | `regexp.MatchString(pattern, r.URL.Query().Get(param))` |
| tls | `version-gte` | `r.TLS != nil && r.TLS.Version >= tlsVersionNumber(value)` |
| tls | `client-cert-present` | `r.TLS != nil && len(r.TLS.PeerCertificates) > 0` |
| source-ip | `in-cidr` | Parse remote addr, check against CIDR(s) via `net.ParseCIDR` |

#### Error cases

- Regex compilation failure: return `conditionResult{met: false, detail: "invalid regex: ..."}`. This should ideally be caught at validation time (ADR-1), but defend here too.
- Body read failure: return `conditionResult{met: false, detail: "failed to read body: ..."}`.
- Invalid CIDR: return `conditionResult{met: false, detail: "invalid CIDR: ..."}`.
- Missing TLS info: `r.TLS == nil` means TLS conditions about version/cert fail (condition not met).

#### Test strategy

Table-driven tests in `condition_test.go` covering:
- Each condition type in both `deny` and `allow` mode
- Compound `all` block with all-pass, first-fail, last-fail
- Body buffering: verify body can still be read after evaluation
- TLS conditions with nil `r.TLS` and populated `r.TLS`
- Source IP with valid/invalid CIDR, IPv4 and IPv6
- Edge cases: empty body, missing header, missing query param

---

## ADR-4: Preset rule packs -- implement built-in assertion sets

**Date:** 2026-04-02
**Issue:** #4
**Status:** READY_FOR_DEV

### Context

The `internal/preset` package is empty. Six presets are specified in the DSL spec. Presets expand into `[]assertion.Assertion` and can be overridden by user assertions with matching names.

### Decision

#### File layout

- `internal/preset/preset.go` -- `Expand` function, registry, merge logic
- `internal/preset/pci_dss.go` -- PCI-DSS preset rules
- `internal/preset/aws_keys.go` -- AWS keys preset rules
- `internal/preset/common_auth.go` -- common auth preset rules
- `internal/preset/pii.go` -- PII preset rules
- `internal/preset/gcp_keys.go` -- GCP keys preset rules
- `internal/preset/private_net.go` -- private network preset rules
- `internal/preset/preset_test.go` -- tests

#### Types

```go
// internal/preset/preset.go

// registry maps preset names to their assertion-generating functions.
var registry = map[string]func() []assertion.Assertion{
    "pci-dss":     pciDSS,
    "aws-keys":    awsKeys,
    "common-auth": commonAuth,
    "pii":         pii,
    "gcp-keys":    gcpKeys,
    "private-net": privateNet,
}
```

Note: this is a package-level var but it is immutable after init (populated at compile time with function references) -- no `init()` function, no mutation. This is acceptable.

#### Functions

```go
// internal/preset/preset.go

// Expand returns all assertions for the named presets.
// Returns an error if any preset name is unknown.
func Expand(names []string) ([]assertion.Assertion, error)

// Merge combines preset assertions with user assertions.
// User assertions whose name matches a preset assertion (e.g., "pci-dss/credit-card-in-body")
// override the preset version. If the user assertion sets enabled=false, the preset rule is removed.
// Non-matching user assertions are appended.
func Merge(presetAssertions, userAssertions []assertion.Assertion) []assertion.Assertion
```

Each preset file exports a package-private function:

```go
// internal/preset/pci_dss.go
func pciDSS() []assertion.Assertion

// internal/preset/aws_keys.go
func awsKeys() []assertion.Assertion

// ... etc.
```

#### Preset rule naming convention

All preset rules use the format `<preset-name>/<rule-name>`, e.g.:
- `pci-dss/credit-card-in-body`
- `pci-dss/credit-card-in-query`
- `pci-dss/track-data-in-body`
- `pci-dss/cvv-in-body`
- `aws-keys/access-key-in-body`
- `aws-keys/access-key-in-query`
- `aws-keys/secret-key-in-body`
- `aws-keys/sts-token-in-body`
- `common-auth/authorization-header`
- `common-auth/cookie-header`
- `common-auth/x-api-key-header`
- `common-auth/bearer-in-body`
- `common-auth/set-cookie-header`
- `pii/ssn-in-body`
- `pii/email-in-body`
- `pii/phone-in-body`
- `pii/dob-in-body`
- `gcp-keys/api-key-in-body`
- `gcp-keys/api-key-in-query`
- `gcp-keys/service-account-in-body`
- `private-net/rfc1918-in-x-forwarded-for`
- `private-net/rfc1918-in-x-real-ip`
- `private-net/rfc1918-in-host`

#### Merge sequence

1. Build a map of preset assertions keyed by name.
2. For each user assertion:
   a. If its name matches a preset assertion name and `Enabled == false`, delete from preset map.
   b. If its name matches a preset assertion name and `Enabled == true`, replace in preset map (override severity, match, conditions).
   c. If its name does not match any preset, add to an append list.
3. Collect remaining preset assertions (in stable order) + append list.

#### Integration with config loading

The caller (CLI or public API) calls:
1. `config.Load(path)` -> `*config.Config`
2. `config.Validate(cfg)` -> check for errors
3. `preset.Expand(cfg.Presets)` -> `[]assertion.Assertion`
4. `config.ToAssertions(cfg.Assertions)` -> `[]assertion.Assertion`
5. `preset.Merge(presetAssertions, userAssertions)` -> final `[]assertion.Assertion`
6. `assertion.NewEngine(merged)` -> `*assertion.Engine`

#### Error cases

- Unknown preset name: return `fmt.Errorf("unknown preset: %q", name)`
- Duplicate preset names in input: deduplicate silently

#### Test strategy

- Test `Expand` with valid names, unknown name, empty list, duplicates.
- Test `Merge`: override severity, override match, disable rule, non-matching user assertions appended, ordering is stable.
- Test each preset function returns non-empty assertions with correct naming convention.

---

## ADR-5: Decoy endpoint mode -- echo server with assertion evaluation

**Date:** 2026-04-02
**Issue:** #5
**Status:** READY_FOR_DEV

### Context

The `internal/decoy` package is empty. Decoy mode is a fake external API that echoes requests back while evaluating them against assertions.

### Decision

#### File layout

- `internal/decoy/handler.go` -- HTTP handler
- `internal/decoy/handler_test.go` -- tests

#### Types

```go
// internal/decoy/handler.go

// EchoResponse is the JSON response returned by the decoy endpoint.
type EchoResponse struct {
    RequestID string              `json:"request_id"`
    Method    string              `json:"method"`
    Path      string              `json:"path"`
    Headers   map[string][]string `json:"headers"`
    Body      string              `json:"body"`
    Query     map[string][]string `json:"query,omitempty"`
}
```

#### Interfaces consumed (defined in this package)

```go
// internal/decoy/handler.go

// Evaluator runs assertions against a request.
type Evaluator interface {
    Evaluate(r *http.Request, requestID string) []assertion.Result
}

// Recorder stores assertion results.
type Recorder interface {
    Record(results []assertion.Result)
}
```

#### Functions

```go
// internal/decoy/handler.go

// Option configures a Handler.
type Option func(*Handler)

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option

// Handler returns an http.Handler that echoes requests and evaluates assertions.
type Handler struct {
    evaluator Evaluator
    recorder  Recorder
    logger    *slog.Logger
}

// NewHandler creates a decoy handler.
func NewHandler(evaluator Evaluator, recorder Recorder, opts ...Option) *Handler

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

#### Sequence

1. Generate a unique request ID (`fmt.Sprintf("req_%d", atomic counter)` or `uuid`-style -- use `crypto/rand` hex for simplicity, or a simple atomic counter).
2. Read request body (buffer it).
3. Call `evaluator.Evaluate(r, requestID)` to run assertions.
4. Call `recorder.Record(results)` to store results.
5. Log request details and violation count via `slog`.
6. Build `EchoResponse` with method, path, headers, body, query.
7. Write JSON response with `200 OK`.

#### Request ID generation

Use an atomic counter for simplicity: `atomic.AddUint64(&counter, 1)` formatted as `"req-<number>"`. This is lightweight and sufficient for testing scenarios.

#### Error cases

- Body read failure: log error, return 500 with error message.
- JSON encoding failure: log error, return 500 (extremely unlikely).

#### Test strategy

- Use `httptest.NewRecorder` and `httptest.NewRequest`.
- Test echo response contains correct method, path, headers, body.
- Test that assertion engine `Evaluate` is called (use a mock/stub evaluator).
- Test that violations are recorded (use a mock/stub recorder).
- Test request ID is unique across requests.

---

## ADR-6: Transparent proxy mode -- forward traffic with assertion inspection

**Date:** 2026-04-02
**Issue:** #6
**Status:** READY_FOR_DEV

### Context

The `internal/proxy` package is empty. Proxy mode forwards traffic to real destinations while inspecting it against assertions.

### Decision

#### File layout

- `internal/proxy/handler.go` -- HTTP proxy handler
- `internal/proxy/handler_test.go` -- tests

#### Interfaces consumed (defined in this package)

```go
// internal/proxy/handler.go

// Evaluator runs assertions against a request.
type Evaluator interface {
    Evaluate(r *http.Request, requestID string) []assertion.Result
}

// Recorder stores assertion results.
type Recorder interface {
    Record(results []assertion.Result)
}
```

#### Types and functions

```go
// internal/proxy/handler.go

// Option configures a Handler.
type Option func(*Handler)

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option

// WithTransport sets the HTTP transport for upstream requests.
func WithTransport(transport http.RoundTripper) Option

// Handler is an HTTP forward proxy that inspects traffic.
type Handler struct {
    evaluator Evaluator
    recorder  Recorder
    logger    *slog.Logger
    transport http.RoundTripper
}

// NewHandler creates a proxy handler.
func NewHandler(evaluator Evaluator, recorder Recorder, opts ...Option) *Handler

// ServeHTTP implements http.Handler.
// Handles both plain HTTP proxy requests and CONNECT tunneling.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

#### Sequence -- plain HTTP proxy

1. Generate request ID.
2. Read and buffer request body (for assertion evaluation).
3. Call `evaluator.Evaluate(r, requestID)`.
4. Call `recorder.Record(results)`.
5. Log request details.
6. Forward request to destination using `httputil.ReverseProxy` or direct `http.Transport.RoundTrip`.
7. Copy response back to client.

For plain HTTP proxy requests, the request URL is absolute (e.g., `GET http://example.com/path HTTP/1.1`). Use `httputil.NewSingleHostReverseProxy` is not appropriate since the host varies. Instead, use a custom `http.RoundTripper`-based approach:

```go
// For plain HTTP proxy:
// 1. The request comes in with an absolute URL.
// 2. Evaluate assertions against the request.
// 3. Forward using h.transport.RoundTrip(outReq).
// 4. Copy response headers and body back.
```

#### Sequence -- CONNECT tunneling (HTTPS)

1. Generate request ID.
2. Evaluate assertions against the CONNECT request (host, method=CONNECT; no body inspection for v1).
3. Record results.
4. Respond with `200 Connection Established`.
5. Hijack the connection (`http.Hijacker`).
6. Dial the target host.
7. Bidirectional copy between client and target using `io.Copy` in goroutines.

Note: In CONNECT mode, we can only inspect the CONNECT request metadata (host, port). Actual HTTPS body inspection requires TLS MITM, which is out of scope for v1.

#### Error cases

- Upstream connection failure: return `502 Bad Gateway` with error detail.
- Upstream timeout: return `504 Gateway Timeout`.
- Hijack failure (for CONNECT): return `500 Internal Server Error`.
- Body read failure: log and proceed (still forward the request).

#### Test strategy

- **Plain HTTP proxy**: Use `httptest.NewServer` as upstream. Create proxy handler, send request through it, verify response matches upstream, verify assertions were evaluated.
- **CONNECT tunneling**: Harder to test. Use a test that dials through the proxy to an `httptest.NewTLSServer`. Verify CONNECT assertion evaluation.
- **Error cases**: Upstream that returns errors, upstream that is unreachable.
- Mock `Evaluator` and `Recorder` to verify they are called.

---

## ADR-7: CLI entrypoint -- flag parsing, config loading, server wiring, and graceful shutdown

**Date:** 2026-04-02
**Issue:** #7
**Status:** READY_FOR_DEV

### Context

`cmd/snitchproxy/main.go` currently prints version and exits. It needs flag parsing, config loading, server wiring, and graceful shutdown.

### Decision

#### File layout

- `cmd/snitchproxy/main.go` -- `main()` and `run()` (updated)
- `cmd/snitchproxy/flags.go` -- flag parsing into a config struct
- `cmd/snitchproxy/flags_test.go` -- flag parsing tests

#### Types

```go
// cmd/snitchproxy/flags.go

// cliFlags holds parsed command-line arguments.
type cliFlags struct {
    mode       string // "proxy" or "decoy"
    configPath string // path to config file
    listenAddr string // e.g. ":8080"
    adminAddr  string // e.g. ":9484"
    failOn     string // severity override, empty means use config value
    version    bool   // print version and exit
}
```

#### Functions

```go
// cmd/snitchproxy/flags.go

// parseFlags parses CLI flags from the given args.
// Uses the standard library flag package.
func parseFlags(args []string) (cliFlags, error)
```

```go
// cmd/snitchproxy/main.go

// run is the main logic, separated from main() for testability.
func run(args []string) error
```

#### Sequence

1. `parseFlags(args)` -- parse `--mode`, `--config`, `--listen`, `--admin`, `--fail-on`, `--version`.
2. If `--version`, print version and return.
3. Resolve config source: `--config` flag, or `SNITCHPROXY_CONFIG` env var. If env var value does not look like a file path (no `.yaml`/`.yml` extension and contains newlines), treat as inline YAML and use `LoadFromBytes`; otherwise use `Load`.
4. `config.Validate(cfg)` -- if errors, print all and return error.
5. `preset.Expand(cfg.Presets)` -- expand presets.
6. `config.ToAssertions(cfg.Assertions)` -- convert user assertions.
7. `preset.Merge(presetAssertions, userAssertions)` -- merge.
8. Apply `--fail-on` override if set.
9. `assertion.NewEngine(merged)` -- create engine.
10. `engine.NewReport()` -- create report.
11. Create mode handler (decoy or proxy) with engine and report.
12. `admin.Handler(report, logger)` -- create admin handler (with resolved assertions for config endpoint).
13. Start mode server on `--listen` addr.
14. Start admin server on `--admin` addr.
15. Log startup info (mode, listen addr, admin addr, assertion count).
16. Wait for SIGTERM/SIGINT via `signal.NotifyContext`.
17. On signal: shut down both servers with timeout (e.g., 10 seconds).
18. Log final violation summary.
19. If `report.HasViolationsAtOrAbove(failOnThreshold)`, return a non-nil error (causes exit code 1).

#### Flag defaults

| Flag | Default | Required |
|---|---|---|
| `--mode` | (none) | Yes |
| `--config` | (none) | Yes, unless `SNITCHPROXY_CONFIG` env is set |
| `--listen` | `:8080` | No |
| `--admin` | `:9484` | No |
| `--fail-on` | (none, use config) | No |
| `--version` | `false` | No |

#### Error cases

- Missing required flags: return descriptive error.
- Config load/validation failure: print all validation errors to stderr, return error.
- Port bind failure: return error with addr info.
- Shutdown timeout: force close after timeout, log warning.

#### Test strategy

- `flags_test.go`: Table-driven tests for flag parsing (all flags, defaults, missing required flags, invalid values).
- `run()` is hard to unit test fully but can be tested with a quick start-then-signal integration test using `:0` ports.

---

## ADR-8: Report formatters -- SARIF, JUnit XML, and JSON output

**Date:** 2026-04-02
**Issue:** #8
**Status:** READY_FOR_DEV

### Context

The `internal/report` package is empty. Three output formats are needed: JSON, SARIF v2.1.0, and JUnit XML. The admin handler currently inlines JSON output -- this should move to the report package.

### Decision

#### File layout

- `internal/report/json.go` -- JSON formatter
- `internal/report/sarif.go` -- SARIF formatter with types
- `internal/report/junit.go` -- JUnit XML formatter with types
- `internal/report/json_test.go` -- tests
- `internal/report/sarif_test.go` -- tests
- `internal/report/junit_test.go` -- tests
- `testdata/report_golden_json.json` -- golden file
- `testdata/report_golden_sarif.json` -- golden file
- `testdata/report_golden_junit.xml` -- golden file

#### Types

```go
// internal/report/json.go

// JSONReport is the top-level JSON report structure.
type JSONReport struct {
    TotalEvaluations int                  `json:"total_evaluations"`
    ViolationCount   int                  `json:"violation_count"`
    Violations       []assertion.Violation `json:"violations"`
}
```

```go
// internal/report/sarif.go

// SARIF v2.1.0 types (only what we need, not the full spec).

type SARIFReport struct {
    Schema  string     `json:"$schema"`
    Version string     `json:"version"`
    Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
    Tool    SARIFTool     `json:"tool"`
    Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
    Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
    Name           string          `json:"name"`
    Version        string          `json:"version"`
    InformationURI string          `json:"informationUri"`
    Rules          []SARIFRule     `json:"rules"`
}

type SARIFRule struct {
    ID               string             `json:"id"`
    ShortDescription SARIFMessage       `json:"shortDescription"`
    DefaultConfig    SARIFDefaultConfig `json:"defaultConfiguration"`
}

type SARIFDefaultConfig struct {
    Level string `json:"level"`
}

type SARIFMessage struct {
    Text string `json:"text"`
}

type SARIFResult struct {
    RuleID  string       `json:"ruleId"`
    Level   string       `json:"level"`
    Message SARIFMessage `json:"message"`
}
```

```go
// internal/report/junit.go

// JUnit XML types.

type JUnitTestSuites struct {
    XMLName xml.Name         `xml:"testsuites"`
    Suites  []JUnitTestSuite `xml:"testsuite"`
}

type JUnitTestSuite struct {
    Name     string          `xml:"name,attr"`
    Tests    int             `xml:"tests,attr"`
    Failures int             `xml:"failures,attr"`
    Cases    []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
    Name      string        `xml:"name,attr"`
    ClassName string        `xml:"classname,attr"`
    Failure   *JUnitFailure `xml:"failure,omitempty"`
}

type JUnitFailure struct {
    Message string `xml:"message,attr"`
    Type    string `xml:"type,attr"`
    Text    string `xml:",chardata"`
}
```

#### Functions

```go
// internal/report/json.go
func FormatJSON(violations []assertion.Violation, totalEvaluations int) ([]byte, error)

// internal/report/sarif.go
func FormatSARIF(violations []assertion.Violation, totalEvaluations int) ([]byte, error)

// internal/report/junit.go
func FormatJUnit(violations []assertion.Violation, totalEvaluations int) ([]byte, error)
```

#### SARIF severity mapping

| assertion.Severity | SARIF level |
|---|---|
| `critical` | `error` |
| `high` | `error` |
| `warning` | `warning` |
| `info` | `note` |

#### JUnit mapping

- One test suite named `"snitchproxy"`.
- Each unique assertion name becomes a test case.
- Violated assertions have a `<failure>` element with the violation detail.
- Passed assertions (evaluated but no violation) are passing test cases.
- `tests` = total unique assertion names evaluated, `failures` = count of violated.

#### Error cases

- JSON/XML encoding failure: return error (extremely unlikely with valid Go types).

#### Test strategy

- Golden file tests: create a fixed set of violations, run each formatter, compare output to golden files in `testdata/`.
- Use `go test -update` flag pattern (or a test helper) to regenerate golden files.
- Validate SARIF output structure (schema, version, required fields).
- Validate JUnit XML is well-formed.

---

## ADR-9: Admin API -- add config endpoint and wire report formatters

**Date:** 2026-04-02
**Issue:** #9
**Status:** READY_FOR_DEV

### Context

The admin API needs a `/__snitchproxy/config` endpoint showing the resolved config, and the report endpoint needs to delegate to the report package formatters instead of returning 501.

### Decision

#### File layout

- `internal/admin/admin.go` -- updated Handler function
- `internal/admin/admin_test.go` -- tests

#### Updated Handler signature

The `Handler` function needs access to the resolved assertions (for the config endpoint) and the report formatters. Update the signature:

```go
// internal/admin/admin.go

// Handler creates the admin API HTTP handler.
func Handler(report *engine.Report, assertions []assertion.Assertion, logger *slog.Logger) http.Handler
```

The additional `assertions` parameter provides the fully resolved assertion list (presets expanded, overrides applied) for the config endpoint.

#### New config endpoint

```go
// GET /__snitchproxy/config
// Returns JSON array of resolved assertions.
mux.HandleFunc(pathPrefix+"/config", func(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(assertions)
})
```

#### Updated report endpoint

Replace the inline JSON and 501 stubs with calls to report formatters:

```go
mux.HandleFunc(pathPrefix+"/report", func(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    violations := report.Violations()
    total := report.TotalEvaluations()

    format := r.URL.Query().Get("format")
    switch format {
    case "sarif":
        data, err := reportpkg.FormatSARIF(violations, total)
        // handle err, write data with Content-Type: application/json
    case "junit":
        data, err := reportpkg.FormatJUnit(violations, total)
        // handle err, write data with Content-Type: application/xml
    default:
        data, err := reportpkg.FormatJSON(violations, total)
        // handle err, write data with Content-Type: application/json
    }
})
```

Import alias: `reportpkg "github.com/vibewarden/snitchproxy/internal/report"` to avoid collision with the `report *engine.Report` parameter.

#### Assertion JSON representation

The `assertion.Assertion` type needs JSON tags for serialization in the config endpoint. Add JSON tags to `Assertion`, `MatchSpec`, and `ConditionSpec` in `internal/assertion/assertion.go`:

```go
type Assertion struct {
    Name        string         `json:"name"`
    Description string         `json:"description"`
    Severity    Severity       `json:"severity"`
    Enabled     bool           `json:"enabled"`
    Match       *MatchSpec     `json:"match,omitempty"`
    Deny        *ConditionSpec `json:"deny,omitempty"`
    Allow       *ConditionSpec `json:"allow,omitempty"`
}

// Similarly for MatchSpec and ConditionSpec fields.
```

#### Error cases

- Report format error: return 500 with error message (should not happen in practice).
- Config endpoint with non-GET: return 405.

#### Test strategy

- `admin_test.go`: Use `httptest.NewRecorder` for each endpoint.
- Test config endpoint returns resolved assertions as JSON.
- Test report endpoint with each format parameter.
- Test report endpoint with violations present and empty.
- Test health and reset endpoints still work.
- Test method-not-allowed on all endpoints.

---

## ADR-10: Public Go API -- implement embedding interface in pkg/snitchproxy

**Date:** 2026-04-02
**Issue:** #10
**Status:** READY_FOR_DEV

### Context

`pkg/snitchproxy` only has a `Mode` type. It needs to be the public API surface for embedding snitchproxy in Go test suites.

### Decision

#### File layout

- `pkg/snitchproxy/snitchproxy.go` -- updated with full API
- `pkg/snitchproxy/options.go` -- functional options
- `pkg/snitchproxy/snitchproxy_test.go` -- tests

#### Types

```go
// pkg/snitchproxy/snitchproxy.go

// SnitchProxy is an embedded snitchproxy instance.
type SnitchProxy struct {
    cfg         *config.Config
    assertions  []assertion.Assertion
    engine      *assertion.Engine
    report      *enginepkg.Report
    failOn      assertion.Severity
    mode        Mode
    listenAddr  string
    adminAddr   string
    modeServer  *http.Server
    adminServer *http.Server
    logger      *slog.Logger
}
```

#### Functions

```go
// pkg/snitchproxy/snitchproxy.go

// New creates a configured SnitchProxy instance.
func New(opts ...Option) (*SnitchProxy, error)

// Start starts the mode server and admin server.
// Use ctx for cancellation.
func (sp *SnitchProxy) Start(ctx context.Context) error

// Close performs graceful shutdown of both servers.
func (sp *SnitchProxy) Close() error

// Violations returns all recorded violations.
func (sp *SnitchProxy) Violations() []assertion.Violation

// HasViolations reports whether any violation meets or exceeds the threshold.
func (sp *SnitchProxy) HasViolations(severity assertion.Severity) bool

// Reset clears all collected violations.
func (sp *SnitchProxy) Reset()

// ListenAddr returns the actual address the mode server is listening on.
// Useful when configured with ":0" for OS-assigned ports.
func (sp *SnitchProxy) ListenAddr() string

// AdminAddr returns the actual address the admin server is listening on.
func (sp *SnitchProxy) AdminAddr() string
```

```go
// pkg/snitchproxy/options.go

// Option configures a SnitchProxy instance.
type Option func(*options)

type options struct {
    configFile string
    configData []byte
    mode       Mode
    listenAddr string
    adminAddr  string
    failOn     string
    logger     *slog.Logger
}

func WithConfigFile(path string) Option
func WithConfigBytes(data []byte) Option
func WithMode(mode Mode) Option
func WithListenAddr(addr string) Option
func WithAdminAddr(addr string) Option
func WithFailOn(severity string) Option
func WithLogger(logger *slog.Logger) Option
```

#### Sequence

1. `New(opts...)`: apply options, load config (from file or bytes), validate, expand presets, merge, create engine and report. Return error if config is invalid.
2. `Start(ctx)`: create `net.Listener` for both ports (to capture actual addr), create mode handler and admin handler, start serving in goroutines. Return error if listeners fail.
3. `Close()`: call `modeServer.Shutdown(ctx)` and `adminServer.Shutdown(ctx)`.

#### Design note on address capture

To support `:0` ports, use `net.Listen("tcp", addr)` to get the listener, then `listener.Addr().String()` to get the actual address. Pass the listener to `http.Server.Serve(listener)`.

#### Error cases

- No config provided: return error from `New`.
- Invalid config: return validation errors from `New`.
- Port bind failure: return error from `Start`.
- Double-start: return error if already started.

#### Test strategy

- Test option application (each option sets the expected field).
- Test `New` with valid config file, invalid config, missing config.
- Integration test: `New` + `Start` with `:0` ports, send a request to decoy, verify `Violations()` returns expected results, `Close()`.

---

## ADR-11: End-to-end integration tests

**Date:** 2026-04-02
**Issue:** #11
**Status:** READY_FOR_DEV

### Context

Zero tests exist in the repository. Integration tests are needed to validate the full request lifecycle.

### Decision

#### File layout

- `internal/integration_test.go` -- integration tests (in an `internal` build-tag or just `_test.go` convention)

Actually, since these tests exercise multiple packages, place them in a dedicated test package:

- `test/integration/decoy_test.go` -- decoy mode integration tests
- `test/integration/proxy_test.go` -- proxy mode integration tests
- `test/integration/preset_test.go` -- preset integration tests
- `test/integration/admin_test.go` -- admin API integration tests
- `test/integration/failon_test.go` -- fail-on threshold tests
- `test/integration/helpers_test.go` -- shared test helpers

All files use `package integration_test` (external test package).

#### Test helper

```go
// test/integration/helpers_test.go

// startDecoy creates and starts a snitchproxy in decoy mode with the given config YAML.
// Returns the SnitchProxy instance (for cleanup) and the base URL.
func startDecoy(t *testing.T, configYAML string) (*snitchproxy.SnitchProxy, string)

// startProxy creates and starts a snitchproxy in proxy mode with the given config YAML.
// Returns the SnitchProxy instance and the proxy URL.
func startProxy(t *testing.T, configYAML string) (*snitchproxy.SnitchProxy, string)

// startBackend creates a test HTTP server that records requests.
func startBackend(t *testing.T) *httptest.Server
```

These helpers use `pkg/snitchproxy` with `WithConfigBytes`, `WithMode`, `WithListenAddr(":0")`, `WithAdminAddr(":0")`, and `t.Cleanup` for shutdown.

#### Test cases

**decoy_test.go:**
1. Send request with Authorization header to decoy, config denies it -> verify violation recorded.
2. Send request that does not match any assertion -> verify no violations.
3. Send request with body matching regex pattern -> verify body condition violation.
4. Multiple requests -> verify all violations accumulated.

**proxy_test.go:**
1. Send HTTP request through proxy to test backend -> verify response is correct AND assertion evaluated.
2. Send request that triggers violation through proxy -> verify violation recorded and request still forwarded.

**preset_test.go:**
1. Load config with `aws-keys` preset, send request with `AKIA...` in body -> verify violation.
2. Load config with `pci-dss` preset, send request with credit card number in body -> verify violation.
3. Override preset rule severity, verify override applied.

**admin_test.go:**
1. Start decoy, send violating traffic, GET `/report` -> verify JSON report.
2. GET `/report?format=sarif` -> verify SARIF output.
3. GET `/report?format=junit` -> verify JUnit output.
4. POST `/reset` -> verify report cleared.
5. GET `/config` -> verify resolved assertions returned.

**failon_test.go:**
1. Config with `fail-on: high`, only `warning` violations -> `HasViolations("high")` returns false.
2. Config with `fail-on: warning`, `warning` violations -> `HasViolations("warning")` returns true.

#### Error cases

- Tests should verify that requests to unreachable backends through proxy return appropriate error responses.

#### Test strategy

All tests use `httptest` servers and in-process snitchproxy via `pkg/snitchproxy`. No Docker required. Tests are run with `go test ./test/integration/...`.

---

## ADR-12: CI pipeline -- GitHub Actions for test, build, and release

**Date:** 2026-04-02
**Issue:** #12
**Status:** READY_FOR_DEV

### Context

No CI/CD pipeline exists. Need GitHub Actions for testing, building, and releasing.

### Decision

#### File layout

- `.github/workflows/ci.yml` -- CI workflow (test, vet, lint, build)
- `.github/workflows/release.yml` -- release workflow (goreleaser)
- `.goreleaser.yml` -- goreleaser config

#### CI workflow (ci.yml)

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache: true
      - run: go vet ./...
      - run: go test -race -count=1 ./...

  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        goos: [linux, darwin, windows]
        goarch: [amd64, arm64]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache: true
      - run: CGO_ENABLED=0 GOOS=${{ matrix.goos }} GOARCH=${{ matrix.goarch }} go build -o /dev/null ./cmd/snitchproxy
      - name: Check binary size (linux/amd64 only)
        if: matrix.goos == 'linux' && matrix.goarch == 'amd64'
        run: |
          CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o snitchproxy ./cmd/snitchproxy
          SIZE=$(stat --format=%s snitchproxy)
          echo "Binary size: $SIZE bytes"
          if [ "$SIZE" -gt 15728640 ]; then
            echo "::warning::Binary exceeds 15MB target ($SIZE bytes)"
          fi

  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t snitchproxy:ci .
```

#### Release workflow (release.yml)

```yaml
name: Release
on:
  push:
    tags: ['v*']

permissions:
  contents: write
  packages: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache: true
      - uses: goreleaser/goreleaser-action@v5
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### Goreleaser config (.goreleaser.yml)

```yaml
builds:
  - main: ./cmd/snitchproxy
    binary: snitchproxy
    env:
      - CGO_ENABLED=0
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
    ldflags:
      - -s -w -X main.version={{.Version}}

dockers:
  - image_templates:
      - "ghcr.io/vibewarden/snitchproxy:{{ .Tag }}"
      - "ghcr.io/vibewarden/snitchproxy:latest"
    dockerfile: Dockerfile
    build_flag_templates:
      - "--label=org.opencontainers.image.version={{.Version}}"

archives:
  - format: tar.gz
    format_overrides:
      - goos: windows
        format: zip

changelog:
  sort: asc
  filters:
    exclude:
      - '^docs:'
      - '^test:'
```

#### Error cases

- CI failures block PR merge (documented recommendation for branch protection).
- Release failures: goreleaser handles retry/cleanup.

#### Test strategy

- The CI workflow itself is the test -- verify it runs `go test`, `go vet`, builds for all platforms, and builds Docker.
- Manual verification of release workflow on first tag push.
