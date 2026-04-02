# CLAUDE.md — Project Conventions for SnitchProxy

## What is SnitchProxy?

SnitchProxy is a dual-mode egress security testing tool:

1. **Decoy endpoint mode**: A fake external API that echoes requests and evaluates them against security assertions (like httpbin with teeth).
2. **Transparent proxy mode**: An inline proxy between your app and real external APIs that inspects all traffic flowing through (like Toxiproxy but for security assertions instead of fault injection).

It catches credential leaks, PII exposure, and policy violations in outbound HTTP traffic. It pairs with VibeWarden (the egress proxy) and httptape (the request recorder) as part of the vibewarden ecosystem.

**Distribution**: Single Go binary, minimal Docker image, Testcontainers module.

## Repository

- **GitHub**: `github.com/vibewarden/snitchproxy`
- **License**: Apache 2.0

## Language & Runtime

- **Go 1.22+** (use latest stable)
- Module path: `github.com/vibewarden/snitchproxy`
- Target: Linux, macOS, Windows (single static binary via `CGO_ENABLED=0`)

## Project Structure

```
snitchproxy/
├── cmd/
│   └── snitchproxy/          # CLI entrypoint (main.go)
├── internal/
│   ├── config/                # YAML config parsing & validation
│   ├── assertion/             # Assertion engine (match, evaluate, compound)
│   ├── preset/                # Built-in rule packs (pci-dss, aws-keys, etc.)
│   ├── proxy/                 # Transparent proxy mode (forward + inspect)
│   ├── decoy/                 # Decoy endpoint mode (echo + inspect)
│   ├── report/                # Report generation (SARIF, JUnit, JSON, HTML)
│   ├── admin/                 # Admin API (health, report retrieval, config)
│   └── engine/                # Core engine wiring (receives requests, runs assertions, collects results)
├── pkg/
│   └── snitchproxy/           # Public Go API for embedding
├── testdata/                  # Sample YAML configs, golden files for tests
├── docs/                      # Documentation, DSL spec
│   └── dsl-spec.md
├── Dockerfile
├── CLAUDE.md
├── README.md
├── LICENSE
├── go.mod
└── go.sum
```

### Key architectural decisions

- **`internal/` for most code**: Only `pkg/snitchproxy/` is the public API surface for embedding. Everything else is internal.
- **Hexagonal-ish**: The `engine` package defines ports (interfaces). `proxy`, `decoy`, `report`, and `admin` are adapters. `assertion` and `config` are domain logic.
- **No frameworks**: Use stdlib `net/http`, `net/http/httputil` for proxying, `encoding/json` and a YAML library for config. Keep dependencies minimal.

## Code Style & Conventions

### Go conventions

- Follow standard Go project layout and idioms.
- Use `errors.New` / `fmt.Errorf` with `%w` for error wrapping. No custom error frameworks.
- Prefer returning `(T, error)` over panicking.
- Interfaces are defined where they are consumed, not where they are implemented.
- Use table-driven tests extensively.
- Test files live next to the code they test: `assertion.go` → `assertion_test.go`.
- No `init()` functions. No global mutable state.

### Naming

- Package names are short, lowercase, singular: `assertion`, `config`, `report`.
- Exported types use clear, descriptive names: `AssertionResult`, `Violation`, `MatchSpec`.
- Avoid stuttering: `assertion.Assertion` is fine, but `assertion.AssertionEngine` should just be `assertion.Engine`.
- CLI flags use kebab-case: `--config-file`, `--fail-on`, `--listen-addr`.
- YAML config keys use kebab-case: `fail-on`, `source-ip`, `version-gte`.

### Dependencies

Keep them minimal. Currently expected:

- `gopkg.in/yaml.v3` — YAML parsing
- `github.com/stretchr/testify` — test assertions (dev only)

Do NOT add:
- Web frameworks (gin, echo, fiber) — use stdlib `net/http`
- Logging frameworks (zap, logrus) — use `log/slog` (stdlib)
- DI frameworks — manual wiring in `main.go` or a `wire.go` file
- ORM or database libraries — snitchproxy is stateless

### Error handling

- Config validation errors are collected and reported together, not fail-fast.
- Runtime assertion failures are NOT Go errors — they are domain results (`Violation` structs).
- Actual errors (can't bind port, can't read config file) are Go errors and bubble up.

### Logging

- Use `log/slog` with structured logging.
- Log levels: `DEBUG` for assertion evaluation details, `INFO` for lifecycle events (started, stopped, config loaded), `WARN` for non-fatal issues, `ERROR` for failures.
- Every log line should include relevant context (request ID, assertion name, etc.).

## Assertion DSL

The assertion DSL is defined in `docs/dsl-spec.md`. Key points:

- Assertions have `deny` (violation if true) or `allow` (violation if NOT true) semantics.
- `match` blocks scope assertions to specific traffic (host glob, path glob, method, header).
- `all` blocks provide AND compound conditions.
- Presets expand into named assertions that can be overridden.
- Four severity levels: `critical`, `high`, `warning`, `info`.
- `fail-on` threshold controls CI pass/fail.

## Admin API

SnitchProxy exposes an admin API on a separate port (default `:9484`) under the `/__snitchproxy/` path prefix:

```
GET  /__snitchproxy/health          → 200 OK (readiness probe for Testcontainers)
GET  /__snitchproxy/report           → full violation report (JSON)
GET  /__snitchproxy/report?format=sarif  → SARIF format
GET  /__snitchproxy/report?format=junit  → JUnit XML format
GET  /__snitchproxy/config           → active resolved config (presets expanded)
POST /__snitchproxy/reset            → clear collected violations
```

## Testcontainers Integration

The Docker image must:

- Expose two ports: proxy/decoy port (default `8080`) and admin port (default `9484`).
- Accept config via: mounted YAML file (`/etc/snitchproxy/config.yaml`) or `SNITCHPROXY_CONFIG` env var (inline YAML or file path).
- Respond to health checks at `/__snitchproxy/health` on the admin port.
- Generate final report on clean shutdown (SIGTERM).

A separate `snitchproxy-testcontainers` module (Kotlin/Java) will provide a typed JVM API.

## Build & Release

- `go build -o snitchproxy ./cmd/snitchproxy`
- Docker: multi-stage build, `scratch` or `distroless` base image.
- Binary size target: < 15MB.
- CI: GitHub Actions. Test → Build → Release (goreleaser).
- Release artifacts: binaries for linux/darwin/windows × amd64/arm64, Docker image.

## Testing Strategy

- **Unit tests**: Per-package, table-driven. Cover assertion evaluation, config parsing, pattern matching.
- **Integration tests**: Start snitchproxy in-process, send HTTP requests, verify violations. Use `net/http/httptest`.
- **Golden file tests**: For report output (SARIF, JUnit). Store expected output in `testdata/`.
- **End-to-end tests**: Docker-based. Start container, run traffic through it, check report via admin API.

## Common Tasks

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Build the binary
go build -o bin/snitchproxy ./cmd/snitchproxy

# Run locally
./bin/snitchproxy --config snitchproxy.yaml

# Run in proxy mode
./bin/snitchproxy --mode proxy --listen :8080 --admin :9484 --config snitchproxy.yaml

# Run in decoy mode
./bin/snitchproxy --mode decoy --listen :8080 --admin :9484 --config snitchproxy.yaml

# Docker build
docker build -t snitchproxy .

# Docker run
docker run -p 8080:8080 -p 9484:9484 -v $(pwd)/snitchproxy.yaml:/etc/snitchproxy/config.yaml snitchproxy
```
