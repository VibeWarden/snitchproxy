# Embedding

SnitchProxy can be embedded directly in your Go tests via the `pkg/snitchproxy` package.

## Installation

```bash
go get github.com/vibewarden/snitchproxy
```

## Usage

```go
package myapp_test

import (
    "context"
    "net/http"
    "testing"

    "github.com/vibewarden/snitchproxy/pkg/snitchproxy"
)

func TestEgressSecurity(t *testing.T) {
    sp, err := snitchproxy.New(
        snitchproxy.WithConfigBytes([]byte(`
presets:
  - common-auth
  - pii
fail-on: high
`)),
        snitchproxy.WithMode(snitchproxy.ModeDecoy),
        snitchproxy.WithListenAddr(":0"),
        snitchproxy.WithAdminAddr(":0"),
    )
    if err != nil {
        t.Fatal(err)
    }

    if err := sp.Start(context.Background()); err != nil {
        t.Fatal(err)
    }
    defer sp.Close()

    // Point your HTTP client at sp.ListenAddr()
    resp, err := http.Get("http://" + sp.ListenAddr() + "/api/data")
    if err != nil {
        t.Fatal(err)
    }
    resp.Body.Close()

    // Check for violations
    if sp.HasViolationsAtOrAbove("high") {
        for _, v := range sp.Violations() {
            t.Errorf("violation: %s — %s", v.Assertion, v.Detail)
        }
    }
}
```

## API Reference

### `New(opts ...Option) (*SnitchProxy, error)`

Creates a new SnitchProxy instance. Applies options, loads config, validates, expands presets, and prepares the assertion engine.

### Options

| Option | Description |
|--------|-------------|
| `WithConfigFile(path)` | Load config from a YAML file |
| `WithConfigBytes(data)` | Load config from inline YAML bytes |
| `WithMode(mode)` | Set operating mode (`ModeDecoy` or `ModeProxy`) |
| `WithListenAddr(addr)` | Set proxy/decoy listen address (default `:8080`, use `:0` for random) |
| `WithAdminAddr(addr)` | Set admin API listen address (default `:9484`, use `:0` for random) |
| `WithFailOn(severity)` | Override the `fail-on` threshold from config |
| `WithLogger(logger)` | Set a custom `*slog.Logger` |

### `Start(ctx context.Context) error`

Starts both the mode server and admin server. Use `:0` addresses for ephemeral ports in tests. The context controls the server lifecycle — when cancelled, servers shut down gracefully.

### `Close() error`

Performs graceful shutdown of both servers with a 10-second timeout.

### `Violations() []assertion.Violation`

Returns all violations collected so far.

### `HasViolationsAtOrAbove(severity) bool`

Returns true if any violation meets or exceeds the given severity level.

### `Reset()`

Clears all collected violations.

### `ListenAddr() string` / `AdminAddr() string`

Returns the actual bound addresses. Useful when using `:0` for random port assignment.
