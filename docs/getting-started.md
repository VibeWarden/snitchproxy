# Getting Started

## Installation

### Binary

```bash
go install github.com/vibewarden/snitchproxy/cmd/snitchproxy@latest
```

### Docker

```bash
docker pull ghcr.io/vibewarden/snitchproxy:latest
```

## Quick Start

### 1. Create a config file

Create `snitchproxy.yaml`:

```yaml
presets:
  - common-auth
  - pii

fail-on: high

assertions:
  - name: no-auth-to-analytics
    description: "Never send credentials to analytics providers"
    severity: critical
    match:
      host:
        - "*.analytics.google.com"
        - "*.segment.io"
    deny:
      header: Authorization
      condition: present
```

### 2. Run in decoy mode

Decoy mode is the easiest way to start. It creates a fake API endpoint that echoes requests back while checking them against your assertions.

```bash
snitchproxy --mode decoy --config snitchproxy.yaml
```

Point your app at `http://localhost:8080` instead of the real external API. Every request is echoed back as JSON and evaluated against your assertions.

### 3. Run in proxy mode

Proxy mode forwards traffic to real destinations while inspecting it.

```bash
snitchproxy --mode proxy --config snitchproxy.yaml
```

Configure your app to use `http://localhost:8080` as its HTTP proxy.

### 4. Check results

Query the admin API for violations:

```bash
# JSON report
curl http://localhost:9484/__snitchproxy/report

# SARIF format (GitHub Security tab)
curl http://localhost:9484/__snitchproxy/report?format=sarif

# JUnit format (CI pipelines)
curl http://localhost:9484/__snitchproxy/report?format=junit
```

### 5. Docker

```bash
docker run -p 8080:8080 -p 9484:9484 \
  -v $(pwd)/snitchproxy.yaml:/etc/snitchproxy/config.yaml \
  ghcr.io/vibewarden/snitchproxy --mode decoy
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | *(required)* | `proxy` or `decoy` |
| `--config` | — | Path to YAML config file |
| `--listen` | `:8080` | Proxy/decoy listen address |
| `--admin` | `:9484` | Admin API listen address |
| `--fail-on` | config value | Severity threshold for exit code 1 |
| `--version` | — | Print version and exit |

The config file can also be provided via the `SNITCHPROXY_CONFIG` environment variable (either a file path or inline YAML).
