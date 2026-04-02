# 🐦 SnitchProxy

**Egress Security Scanner — Catch data leaks before they leave your app.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

SnitchProxy is a dual-mode egress security testing tool. Deploy it as a **fake external API** to catch credential leaks, or as a **transparent proxy** to audit real integration traffic. Either way, it snitches on your app when sensitive data tries to escape.

## The Problem

Every security tool today tests *inbound* traffic — is your server safe from attackers? Nobody tests *outbound* traffic — is your app safe to connect to? Apps routinely leak credentials, session tokens, PII, and internal headers to third-party APIs. There's no standard tool to catch this.

## How It Works

**Mode 1 — Decoy Endpoint** (like httpbin with teeth):
1. Point your app at SnitchProxy instead of a real external API
2. SnitchProxy echoes every request AND evaluates it against your assertions
3. Returns `200` if clean, `422` if violation detected

**Mode 2 — Transparent Proxy** (like Toxiproxy for security):
1. Route your app's outbound traffic through SnitchProxy
2. Traffic flows to real external APIs, but SnitchProxy inspects everything
3. Violations are reported via response headers, admin API, and final report

## Quick Start

```bash
# Install
go install github.com/vibewarden/snitchproxy/cmd/snitchproxy@latest

# Run in decoy mode
snitchproxy --mode decoy --config snitchproxy.yaml

# Run in proxy mode
snitchproxy --mode proxy --config snitchproxy.yaml
```

## Configuration

SnitchProxy uses a YAML-based assertion DSL. Define what should and shouldn't appear in outbound traffic:

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

  - name: stripe-requires-idempotency
    description: "All Stripe charges must carry an idempotency key"
    severity: high
    match:
      host: "api.stripe.com"
      path: "/v1/charges"
      method: POST
    allow:
      header: Idempotency-Key
      condition: present
```

See [DSL Specification](docs/dsl-spec.md) for the full reference.

## Built-in Presets

| Preset        | What it catches                                                     |
|---------------|---------------------------------------------------------------------|
| `pci-dss`     | Credit card numbers (Luhn-validated), track data, CVVs              |
| `aws-keys`    | `AKIA*` access keys, secret keys, STS tokens                       |
| `common-auth` | `Authorization`, `Cookie`, `X-API-Key`, Bearer tokens               |
| `pii`         | SSN, email addresses, phone numbers, dates of birth                 |
| `gcp-keys`    | GCP API keys, service account JSON fragments                        |
| `private-net` | Private IPs leaked in `X-Forwarded-For`, `X-Real-IP`, `Host`       |

## CI Integration

SnitchProxy generates reports in standard formats for CI pipelines:

```bash
# Get SARIF report (GitHub Security tab)
curl http://localhost:9484/__snitchproxy/report?format=sarif

# Get JUnit report (CI pipelines)
curl http://localhost:9484/__snitchproxy/report?format=junit
```

## Testcontainers

Use SnitchProxy in integration tests from any language:

```java
// Java/Kotlin with Testcontainers
var snitch = new SnitchproxyContainer()
    .withPresets("common-auth", "pii")
    .withAssertion("no-auth-header", deny().header("Authorization").present());

snitch.start();

// Point your HTTP client at snitch.getProxyUrl()
// Run your tests...

snitch.assertClean();  // throws if violations found
```

## Part of the VibeWarden Ecosystem

| Tool | Role |
|------|------|
| [VibeWarden](https://github.com/vibewarden/vibewarden) | Egress proxy — the lock |
| **SnitchProxy** | Egress assertion engine — the lock tester |
| [httptape](https://github.com/vibewarden/httptape) | Request recorder — the evidence |

## License

Apache 2.0 — see [LICENSE](LICENSE).
