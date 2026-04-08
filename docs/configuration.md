# Configuration

SnitchProxy is configured via a YAML file. The config defines which [presets](presets.md) to enable, custom [assertions](dsl-spec.md), and the failure threshold.

## Config file location

Provide the config via:

- `--config` CLI flag: `snitchproxy --mode decoy --config snitchproxy.yaml`
- `SNITCHPROXY_CONFIG` env var: file path or inline YAML
- Docker mount: `-v $(pwd)/snitchproxy.yaml:/etc/snitchproxy/config.yaml`

## Full example

```yaml
# snitchproxy.yaml — E-commerce API egress policy

presets:
  - common-auth
  - pii

fail-on: high

assertions:
  - name: no-internal-session
    description: "Internal session tokens must never leave the network"
    severity: critical
    deny:
      header: X-Internal-Session
      condition: present

  - name: no-auth-to-analytics
    description: "Never send credentials to analytics providers"
    severity: critical
    match:
      host:
        - "*.analytics.google.com"
        - "*.segment.io"
        - "*.mixpanel.com"
    deny:
      header: Authorization
      condition: present

  - name: stripe-payment-hardening
    description: "Stripe charge requests must use JSON over TLS 1.2+"
    severity: critical
    match:
      host: "api.stripe.com"
      path: "/v1/charges"
      method: POST
    allow:
      all:
        - header: Content-Type
          condition: equals
          value: "application/json"
        - header: Idempotency-Key
          condition: present
        - on: tls
          condition: version-gte
          value: "1.2"
```

## Top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `presets` | `string[]` | `[]` | Built-in rule packs to enable. See [Presets](presets.md). |
| `fail-on` | `string` | `high` | Severity threshold. If any violation meets or exceeds this level, the process exits with code 1. One of: `critical`, `high`, `warning`, `info`. |
| `assertions` | `object[]` | `[]` | Custom assertion rules. See [Assertion DSL](dsl-spec.md). |

## Validation

Config validation is strict and collects all errors at once (not fail-fast):

- Each assertion must have a unique, non-empty `name`
- Each assertion must have exactly one of `deny` or `allow` (not both)
- `severity` must be one of: `critical`, `high`, `warning`, `info`
- Conditions must be valid for their context (e.g., `in-cidr` only for `source-ip`)
- `pattern` values must be valid regular expressions
- `all` blocks must not be empty
- Header context requires a `header` field
- Query context requires a `param` field

## Preset overrides

User assertions can override preset rules by matching the preset rule name. For example, to disable a specific PCI-DSS rule:

```yaml
presets:
  - pci-dss

assertions:
  - name: pci-dss/credit-card-in-query
    enabled: false  # disable this specific preset rule
```

Or to change its severity:

```yaml
assertions:
  - name: pci-dss/credit-card-in-body
    severity: warning  # downgrade from high to warning
    deny:
      on: body
      condition: matches
      pattern: '\b\d{13,19}\b'
```
