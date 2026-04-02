# Snitchproxy — Assertion DSL Specification

> **Version:** 0.1.0-draft
> **Status:** Design phase
> **Config file:** `snitchproxy.yaml`

---

## Overview

Snitchproxy inspects outbound HTTP traffic and evaluates it against a set of **assertions**.
Each assertion answers one question: _"Is this request safe to leave the network?"_

The DSL is designed around three concepts:

1. **Match** — _which_ requests does this assertion apply to?
2. **Allow / Deny** — _what_ condition triggers a pass or violation?
3. **Presets** — curated rule packs for common leak patterns.

---

## Top-level structure

```yaml
# snitchproxy.yaml

presets:
  - <preset-name>
  - <preset-name>

assertions:
  - name: <unique-id>
    description: "<human-readable explanation>"
    severity: critical | high | warning | info
    match:       # optional — omit to apply to all traffic
      ...
    deny:        # "if this is true, it's a violation"
      ...
    # OR
    allow:       # "if this is NOT true, it's a violation"
      ...
```

An assertion must have exactly one of `deny` or `allow`, never both.

---

## Match block

The `match` block scopes an assertion to specific traffic. If omitted, the
assertion applies to **all** proxied requests. All fields within a `match`
are AND'd together. Multiple values within a single field are OR'd.

```yaml
match:
  host: "<glob-pattern>"                   # single host
  host:                                     # OR — matches any
    - "*.analytics.google.com"
    - "*.segment.io"
  path: "/v1/charges"                      # exact path
  path: "/webhooks/**"                     # glob: ** matches nested segments
  method: POST                             # single method
  method: [POST, PUT, PATCH]               # any of these methods
  header:                                  # match on request header values
    Content-Type: "multipart/form-data"
    X-Request-Source: "batch-*"            # glob supported in values
```

### Pattern syntax

| Pattern      | Meaning                                  | Example                              |
|--------------|------------------------------------------|--------------------------------------|
| `*`          | Matches one segment / any characters     | `*.stripe.com` → `api.stripe.com`    |
| `**`         | Matches zero or more path segments       | `/api/**` → `/api/v1/users/123`      |
| Exact string | Literal match                            | `api.stripe.com`                     |

### Matching semantics

| Field    | Multiple values | Combination with other fields |
|----------|-----------------|-------------------------------|
| `host`   | OR              | AND with path, method, header |
| `path`   | OR              | AND with host, method, header |
| `method` | OR              | AND with host, path, header   |
| `header` | AND (all headers must match) | AND with everything else |

---

## Allow / Deny blocks

### `deny` — violation if the condition IS true

Use `deny` when you want to reject requests that exhibit a specific trait.

```yaml
# "If the Authorization header is present, that's a violation"
deny:
  header: Authorization
  condition: present
```

### `allow` — violation if the condition is NOT true

Use `allow` when you want to require requests to have a specific trait.

```yaml
# "If the Idempotency-Key header is missing, that's a violation"
allow:
  header: Idempotency-Key
  condition: present
```

### Condition reference

#### Header conditions

```yaml
# Header exists
deny:
  header: X-Internal-Token
  condition: present

# Header has exact value
allow:
  header: Content-Type
  condition: equals
  value: "application/json"

# Header matches regex
deny:
  header: Cookie
  condition: matches
  pattern: "session_id=|_internal_auth="

# Header does not match regex
allow:
  header: Authorization
  condition: not-matches
  pattern: "^Basic "
```

#### Body conditions

```yaml
# Body matches regex pattern
deny:
  on: body
  condition: matches
  pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"    # SSN pattern

# Body contains exact string
deny:
  on: body
  condition: contains
  value: "BEGIN RSA PRIVATE KEY"
```

#### Query parameter conditions

```yaml
# Query param exists
deny:
  on: query
  param: api_key
  condition: present

# Query param matches pattern
deny:
  on: query
  param: token
  condition: matches
  pattern: "^sk_live_"
```

#### TLS conditions

```yaml
# Minimum TLS version
allow:
  on: tls
  condition: version-gte
  value: "1.2"

# Client certificate present (for mTLS)
allow:
  on: tls
  condition: client-cert-present
```

#### Source IP conditions

```yaml
# Source IP in CIDR range
allow:
  on: source-ip
  condition: in-cidr
  value: "10.0.0.0/8"

# Multiple CIDR ranges
allow:
  on: source-ip
  condition: in-cidr
  value:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
```

---

## Compound conditions (`all`)

When an assertion requires multiple conditions to be true simultaneously,
use the `all` block. Every condition inside must pass — short-circuits on
first failure.

```yaml
- name: payment-endpoint-hardening
  description: "Payment requests must use TLS 1.2+, JSON, and carry idempotency key"
  severity: critical
  match:
    host: "api.stripe.com"
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

> **v2 consideration:** An `any` block (OR semantics) may be added in a
> future version for cases like "must authenticate via Bearer OR mTLS."

---

## Presets

Presets are curated rule packs that expand into a set of assertions.
They provide sensible defaults for common compliance and security scenarios.

```yaml
presets:
  - pci-dss
  - aws-keys
  - common-auth
  - pii
```

### Available presets

| Preset        | What it checks                                                           |
|---------------|--------------------------------------------------------------------------|
| `pci-dss`     | Credit card PANs (Luhn-validated), track data, CVVs in body and query    |
| `aws-keys`    | `AKIA*` access key IDs, secret key patterns, STS tokens                  |
| `common-auth` | `Authorization`, `Cookie`, `X-API-Key`, `Bearer` tokens, `Set-Cookie`    |
| `pii`         | SSN, email addresses, phone numbers (international), dates of birth      |
| `gcp-keys`    | GCP API keys, service account JSON fragments                             |
| `private-net` | Private IPs (RFC 1918) leaked in `X-Forwarded-For`, `X-Real-IP`, `Host`  |

### Overriding preset rules

Every preset rule has a name in the format `<preset>/<rule-name>`.
You can override its severity or scope it to specific traffic:

```yaml
presets:
  - pci-dss

assertions:
  # Downgrade credit card check severity in staging
  - name: pci-dss/credit-card-in-body
    severity: warning
    match:
      host: "*.staging.internal"

  # Disable a preset rule entirely
  - name: pci-dss/track-data-in-body
    enabled: false
```

---

## Severity levels

| Level      | Meaning                                           | Default CI behavior   |
|------------|---------------------------------------------------|-----------------------|
| `critical` | Data breach risk — immediate action required       | Fail the build        |
| `high`     | Significant leak risk — should block in production | Fail the build        |
| `warning`  | Potential issue — review recommended               | Pass with warning     |
| `info`     | Informational finding — no action required         | Pass silently         |

Severity thresholds are configurable at the top level:

```yaml
fail-on: warning   # fail if any assertion of this severity or above is violated
                    # default: high
```

---

## Complete example

```yaml
# snitchproxy.yaml — E-commerce API egress policy

presets:
  - pci-dss
  - common-auth
  - pii

fail-on: high

assertions:

  # Global: never leak internal session tokens
  - name: no-internal-session
    description: "Internal session tokens must never leave the network"
    severity: critical
    deny:
      header: X-Internal-Session
      condition: present

  # Global: never send AWS keys anywhere
  - name: no-aws-keys-in-body
    description: "AWS credentials must not appear in outbound request bodies"
    severity: critical
    deny:
      on: body
      condition: matches
      pattern: "AKIA[0-9A-Z]{16}"

  # Scoped: don't send auth headers to analytics
  - name: no-auth-to-analytics
    description: "Credentials must not leak to analytics providers"
    severity: critical
    match:
      host:
        - "*.analytics.google.com"
        - "*.segment.io"
        - "*.mixpanel.com"
    deny:
      header: Authorization
      condition: present

  # Scoped: Stripe payments must be hardened
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

  # Scoped: webhook calls must be clean
  - name: no-credentials-to-webhooks
    description: "Outbound webhook calls must not carry our credentials"
    severity: high
    match:
      path: "/webhooks/**"
    deny:
      header: Authorization
      condition: present

  # Scoped: only multipart uploads should carry file data
  - name: no-binary-to-json-endpoints
    description: "Binary data should only go to multipart endpoints"
    severity: warning
    match:
      header:
        Content-Type: "application/json"
    deny:
      on: body
      condition: matches
      pattern: "^(?:[A-Za-z0-9+/]{4}){100,}"   # long base64 blocks

  # Override: relax PCI check for staging
  - name: pci-dss/credit-card-in-body
    severity: info
    match:
      host: "*.staging.internal"
```

---

## Design principles

1. **Deny by default, document by exception.** If you're not sure, `deny` it.
2. **Assertions are independent.** Each assertion evaluates on its own. No ordering, no dependencies.
3. **Match narrows, allow/deny asserts.** These are separate concerns and should stay separated.
4. **Presets are just assertions.** They follow the exact same structure and can be overridden like any other rule.
5. **Flat over nested.** Prefer multiple simple assertions over deeply nested compound blocks.
