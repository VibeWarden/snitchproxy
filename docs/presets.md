# Presets

Presets are built-in rule packs that detect common data leak patterns. Enable them in your config with the `presets` field.

```yaml
presets:
  - common-auth
  - pii
  - pci-dss
```

## Available Presets

### `common-auth`

Detects leaked authentication credentials.

| Rule | Severity | What it catches |
|------|----------|----------------|
| `common-auth/authorization-header` | high | `Authorization` header present |
| `common-auth/cookie-header` | high | `Cookie` header present |
| `common-auth/x-api-key-header` | high | `X-API-Key` header present |
| `common-auth/bearer-in-body` | high | Bearer tokens in request body |
| `common-auth/set-cookie-header` | high | `Set-Cookie` header present |

### `pii`

Detects personally identifiable information in request bodies.

| Rule | Severity | What it catches |
|------|----------|----------------|
| `pii/ssn-in-body` | critical | Social Security Numbers |
| `pii/email-in-body` | warning | Email addresses |
| `pii/phone-in-body` | warning | Phone numbers |
| `pii/dob-in-body` | warning | Dates of birth |

### `pci-dss`

Detects payment card data (PCI DSS compliance).

| Rule | Severity | What it catches |
|------|----------|----------------|
| `pci-dss/credit-card-in-body` | critical | Credit card numbers in body |
| `pci-dss/credit-card-in-query` | critical | Credit card numbers in query strings |
| `pci-dss/track-data-in-body` | critical | Magnetic stripe track data |
| `pci-dss/cvv-in-body` | critical | CVV/CVC codes |

### `aws-keys`

Detects leaked AWS credentials.

| Rule | Severity | What it catches |
|------|----------|----------------|
| `aws-keys/access-key-in-body` | critical | `AKIA*` access keys in body |
| `aws-keys/access-key-in-query` | critical | `AKIA*` access keys in query |
| `aws-keys/secret-key-in-body` | critical | AWS secret keys in body |
| `aws-keys/sts-token-in-body` | high | STS session tokens in body |

### `gcp-keys`

Detects leaked GCP credentials.

| Rule | Severity | What it catches |
|------|----------|----------------|
| `gcp-keys/api-key-in-body` | critical | GCP API keys in body |
| `gcp-keys/api-key-in-query` | critical | GCP API keys in query |
| `gcp-keys/service-account-in-body` | critical | Service account JSON fragments |

### `private-net`

Detects internal network information leaking in headers.

| Rule | Severity | What it catches |
|------|----------|----------------|
| `private-net/rfc1918-in-x-forwarded-for` | warning | RFC 1918 IPs in `X-Forwarded-For` |
| `private-net/rfc1918-in-x-real-ip` | warning | RFC 1918 IPs in `X-Real-IP` |
| `private-net/rfc1918-in-host` | warning | RFC 1918 IPs in `Host` header |

## Overriding Preset Rules

You can override any preset rule by creating a custom assertion with the same name. See [Configuration](configuration.md#preset-overrides) for details.
