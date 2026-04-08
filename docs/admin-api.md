# Admin API

SnitchProxy exposes an admin API on a separate port (default `:9484`) under the `/__snitchproxy/` path prefix.

## Endpoints

### Health check

```
GET /__snitchproxy/health
```

Returns `200 OK` with:

```json
{"status": "ok"}
```

Use this as a readiness probe for Docker/Testcontainers.

### Violation report

```
GET /__snitchproxy/report
GET /__snitchproxy/report?format=json
GET /__snitchproxy/report?format=sarif
GET /__snitchproxy/report?format=junit
```

Returns the current violation report. Default format is JSON.

**JSON** (`application/json`):

```json
{
  "total_evaluations": 42,
  "violation_count": 2,
  "violations": [
    {
      "assertion": "no-auth-to-analytics",
      "description": "Never send credentials to analytics providers",
      "severity": "critical",
      "detail": "header \"Authorization\" is present",
      "request_id": "req-7"
    }
  ]
}
```

**SARIF** (`application/json`) — for GitHub Security tab integration:

```bash
curl http://localhost:9484/__snitchproxy/report?format=sarif > results.sarif
# Upload to GitHub Security tab via github/codeql-action/upload-sarif
```

**JUnit XML** (`application/xml`) — for CI pipeline integration:

```bash
curl http://localhost:9484/__snitchproxy/report?format=junit > results.xml
# Parse with your CI system's JUnit reporter
```

### Active configuration

```
GET /__snitchproxy/config
```

Returns the fully resolved assertion list (presets expanded, overrides applied) as a JSON array. Useful for debugging which rules are active.

### Reset violations

```
POST /__snitchproxy/reset
```

Clears all collected violations and resets the evaluation counter. Returns `204 No Content`.
