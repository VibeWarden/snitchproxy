package report

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vibewarden/snitchproxy/internal/assertion"
)

var update = flag.Bool("update", false, "update golden files")

func testViolations() []assertion.Violation {
	return []assertion.Violation{
		{
			Assertion:   "no-authorization-leak",
			Description: "Authorization header must not be forwarded to third-party hosts",
			Severity:    assertion.SeverityCritical,
			Detail:      "Authorization header present in request to api.example.com",
			RequestID:   "req-001",
		},
		{
			Assertion:   "no-plaintext-secrets",
			Description: "Request body must not contain plaintext secrets",
			Severity:    assertion.SeverityHigh,
			Detail:      "Body contains AWS secret key pattern",
			RequestID:   "req-002",
		},
		{
			Assertion:   "prefer-tls",
			Description: "Connections should use TLS",
			Severity:    assertion.SeverityWarning,
			Detail:      "Non-TLS connection to metrics.internal:9090",
			RequestID:   "req-003",
		},
		{
			Assertion:   "log-external-calls",
			Description: "External API calls should include a correlation ID",
			Severity:    assertion.SeverityInfo,
			Detail:      "Missing X-Correlation-ID header",
			RequestID:   "req-004",
		},
	}
}

const testTotalEvaluations = 42

func goldenPath(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func updateGolden(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, data, 0o644))
}

func TestFormatJSON(t *testing.T) {
	tests := []struct {
		name             string
		violations       []assertion.Violation
		totalEvaluations int
		goldenFile       string
	}{
		{
			name:             "standard violations",
			violations:       testViolations(),
			totalEvaluations: testTotalEvaluations,
			goldenFile:       goldenPath("report_golden_json.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormatJSON(tt.violations, tt.totalEvaluations)
			require.NoError(t, err)

			if *update {
				updateGolden(t, tt.goldenFile, got)
				return
			}

			want, err := os.ReadFile(tt.goldenFile)
			require.NoError(t, err, "golden file not found; run with -update to create")
			assert.JSONEq(t, string(want), string(got))
		})
	}
}

func TestFormatJSON_Empty(t *testing.T) {
	got, err := FormatJSON(nil, 0)
	require.NoError(t, err)
	assert.Contains(t, string(got), `"violations": []`)
	assert.Contains(t, string(got), `"violation_count": 0`)
}
