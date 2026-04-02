package report

import (
	"encoding/xml"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vibewarden/snitchproxy/internal/assertion"
)

func TestFormatJUnit(t *testing.T) {
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
			goldenFile:       goldenPath("report_golden_junit.xml"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormatJUnit(tt.violations, tt.totalEvaluations)
			require.NoError(t, err)

			if *update {
				updateGolden(t, tt.goldenFile, got)
				return
			}

			want, err := os.ReadFile(tt.goldenFile)
			require.NoError(t, err, "golden file not found; run with -update to create")
			assert.Equal(t, string(want), string(got))
		})
	}
}

func TestFormatJUnit_Structure(t *testing.T) {
	got, err := FormatJUnit(testViolations(), testTotalEvaluations)
	require.NoError(t, err)

	var suites JUnitTestSuites
	require.NoError(t, xml.Unmarshal(got, &suites))

	require.Len(t, suites.Suites, 1)
	suite := suites.Suites[0]
	assert.Equal(t, "snitchproxy", suite.Name)
	assert.Equal(t, 4, suite.Tests)
	assert.Equal(t, 4, suite.Failures)
	assert.Len(t, suite.Cases, 4)

	// Each case should have a failure since all test violations are violated.
	for _, c := range suite.Cases {
		assert.Equal(t, "snitchproxy", c.ClassName)
		assert.NotNil(t, c.Failure)
	}
}

func TestFormatJUnit_Empty(t *testing.T) {
	got, err := FormatJUnit(nil, 10)
	require.NoError(t, err)

	var suites JUnitTestSuites
	require.NoError(t, xml.Unmarshal(got, &suites))

	require.Len(t, suites.Suites, 1)
	assert.Equal(t, 0, suites.Suites[0].Tests)
	assert.Equal(t, 0, suites.Suites[0].Failures)
	assert.Empty(t, suites.Suites[0].Cases)
}

func TestFormatJUnit_DuplicateAssertions(t *testing.T) {
	violations := []assertion.Violation{
		{
			Assertion:   "no-secrets",
			Description: "No secrets in body",
			Severity:    assertion.SeverityHigh,
			Detail:      "Found secret in request 1",
			RequestID:   "req-001",
		},
		{
			Assertion:   "no-secrets",
			Description: "No secrets in body",
			Severity:    assertion.SeverityHigh,
			Detail:      "Found secret in request 2",
			RequestID:   "req-002",
		},
	}

	got, err := FormatJUnit(violations, 5)
	require.NoError(t, err)

	var suites JUnitTestSuites
	require.NoError(t, xml.Unmarshal(got, &suites))

	// Should be one test case with combined failure text.
	require.Len(t, suites.Suites[0].Cases, 1)
	assert.Equal(t, 1, suites.Suites[0].Failures)
	assert.Contains(t, suites.Suites[0].Cases[0].Failure.Text, "Found secret in request 1")
	assert.Contains(t, suites.Suites[0].Cases[0].Failure.Text, "Found secret in request 2")
}
