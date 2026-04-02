package report

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vibewarden/snitchproxy/internal/assertion"
)

func TestFormatSARIF(t *testing.T) {
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
			goldenFile:       goldenPath("report_golden_sarif.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormatSARIF(tt.violations, tt.totalEvaluations)
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

func TestFormatSARIF_Structure(t *testing.T) {
	got, err := FormatSARIF(testViolations(), testTotalEvaluations)
	require.NoError(t, err)

	var report SARIFReport
	require.NoError(t, json.Unmarshal(got, &report))

	assert.Equal(t, "2.1.0", report.Version)
	assert.Contains(t, report.Schema, "sarif-schema-2.1.0")
	require.Len(t, report.Runs, 1)
	assert.Equal(t, "snitchproxy", report.Runs[0].Tool.Driver.Name)
	assert.Len(t, report.Runs[0].Results, 4)
	assert.Len(t, report.Runs[0].Tool.Driver.Rules, 4)
}

func TestFormatSARIF_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity assertion.Severity
		expected string
	}{
		{assertion.SeverityCritical, "error"},
		{assertion.SeverityHigh, "error"},
		{assertion.SeverityWarning, "warning"},
		{assertion.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			assert.Equal(t, tt.expected, sarifLevel(tt.severity))
		})
	}
}

func TestFormatSARIF_Empty(t *testing.T) {
	got, err := FormatSARIF(nil, 0)
	require.NoError(t, err)

	var report SARIFReport
	require.NoError(t, json.Unmarshal(got, &report))
	assert.Empty(t, report.Runs[0].Results)
	assert.Empty(t, report.Runs[0].Tool.Driver.Rules)
}
