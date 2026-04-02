package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vibewarden/snitchproxy/internal/assertion"
)

func TestFailOn_WarningViolationsBelowHighThreshold(t *testing.T) {
	configYAML := `
fail-on: high
assertions:
  - name: warn-rule
    description: "Warning level rule"
    severity: warning
    deny:
      header: X-Test
      condition: present
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	// Send request that triggers the warning-level rule.
	req, err := http.NewRequest("GET", modeURL+"/test", nil)
	require.NoError(t, err)
	req.Header.Set("X-Test", "value")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	// Violation exists.
	require.Len(t, sp.Violations(), 1)

	// HasViolationsAtOrAbove("high") should be false since only warning-level violation exists.
	assert.False(t, sp.HasViolationsAtOrAbove(assertion.SeverityHigh),
		"warning violation should not meet high threshold")

	// HasViolationsAtOrAbove("warning") should be true.
	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityWarning),
		"warning violation should meet warning threshold")

	// HasViolationsAtOrAbove("info") should be true.
	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityInfo),
		"warning violation should meet info threshold")
}

func TestFailOn_HighViolationMeetsHighThreshold(t *testing.T) {
	configYAML := `
fail-on: high
assertions:
  - name: high-rule
    description: "High level rule"
    severity: high
    deny:
      header: Authorization
      condition: present
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	req, err := http.NewRequest("GET", modeURL+"/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	require.Len(t, sp.Violations(), 1)

	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityHigh),
		"high violation should meet high threshold")
	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityWarning),
		"high violation should meet warning threshold")
	assert.False(t, sp.HasViolationsAtOrAbove(assertion.SeverityCritical),
		"high violation should not meet critical threshold")
}

func TestFailOn_CriticalViolationMeetsAllThresholds(t *testing.T) {
	configYAML := `
assertions:
  - name: critical-rule
    description: "Critical level rule"
    severity: critical
    deny:
      header: X-Secret
      condition: present
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	req, err := http.NewRequest("GET", modeURL+"/test", nil)
	require.NoError(t, err)
	req.Header.Set("X-Secret", "value")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	require.Len(t, sp.Violations(), 1)

	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityCritical))
	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityHigh))
	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityWarning))
	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityInfo))
}

func TestFailOn_NoViolationsReturnsFalse(t *testing.T) {
	configYAML := `
assertions:
  - name: no-match-rule
    description: "This won't match"
    severity: critical
    deny:
      header: X-Never-Sent
      condition: present
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	// Send clean request.
	req, err := http.NewRequest("GET", modeURL+"/test", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Empty(t, sp.Violations())
	assert.False(t, sp.HasViolationsAtOrAbove(assertion.SeverityInfo))
}

func TestFailOn_MixedSeverities(t *testing.T) {
	configYAML := `
assertions:
  - name: info-rule
    description: "Info level"
    severity: info
    deny:
      header: X-Info
      condition: present
  - name: warning-rule
    description: "Warning level"
    severity: warning
    deny:
      header: X-Warning
      condition: present
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	// Trigger only the info-level rule.
	req, err := http.NewRequest("GET", modeURL+"/test", nil)
	require.NoError(t, err)
	req.Header.Set("X-Info", "yes")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityInfo))
	assert.False(t, sp.HasViolationsAtOrAbove(assertion.SeverityWarning))

	// Now also trigger the warning-level rule.
	req2, err := http.NewRequest("GET", modeURL+"/test", nil)
	require.NoError(t, err)
	req2.Header.Set("X-Warning", "yes")

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	resp2.Body.Close()

	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityWarning))
	assert.False(t, sp.HasViolationsAtOrAbove(assertion.SeverityHigh))
}
