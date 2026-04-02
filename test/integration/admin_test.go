package integration_test

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdmin_HealthEndpoint(t *testing.T) {
	configYAML := `
assertions:
  - name: dummy
    description: "dummy"
    severity: info
    deny:
      header: X-Never
      condition: present
`
	_, _, adminURL := startDecoy(t, configYAML)

	resp, err := http.Get(adminURL + "/__snitchproxy/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]string
	err = json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, "ok", body["status"])
}

func TestAdmin_ReportJSON(t *testing.T) {
	configYAML := `
assertions:
  - name: no-auth
    description: "No auth header"
    severity: high
    deny:
      header: Authorization
      condition: present
`
	_, modeURL, adminURL := startDecoy(t, configYAML)

	// Send a violating request.
	req, err := http.NewRequest("GET", modeURL+"/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	// Get JSON report.
	reportResp, err := http.Get(adminURL + "/__snitchproxy/report")
	require.NoError(t, err)
	defer reportResp.Body.Close()

	assert.Equal(t, http.StatusOK, reportResp.StatusCode)
	assert.Contains(t, reportResp.Header.Get("Content-Type"), "application/json")

	var report struct {
		TotalEvaluations int `json:"total_evaluations"`
		ViolationCount   int `json:"violation_count"`
		Violations       []struct {
			Assertion   string `json:"assertion"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
			Detail      string `json:"detail"`
			RequestID   string `json:"request_id"`
		} `json:"violations"`
	}
	err = json.NewDecoder(reportResp.Body).Decode(&report)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, report.TotalEvaluations, 1)
	assert.Equal(t, 1, report.ViolationCount)
	require.Len(t, report.Violations, 1)
	assert.Equal(t, "no-auth", report.Violations[0].Assertion)
	assert.Equal(t, "high", report.Violations[0].Severity)
	assert.NotEmpty(t, report.Violations[0].RequestID)
}

func TestAdmin_ReportSARIF(t *testing.T) {
	configYAML := `
assertions:
  - name: no-auth
    description: "No auth header"
    severity: high
    deny:
      header: Authorization
      condition: present
`
	_, modeURL, adminURL := startDecoy(t, configYAML)

	// Send a violating request.
	req, err := http.NewRequest("GET", modeURL+"/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	// Get SARIF report.
	reportResp, err := http.Get(adminURL + "/__snitchproxy/report?format=sarif")
	require.NoError(t, err)
	defer reportResp.Body.Close()

	assert.Equal(t, http.StatusOK, reportResp.StatusCode)
	assert.Contains(t, reportResp.Header.Get("Content-Type"), "application/json")

	var sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	err = json.NewDecoder(reportResp.Body).Decode(&sarif)
	require.NoError(t, err)

	assert.Equal(t, "2.1.0", sarif.Version)
	require.Len(t, sarif.Runs, 1)
	assert.Equal(t, "snitchproxy", sarif.Runs[0].Tool.Driver.Name)
	require.Len(t, sarif.Runs[0].Results, 1)
	assert.Equal(t, "no-auth", sarif.Runs[0].Results[0].RuleID)
	assert.Equal(t, "error", sarif.Runs[0].Results[0].Level) // high -> error in SARIF
}

func TestAdmin_ReportJUnit(t *testing.T) {
	configYAML := `
assertions:
  - name: no-auth
    description: "No auth header"
    severity: high
    deny:
      header: Authorization
      condition: present
`
	_, modeURL, adminURL := startDecoy(t, configYAML)

	// Send a violating request.
	req, err := http.NewRequest("GET", modeURL+"/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	// Get JUnit report.
	reportResp, err := http.Get(adminURL + "/__snitchproxy/report?format=junit")
	require.NoError(t, err)
	defer reportResp.Body.Close()

	assert.Equal(t, http.StatusOK, reportResp.StatusCode)
	assert.Contains(t, reportResp.Header.Get("Content-Type"), "application/xml")

	body, err := io.ReadAll(reportResp.Body)
	require.NoError(t, err)

	// Parse XML to verify structure.
	var suites struct {
		XMLName xml.Name `xml:"testsuites"`
		Suites  []struct {
			Name     string `xml:"name,attr"`
			Tests    int    `xml:"tests,attr"`
			Failures int    `xml:"failures,attr"`
			Cases    []struct {
				Name    string `xml:"name,attr"`
				Failure *struct {
					Message string `xml:"message,attr"`
					Type    string `xml:"type,attr"`
				} `xml:"failure"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	err = xml.Unmarshal(body, &suites)
	require.NoError(t, err)

	require.Len(t, suites.Suites, 1)
	assert.Equal(t, "snitchproxy", suites.Suites[0].Name)
	assert.GreaterOrEqual(t, suites.Suites[0].Failures, 1)
	require.NotEmpty(t, suites.Suites[0].Cases)

	var found bool
	for _, c := range suites.Suites[0].Cases {
		if c.Name == "no-auth" {
			found = true
			require.NotNil(t, c.Failure)
			assert.Equal(t, "high", c.Failure.Type)
		}
	}
	assert.True(t, found, "expected test case for 'no-auth' assertion")
}

func TestAdmin_ResetClearsViolations(t *testing.T) {
	configYAML := `
assertions:
  - name: no-auth
    description: "No auth header"
    severity: high
    deny:
      header: Authorization
      condition: present
`
	sp, modeURL, adminURL := startDecoy(t, configYAML)

	// Send a violating request.
	req, err := http.NewRequest("GET", modeURL+"/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	require.Len(t, sp.Violations(), 1)

	// POST /reset.
	resetResp, err := http.Post(adminURL+"/__snitchproxy/reset", "", nil)
	require.NoError(t, err)
	defer resetResp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resetResp.StatusCode)

	// Violations should be cleared.
	assert.Empty(t, sp.Violations())

	// Report should show zero violations.
	reportResp, err := http.Get(adminURL + "/__snitchproxy/report")
	require.NoError(t, err)
	defer reportResp.Body.Close()

	var report struct {
		ViolationCount int `json:"violation_count"`
	}
	err = json.NewDecoder(reportResp.Body).Decode(&report)
	require.NoError(t, err)
	assert.Equal(t, 0, report.ViolationCount)
}

func TestAdmin_ConfigEndpoint(t *testing.T) {
	configYAML := `
presets:
  - common-auth
assertions: []
`
	_, _, adminURL := startDecoy(t, configYAML)

	resp, err := http.Get(adminURL + "/__snitchproxy/config")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var assertions []struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	err = json.NewDecoder(resp.Body).Decode(&assertions)
	require.NoError(t, err)

	// common-auth preset should have expanded into multiple assertions.
	assert.NotEmpty(t, assertions)

	var found bool
	for _, a := range assertions {
		if a.Name == "common-auth/authorization-header" {
			found = true
			assert.True(t, a.Enabled)
		}
	}
	assert.True(t, found, "expected common-auth/authorization-header in resolved config")
}
