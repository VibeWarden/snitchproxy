package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecoy_DenyAuthorizationHeader(t *testing.T) {
	configYAML := `
assertions:
  - name: no-auth-header
    description: "Authorization header must not be sent"
    severity: high
    deny:
      header: Authorization
      condition: present
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	req, err := http.NewRequest("GET", modeURL+"/api/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer secret-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Echo response should be 200 OK.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse the echo response.
	var echo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&echo)
	require.NoError(t, err)

	assert.Equal(t, "GET", echo["method"])
	assert.Equal(t, "/api/test", echo["path"])

	// Verify violation was recorded.
	violations := sp.Violations()
	require.Len(t, violations, 1)
	assert.Equal(t, "no-auth-header", violations[0].Assertion)
	assert.Equal(t, "high", string(violations[0].Severity))
}

func TestDecoy_NoViolationWhenNoMatch(t *testing.T) {
	configYAML := `
assertions:
  - name: no-auth-header
    description: "Authorization header must not be sent"
    severity: high
    deny:
      header: Authorization
      condition: present
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	// Send request without Authorization header.
	req, err := http.NewRequest("GET", modeURL+"/api/clean", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// No violations should be recorded.
	violations := sp.Violations()
	assert.Empty(t, violations)
}

func TestDecoy_BodyPatternViolation(t *testing.T) {
	configYAML := `
assertions:
  - name: no-secrets-in-body
    description: "Request body must not contain secrets"
    severity: critical
    deny:
      on: body
      condition: matches
      pattern: "secret_key=[A-Za-z0-9]+"
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	body := strings.NewReader("payload=data&secret_key=abc123XYZ")
	req, err := http.NewRequest("POST", modeURL+"/api/data", body)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	violations := sp.Violations()
	require.Len(t, violations, 1)
	assert.Equal(t, "no-secrets-in-body", violations[0].Assertion)
	assert.Equal(t, "critical", string(violations[0].Severity))
}

func TestDecoy_MultipleRequestsAccumulateViolations(t *testing.T) {
	configYAML := `
assertions:
  - name: no-auth-header
    description: "Authorization header must not be sent"
    severity: high
    deny:
      header: Authorization
      condition: present
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	// Send three requests with Authorization header.
	for i := 0; i < 3; i++ {
		req, err := http.NewRequest("GET", modeURL+"/api/test", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer token")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
	}

	violations := sp.Violations()
	assert.Len(t, violations, 3)
	for _, v := range violations {
		assert.Equal(t, "no-auth-header", v.Assertion)
	}
}

func TestDecoy_EchoResponseContainsRequestDetails(t *testing.T) {
	configYAML := `
assertions:
  - name: dummy
    description: "dummy rule"
    severity: info
    deny:
      header: X-Never-Sent
      condition: present
`
	_, modeURL, _ := startDecoy(t, configYAML)

	body := strings.NewReader("hello world")
	req, err := http.NewRequest("POST", modeURL+"/api/echo?foo=bar", body)
	require.NoError(t, err)
	req.Header.Set("X-Custom", "test-value")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var echo struct {
		RequestID string              `json:"request_id"`
		Method    string              `json:"method"`
		Path      string              `json:"path"`
		Headers   map[string][]string `json:"headers"`
		Body      string              `json:"body"`
		Query     map[string][]string `json:"query"`
	}
	err = json.NewDecoder(resp.Body).Decode(&echo)
	require.NoError(t, err)

	assert.NotEmpty(t, echo.RequestID)
	assert.Equal(t, "POST", echo.Method)
	assert.Equal(t, "/api/echo", echo.Path)
	assert.Equal(t, "hello world", echo.Body)
	assert.Contains(t, echo.Headers["X-Custom"], "test-value")
	assert.Contains(t, echo.Query["foo"], "bar")
}

func TestDecoy_AllowSemantics(t *testing.T) {
	configYAML := `
assertions:
  - name: require-content-type
    description: "Content-Type header must be present"
    severity: warning
    allow:
      header: Content-Type
      condition: present
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	// Send request WITHOUT Content-Type (should violate allow rule).
	req, err := http.NewRequest("GET", modeURL+"/api/test", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	violations := sp.Violations()
	require.Len(t, violations, 1)
	assert.Equal(t, "require-content-type", violations[0].Assertion)

	// Reset and send request WITH Content-Type (should pass).
	sp.Reset()
	req2, err := http.NewRequest("POST", modeURL+"/api/test", strings.NewReader("data"))
	require.NoError(t, err)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Empty(t, sp.Violations())
}

func getBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return body
}
