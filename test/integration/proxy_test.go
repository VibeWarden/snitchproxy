package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_ForwardsRequestToBackend(t *testing.T) {
	backend := startBackend(t)

	configYAML := `
assertions:
  - name: no-auth-header
    description: "Authorization header must not be sent"
    severity: high
    deny:
      header: Authorization
      condition: present
`
	_, proxyURL, _ := startProxy(t, configYAML)

	// Create HTTP client that uses the proxy.
	proxyTransport := &http.Transport{
		Proxy: func(_ *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
	}
	client := &http.Client{Transport: proxyTransport}

	// Send request through proxy to backend (no violation).
	req, err := http.NewRequest("GET", backend.Server.URL+"/api/data", nil)
	require.NoError(t, err)
	req.Header.Set("X-Trace", "test-trace")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response came from backend.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := getBody(t, resp)
	assert.Contains(t, string(body), `"status":"ok"`)

	// Verify backend received the request.
	reqs := backend.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "GET", reqs[0].Method)
	assert.Equal(t, "/api/data", reqs[0].Path)
}

func TestProxy_RecordsViolationAndStillForwards(t *testing.T) {
	backend := startBackend(t)

	configYAML := `
assertions:
  - name: no-auth-header
    description: "Authorization header must not be sent"
    severity: high
    deny:
      header: Authorization
      condition: present
`
	sp, proxyURL, _ := startProxy(t, configYAML)

	proxyTransport := &http.Transport{
		Proxy: func(_ *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
	}
	client := &http.Client{Transport: proxyTransport}

	// Send request with Authorization header (should trigger violation).
	req, err := http.NewRequest("POST", backend.Server.URL+"/api/secret", strings.NewReader("payload"))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer leaked-token")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Request should still be forwarded successfully.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Backend should have received the request.
	reqs := backend.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "POST", reqs[0].Method)
	assert.Equal(t, "/api/secret", reqs[0].Path)

	// Violation should be recorded.
	violations := sp.Violations()
	require.Len(t, violations, 1)
	assert.Equal(t, "no-auth-header", violations[0].Assertion)
	assert.Equal(t, "high", string(violations[0].Severity))
}

func TestProxy_BodyPatternViolationAndForward(t *testing.T) {
	backend := startBackend(t)

	configYAML := `
assertions:
  - name: no-secrets-in-body
    description: "No secrets in body"
    severity: critical
    deny:
      on: body
      condition: matches
      pattern: "password=[A-Za-z0-9]+"
`
	sp, proxyURL, _ := startProxy(t, configYAML)

	proxyTransport := &http.Transport{
		Proxy: func(_ *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
	}
	client := &http.Client{Transport: proxyTransport}

	req, err := http.NewRequest("POST", backend.Server.URL+"/api/submit", strings.NewReader("user=alice&password=hunter2"))
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Backend received the request with body intact.
	reqs := backend.Requests()
	require.Len(t, reqs, 1)
	assert.Contains(t, reqs[0].Body, "password=hunter2")

	// Violation recorded.
	violations := sp.Violations()
	require.Len(t, violations, 1)
	assert.Equal(t, "no-secrets-in-body", violations[0].Assertion)
}
