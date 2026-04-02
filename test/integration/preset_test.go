package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreset_CommonAuthAuthorizationHeader(t *testing.T) {
	configYAML := `
presets:
  - common-auth
assertions: []
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	req, err := http.NewRequest("GET", modeURL+"/api/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer my-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	violations := sp.Violations()
	// common-auth preset should flag the Authorization header.
	var found bool
	for _, v := range violations {
		if v.Assertion == "common-auth/authorization-header" {
			found = true
			assert.Equal(t, "high", string(v.Severity))
		}
	}
	assert.True(t, found, "expected common-auth/authorization-header violation, got violations: %v", violations)
}

func TestPreset_AWSKeysInBody(t *testing.T) {
	configYAML := `
presets:
  - aws-keys
assertions: []
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	// Send request body containing a fake AWS access key.
	body := strings.NewReader(`{"access_key": "AKIAIOSFODNN7EXAMPLE"}`)
	req, err := http.NewRequest("POST", modeURL+"/api/webhook", body)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	violations := sp.Violations()
	var found bool
	for _, v := range violations {
		if v.Assertion == "aws-keys/access-key-in-body" {
			found = true
			assert.Equal(t, "critical", string(v.Severity))
		}
	}
	assert.True(t, found, "expected aws-keys/access-key-in-body violation, got violations: %v", violations)
}

func TestPreset_PCIDSSCreditCardInBody(t *testing.T) {
	configYAML := `
presets:
  - pci-dss
assertions: []
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	// Send request body containing a test credit card number.
	body := strings.NewReader(`{"card": "4111 1111 1111 1111"}`)
	req, err := http.NewRequest("POST", modeURL+"/api/payment", body)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	violations := sp.Violations()
	var found bool
	for _, v := range violations {
		if v.Assertion == "pci-dss/credit-card-in-body" {
			found = true
			assert.Equal(t, "critical", string(v.Severity))
		}
	}
	assert.True(t, found, "expected pci-dss/credit-card-in-body violation, got violations: %v", violations)
}

func TestPreset_OverrideSeverity(t *testing.T) {
	// Override the common-auth/authorization-header rule's severity from high to info.
	configYAML := `
presets:
  - common-auth
assertions:
  - name: common-auth/authorization-header
    description: "Authorization header present in outbound request"
    severity: info
    deny:
      header: Authorization
      condition: present
`
	sp, modeURL, _ := startDecoy(t, configYAML)

	req, err := http.NewRequest("GET", modeURL+"/api/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	violations := sp.Violations()
	var found bool
	for _, v := range violations {
		if v.Assertion == "common-auth/authorization-header" {
			found = true
			assert.Equal(t, "info", string(v.Severity), "severity should be overridden to info")
		}
	}
	assert.True(t, found, "expected common-auth/authorization-header violation")
}
