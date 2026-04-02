package snitchproxy_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vibewarden/snitchproxy/internal/assertion"
	"github.com/vibewarden/snitchproxy/pkg/snitchproxy"
)

// minimalConfig is a valid YAML config with one deny assertion that
// fires when the Authorization header is present (simulates a credential leak).
const minimalConfig = `
assertions:
  - name: no-auth-header
    description: "Authorization header must not be sent"
    severity: high
    deny:
      header: Authorization
      condition: present
`

func TestNew_WithConfigBytes(t *testing.T) {
	sp, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(minimalConfig)),
		snitchproxy.WithMode(snitchproxy.ModeDecoy),
	)
	require.NoError(t, err)
	require.NotNil(t, sp)
}

func TestNew_NoConfig(t *testing.T) {
	_, err := snitchproxy.New()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no config provided")
}

func TestNew_InvalidConfig(t *testing.T) {
	invalidYAML := `
assertions:
  - name: bad
    severity: critical
`
	_, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(invalidYAML)),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config validation")
}

func TestStartClose(t *testing.T) {
	sp, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(minimalConfig)),
		snitchproxy.WithMode(snitchproxy.ModeDecoy),
		snitchproxy.WithListenAddr(":0"),
		snitchproxy.WithAdminAddr(":0"),
	)
	require.NoError(t, err)

	err = sp.Start(context.Background())
	require.NoError(t, err)
	defer sp.Close()

	// Verify that both servers are listening by checking their addresses.
	assert.NotEmpty(t, sp.ListenAddr())
	assert.NotEmpty(t, sp.AdminAddr())

	// Verify the admin health endpoint responds.
	resp, err := http.Get(fmt.Sprintf("http://%s/__snitchproxy/health", sp.AdminAddr()))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestViolations(t *testing.T) {
	sp, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(minimalConfig)),
		snitchproxy.WithMode(snitchproxy.ModeDecoy),
		snitchproxy.WithListenAddr(":0"),
		snitchproxy.WithAdminAddr(":0"),
	)
	require.NoError(t, err)

	err = sp.Start(context.Background())
	require.NoError(t, err)
	defer sp.Close()

	// No violations initially.
	assert.Empty(t, sp.Violations())
	assert.False(t, sp.HasViolationsAtOrAbove(assertion.SeverityInfo))

	// Send a request with an Authorization header to trigger the deny assertion.
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test", sp.ListenAddr()), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer secret-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// Now we should have a violation.
	violations := sp.Violations()
	require.Len(t, violations, 1)
	assert.Equal(t, "no-auth-header", violations[0].Assertion)
	assert.Equal(t, assertion.SeverityHigh, violations[0].Severity)
	assert.True(t, sp.HasViolationsAtOrAbove(assertion.SeverityHigh))
}

func TestViolations_Reset(t *testing.T) {
	sp, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(minimalConfig)),
		snitchproxy.WithMode(snitchproxy.ModeDecoy),
		snitchproxy.WithListenAddr(":0"),
		snitchproxy.WithAdminAddr(":0"),
	)
	require.NoError(t, err)

	err = sp.Start(context.Background())
	require.NoError(t, err)
	defer sp.Close()

	// Trigger a violation.
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/test", sp.ListenAddr()), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer secret-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	require.Len(t, sp.Violations(), 1)

	// Reset clears violations.
	sp.Reset()
	assert.Empty(t, sp.Violations())
}

func TestNew_WithConfigBytes_ProxyMode(t *testing.T) {
	sp, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(minimalConfig)),
		snitchproxy.WithMode(snitchproxy.ModeProxy),
	)
	require.NoError(t, err)
	require.NotNil(t, sp)
}

func TestListenAddr_BeforeStart(t *testing.T) {
	sp, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(minimalConfig)),
		snitchproxy.WithMode(snitchproxy.ModeDecoy),
	)
	require.NoError(t, err)

	// Before Start, addresses should be empty.
	assert.Empty(t, sp.ListenAddr())
	assert.Empty(t, sp.AdminAddr())
}

func TestNew_WithFailOn(t *testing.T) {
	sp, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(minimalConfig)),
		snitchproxy.WithMode(snitchproxy.ModeDecoy),
		snitchproxy.WithFailOn("critical"),
	)
	require.NoError(t, err)
	require.NotNil(t, sp)
}

func TestNew_MalformedYAML(t *testing.T) {
	_, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(strings.Repeat("{{{", 10))),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading config bytes")
}
