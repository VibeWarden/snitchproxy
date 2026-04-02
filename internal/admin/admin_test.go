package admin

import (
	"encoding/json"
	"encoding/xml"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vibewarden/snitchproxy/internal/assertion"
	"github.com/vibewarden/snitchproxy/internal/engine"
	"github.com/vibewarden/snitchproxy/internal/report"
)

func newTestHandler(t *testing.T, assertions []assertion.Assertion) (http.Handler, *engine.Report) {
	t.Helper()
	r := engine.NewReport()
	logger := slog.Default()
	h := Handler(r, assertions, logger)
	return h, r
}

func TestHealthEndpoint(t *testing.T) {
	h, _ := newTestHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/__snitchproxy/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "ok", body["status"])
}

func TestReportEndpointJSONDefault(t *testing.T) {
	h, _ := newTestHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/__snitchproxy/report", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var jr report.JSONReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &jr))
	assert.Equal(t, 0, jr.TotalEvaluations)
	assert.Empty(t, jr.Violations)
}

func TestReportEndpointJSONExplicit(t *testing.T) {
	h, r := newTestHandler(t, nil)
	r.Record([]assertion.Result{
		{
			Assertion: "test-rule",
			Passed:    false,
			Violation: &assertion.Violation{
				Assertion:   "test-rule",
				Description: "test desc",
				Severity:    assertion.SeverityHigh,
				Detail:      "found something",
				RequestID:   "req-1",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/__snitchproxy/report?format=json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var jr report.JSONReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &jr))
	assert.Equal(t, 1, jr.TotalEvaluations)
	assert.Len(t, jr.Violations, 1)
	assert.Equal(t, "test-rule", jr.Violations[0].Assertion)
}

func TestReportEndpointSARIF(t *testing.T) {
	h, r := newTestHandler(t, nil)
	r.Record([]assertion.Result{
		{
			Assertion: "sarif-rule",
			Passed:    false,
			Violation: &assertion.Violation{
				Assertion:   "sarif-rule",
				Description: "sarif desc",
				Severity:    assertion.SeverityCritical,
				Detail:      "sarif detail",
				RequestID:   "req-2",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/__snitchproxy/report?format=sarif", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var sr report.SARIFReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &sr))
	assert.Equal(t, "2.1.0", sr.Version)
	require.Len(t, sr.Runs, 1)
	assert.Len(t, sr.Runs[0].Results, 1)
	assert.Equal(t, "sarif-rule", sr.Runs[0].Results[0].RuleID)
}

func TestReportEndpointJUnit(t *testing.T) {
	h, r := newTestHandler(t, nil)
	r.Record([]assertion.Result{
		{
			Assertion: "junit-rule",
			Passed:    false,
			Violation: &assertion.Violation{
				Assertion:   "junit-rule",
				Description: "junit desc",
				Severity:    assertion.SeverityWarning,
				Detail:      "junit detail",
				RequestID:   "req-3",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/__snitchproxy/report?format=junit", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/xml", rec.Header().Get("Content-Type"))

	var suites report.JUnitTestSuites
	require.NoError(t, xml.Unmarshal(rec.Body.Bytes(), &suites))
	require.Len(t, suites.Suites, 1)
	assert.Equal(t, 1, suites.Suites[0].Failures)
	require.Len(t, suites.Suites[0].Cases, 1)
	assert.Equal(t, "junit-rule", suites.Suites[0].Cases[0].Name)
}

func TestReportEndpointUnknownFormat(t *testing.T) {
	h, _ := newTestHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/__snitchproxy/report?format=csv", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestConfigEndpoint(t *testing.T) {
	assertions := []assertion.Assertion{
		{
			Name:        "no-auth-header-leak",
			Description: "Deny authorization header forwarding",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Match: &assertion.MatchSpec{
				Hosts: []string{"*.external.com"},
			},
			Deny: &assertion.ConditionSpec{
				Header:    "Authorization",
				Condition: "present",
			},
		},
		{
			Name:        "require-tls",
			Description: "Require TLS",
			Severity:    assertion.SeverityHigh,
			Enabled:     true,
			Allow: &assertion.ConditionSpec{
				On:        "tls",
				Condition: "present",
			},
		},
	}

	h, _ := newTestHandler(t, assertions)

	req := httptest.NewRequest(http.MethodGet, "/__snitchproxy/config", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var result []assertion.Assertion
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	require.Len(t, result, 2)
	assert.Equal(t, "no-auth-header-leak", result[0].Name)
	assert.Equal(t, assertion.SeverityCritical, result[0].Severity)
	assert.Equal(t, "*.external.com", result[0].Match.Hosts[0])
	assert.Equal(t, "require-tls", result[1].Name)
}

func TestResetEndpoint(t *testing.T) {
	h, r := newTestHandler(t, nil)

	// Record a violation first.
	r.Record([]assertion.Result{
		{
			Assertion: "rule",
			Passed:    false,
			Violation: &assertion.Violation{
				Assertion: "rule",
				Severity:  assertion.SeverityInfo,
			},
		},
	})
	assert.Equal(t, 1, r.TotalEvaluations())

	req := httptest.NewRequest(http.MethodPost, "/__snitchproxy/reset", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, 0, r.TotalEvaluations())
	assert.Empty(t, r.Violations())
}

func TestMethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(t, nil)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/__snitchproxy/report"},
		{http.MethodPost, "/__snitchproxy/config"},
		{http.MethodGet, "/__snitchproxy/reset"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		})
	}
}
