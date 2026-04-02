package assertion

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper to create a minimal request for condition tests.
func newCondReq(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return &http.Request{
		Method:     method,
		URL:        u,
		Header:     http.Header{},
		Host:       u.Host,
		RemoteAddr: "192.168.1.100:12345",
	}
}

func TestEvalHeaderCondition(t *testing.T) {
	tests := []struct {
		name    string
		spec    ConditionSpec
		headers map[string]string
		wantMet bool
	}{
		{
			name:    "present - header exists",
			spec:    ConditionSpec{Header: "Authorization", Condition: "present"},
			headers: map[string]string{"Authorization": "Bearer token"},
			wantMet: true,
		},
		{
			name:    "present - header missing",
			spec:    ConditionSpec{Header: "Authorization", Condition: "present"},
			headers: map[string]string{},
			wantMet: false,
		},
		{
			name:    "present - header with empty value",
			spec:    ConditionSpec{Header: "X-Custom", Condition: "present"},
			headers: map[string]string{"X-Custom": ""},
			wantMet: true,
		},
		{
			name:    "equals - match",
			spec:    ConditionSpec{Header: "Content-Type", Condition: "equals", Value: "application/json"},
			headers: map[string]string{"Content-Type": "application/json"},
			wantMet: true,
		},
		{
			name:    "equals - no match",
			spec:    ConditionSpec{Header: "Content-Type", Condition: "equals", Value: "application/json"},
			headers: map[string]string{"Content-Type": "text/plain"},
			wantMet: false,
		},
		{
			name:    "matches - regex match",
			spec:    ConditionSpec{Header: "Authorization", Condition: "matches", Pattern: `^Bearer .+`},
			headers: map[string]string{"Authorization": "Bearer abc123"},
			wantMet: true,
		},
		{
			name:    "matches - regex no match",
			spec:    ConditionSpec{Header: "Authorization", Condition: "matches", Pattern: `^Bearer .+`},
			headers: map[string]string{"Authorization": "Basic abc123"},
			wantMet: false,
		},
		{
			name:    "matches - invalid regex",
			spec:    ConditionSpec{Header: "X-Test", Condition: "matches", Pattern: `[invalid`},
			headers: map[string]string{"X-Test": "value"},
			wantMet: false,
		},
		{
			name:    "not-matches - regex no match means met",
			spec:    ConditionSpec{Header: "Authorization", Condition: "not-matches", Pattern: `^Bearer .+`},
			headers: map[string]string{"Authorization": "Basic abc123"},
			wantMet: true,
		},
		{
			name:    "not-matches - regex match means not met",
			spec:    ConditionSpec{Header: "Authorization", Condition: "not-matches", Pattern: `^Bearer .+`},
			headers: map[string]string{"Authorization": "Bearer token"},
			wantMet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newCondReq(t, "GET", "http://example.com/")
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			cr := evalHeaderCondition(&tt.spec, r)
			assert.Equal(t, tt.wantMet, cr.met)
			assert.NotEmpty(t, cr.detail)
		})
	}
}

func TestEvalBodyCondition(t *testing.T) {
	tests := []struct {
		name    string
		spec    ConditionSpec
		body    string
		wantMet bool
	}{
		{
			name:    "matches - pattern found",
			spec:    ConditionSpec{On: "body", Condition: "matches", Pattern: `"ssn":\s*"\d{3}-\d{2}-\d{4}"`},
			body:    `{"ssn": "123-45-6789"}`,
			wantMet: true,
		},
		{
			name:    "matches - pattern not found",
			spec:    ConditionSpec{On: "body", Condition: "matches", Pattern: `"ssn":\s*"\d{3}-\d{2}-\d{4}"`},
			body:    `{"name": "John"}`,
			wantMet: false,
		},
		{
			name:    "matches - invalid regex",
			spec:    ConditionSpec{On: "body", Condition: "matches", Pattern: `[invalid`},
			body:    `anything`,
			wantMet: false,
		},
		{
			name:    "contains - value found",
			spec:    ConditionSpec{On: "body", Condition: "contains", Value: "secret"},
			body:    `this is a secret message`,
			wantMet: true,
		},
		{
			name:    "contains - value not found",
			spec:    ConditionSpec{On: "body", Condition: "contains", Value: "secret"},
			body:    `nothing here`,
			wantMet: false,
		},
		{
			name:    "empty body - contains",
			spec:    ConditionSpec{On: "body", Condition: "contains", Value: "something"},
			body:    "",
			wantMet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newCondReq(t, "POST", "http://example.com/")
			r.Body = io.NopCloser(strings.NewReader(tt.body))
			cr := evalBodyCondition(&tt.spec, r)
			assert.Equal(t, tt.wantMet, cr.met)
			assert.NotEmpty(t, cr.detail)
		})
	}
}

func TestEvalQueryCondition(t *testing.T) {
	tests := []struct {
		name    string
		spec    ConditionSpec
		rawURL  string
		wantMet bool
	}{
		{
			name:    "present - param exists",
			spec:    ConditionSpec{On: "query", Param: "token", Condition: "present"},
			rawURL:  "http://example.com/?token=abc",
			wantMet: true,
		},
		{
			name:    "present - param missing",
			spec:    ConditionSpec{On: "query", Param: "token", Condition: "present"},
			rawURL:  "http://example.com/?other=abc",
			wantMet: false,
		},
		{
			name:    "present - param empty value",
			spec:    ConditionSpec{On: "query", Param: "token", Condition: "present"},
			rawURL:  "http://example.com/?token=",
			wantMet: true,
		},
		{
			name:    "matches - regex match",
			spec:    ConditionSpec{On: "query", Param: "id", Condition: "matches", Pattern: `^\d+$`},
			rawURL:  "http://example.com/?id=12345",
			wantMet: true,
		},
		{
			name:    "matches - regex no match",
			spec:    ConditionSpec{On: "query", Param: "id", Condition: "matches", Pattern: `^\d+$`},
			rawURL:  "http://example.com/?id=abc",
			wantMet: false,
		},
		{
			name:    "matches - invalid regex",
			spec:    ConditionSpec{On: "query", Param: "id", Condition: "matches", Pattern: `[invalid`},
			rawURL:  "http://example.com/?id=123",
			wantMet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newCondReq(t, "GET", tt.rawURL)
			cr := evalQueryCondition(&tt.spec, r)
			assert.Equal(t, tt.wantMet, cr.met)
			assert.NotEmpty(t, cr.detail)
		})
	}
}

func TestEvalTLSCondition(t *testing.T) {
	tests := []struct {
		name    string
		spec    ConditionSpec
		tls     *tls.ConnectionState
		wantMet bool
	}{
		{
			name:    "version-gte - TLS 1.2 >= 1.2",
			spec:    ConditionSpec{On: "tls", Condition: "version-gte", Value: "1.2"},
			tls:     &tls.ConnectionState{Version: tls.VersionTLS12},
			wantMet: true,
		},
		{
			name:    "version-gte - TLS 1.3 >= 1.2",
			spec:    ConditionSpec{On: "tls", Condition: "version-gte", Value: "1.2"},
			tls:     &tls.ConnectionState{Version: tls.VersionTLS13},
			wantMet: true,
		},
		{
			name:    "version-gte - TLS 1.1 < 1.2",
			spec:    ConditionSpec{On: "tls", Condition: "version-gte", Value: "1.2"},
			tls:     &tls.ConnectionState{Version: tls.VersionTLS11},
			wantMet: false,
		},
		{
			name:    "version-gte - nil TLS",
			spec:    ConditionSpec{On: "tls", Condition: "version-gte", Value: "1.2"},
			tls:     nil,
			wantMet: false,
		},
		{
			name:    "version-gte - unknown version string",
			spec:    ConditionSpec{On: "tls", Condition: "version-gte", Value: "99.9"},
			tls:     &tls.ConnectionState{Version: tls.VersionTLS13},
			wantMet: false,
		},
		{
			name:    "client-cert-present - cert exists",
			spec:    ConditionSpec{On: "tls", Condition: "client-cert-present"},
			tls:     &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}},
			wantMet: true,
		},
		{
			name:    "client-cert-present - no certs",
			spec:    ConditionSpec{On: "tls", Condition: "client-cert-present"},
			tls:     &tls.ConnectionState{PeerCertificates: nil},
			wantMet: false,
		},
		{
			name:    "client-cert-present - nil TLS",
			spec:    ConditionSpec{On: "tls", Condition: "client-cert-present"},
			tls:     nil,
			wantMet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newCondReq(t, "GET", "https://example.com/")
			r.TLS = tt.tls
			cr := evalTLSCondition(&tt.spec, r)
			assert.Equal(t, tt.wantMet, cr.met)
			assert.NotEmpty(t, cr.detail)
		})
	}
}

func TestEvalSourceIPCondition(t *testing.T) {
	tests := []struct {
		name       string
		spec       ConditionSpec
		remoteAddr string
		wantMet    bool
	}{
		{
			name:       "in-cidr - IPv4 match single value",
			spec:       ConditionSpec{On: "source-ip", Condition: "in-cidr", Value: "192.168.1.0/24"},
			remoteAddr: "192.168.1.50:12345",
			wantMet:    true,
		},
		{
			name:       "in-cidr - IPv4 no match",
			spec:       ConditionSpec{On: "source-ip", Condition: "in-cidr", Value: "10.0.0.0/8"},
			remoteAddr: "192.168.1.50:12345",
			wantMet:    false,
		},
		{
			name:       "in-cidr - IPv4 match via values",
			spec:       ConditionSpec{On: "source-ip", Condition: "in-cidr", Values: []string{"10.0.0.0/8", "192.168.1.0/24"}},
			remoteAddr: "192.168.1.50:12345",
			wantMet:    true,
		},
		{
			name:       "in-cidr - IPv6 match",
			spec:       ConditionSpec{On: "source-ip", Condition: "in-cidr", Value: "::1/128"},
			remoteAddr: "[::1]:12345",
			wantMet:    true,
		},
		{
			name:       "in-cidr - IPv6 no match",
			spec:       ConditionSpec{On: "source-ip", Condition: "in-cidr", Value: "::1/128"},
			remoteAddr: "[::2]:12345",
			wantMet:    false,
		},
		{
			name:       "in-cidr - invalid CIDR",
			spec:       ConditionSpec{On: "source-ip", Condition: "in-cidr", Value: "not-a-cidr"},
			remoteAddr: "192.168.1.50:12345",
			wantMet:    false,
		},
		{
			name:       "in-cidr - unparseable remote addr",
			spec:       ConditionSpec{On: "source-ip", Condition: "in-cidr", Value: "192.168.1.0/24"},
			remoteAddr: "not-an-ip",
			wantMet:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newCondReq(t, "GET", "http://example.com/")
			r.RemoteAddr = tt.remoteAddr
			cr := evalSourceIPCondition(&tt.spec, r)
			assert.Equal(t, tt.wantMet, cr.met)
			assert.NotEmpty(t, cr.detail)
		})
	}
}

func TestEvalAll(t *testing.T) {
	tests := []struct {
		name    string
		specs   []ConditionSpec
		headers map[string]string
		wantMet bool
	}{
		{
			name: "all conditions pass",
			specs: []ConditionSpec{
				{Header: "Authorization", Condition: "present"},
				{Header: "Content-Type", Condition: "equals", Value: "application/json"},
			},
			headers: map[string]string{
				"Authorization": "Bearer token",
				"Content-Type":  "application/json",
			},
			wantMet: true,
		},
		{
			name: "first condition fails",
			specs: []ConditionSpec{
				{Header: "Authorization", Condition: "present"},
				{Header: "Content-Type", Condition: "equals", Value: "application/json"},
			},
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			wantMet: false,
		},
		{
			name: "last condition fails",
			specs: []ConditionSpec{
				{Header: "Authorization", Condition: "present"},
				{Header: "Content-Type", Condition: "equals", Value: "application/json"},
			},
			headers: map[string]string{
				"Authorization": "Bearer token",
				"Content-Type":  "text/plain",
			},
			wantMet: false,
		},
		{
			name:    "empty all block",
			specs:   []ConditionSpec{},
			headers: map[string]string{},
			wantMet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newCondReq(t, "GET", "http://example.com/")
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			cr := evalAll(tt.specs, r)
			assert.Equal(t, tt.wantMet, cr.met)
			assert.NotEmpty(t, cr.detail)
		})
	}
}

func TestEvalConditionRouting(t *testing.T) {
	t.Run("nil spec returns not met", func(t *testing.T) {
		r := newCondReq(t, "GET", "http://example.com/")
		cr := evalCondition(nil, r)
		assert.False(t, cr.met)
	})

	t.Run("compound all is routed", func(t *testing.T) {
		r := newCondReq(t, "GET", "http://example.com/")
		r.Header.Set("X-Test", "yes")
		spec := &ConditionSpec{
			All: []ConditionSpec{
				{Header: "X-Test", Condition: "present"},
			},
		}
		cr := evalCondition(spec, r)
		assert.True(t, cr.met)
	})

	t.Run("unknown context returns not met", func(t *testing.T) {
		r := newCondReq(t, "GET", "http://example.com/")
		spec := &ConditionSpec{On: "unknown", Condition: "present"}
		cr := evalCondition(spec, r)
		assert.False(t, cr.met)
	})
}

func TestEvaluateDenyAllow(t *testing.T) {
	tests := []struct {
		name       string
		assertion  Assertion
		headers    map[string]string
		wantPassed bool
	}{
		{
			name: "deny - condition met = violation",
			assertion: Assertion{
				Name:     "no-auth-header",
				Severity: SeverityHigh,
				Enabled:  true,
				Deny:     &ConditionSpec{Header: "Authorization", Condition: "present"},
			},
			headers:    map[string]string{"Authorization": "Bearer token"},
			wantPassed: false,
		},
		{
			name: "deny - condition not met = pass",
			assertion: Assertion{
				Name:     "no-auth-header",
				Severity: SeverityHigh,
				Enabled:  true,
				Deny:     &ConditionSpec{Header: "Authorization", Condition: "present"},
			},
			headers:    map[string]string{},
			wantPassed: true,
		},
		{
			name: "allow - condition met = pass",
			assertion: Assertion{
				Name:     "require-content-type",
				Severity: SeverityWarning,
				Enabled:  true,
				Allow:    &ConditionSpec{Header: "Content-Type", Condition: "present"},
			},
			headers:    map[string]string{"Content-Type": "application/json"},
			wantPassed: true,
		},
		{
			name: "allow - condition not met = violation",
			assertion: Assertion{
				Name:        "require-content-type",
				Description: "Content-Type header must be present",
				Severity:    SeverityWarning,
				Enabled:     true,
				Allow:       &ConditionSpec{Header: "Content-Type", Condition: "present"},
			},
			headers:    map[string]string{},
			wantPassed: false,
		},
		{
			name: "out of scope - auto pass",
			assertion: Assertion{
				Name:    "scoped-assertion",
				Enabled: true,
				Match:   &MatchSpec{Hosts: []string{"api.example.com"}},
				Deny:    &ConditionSpec{Header: "Authorization", Condition: "present"},
			},
			headers:    map[string]string{"Authorization": "Bearer token"},
			wantPassed: true, // request host doesn't match
		},
		{
			name: "disabled assertion - skipped by engine",
			assertion: Assertion{
				Name:    "disabled",
				Enabled: false,
				Deny:    &ConditionSpec{Header: "Authorization", Condition: "present"},
			},
			headers:    map[string]string{"Authorization": "Bearer token"},
			wantPassed: true, // won't even be evaluated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newCondReq(t, "GET", "http://other.example.com/api/test")
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}

			if !tt.assertion.Enabled {
				// Disabled assertions are filtered by Engine.Evaluate, not evaluate().
				engine := NewEngine([]Assertion{tt.assertion})
				results := engine.Evaluate(r, "req-1")
				assert.Empty(t, results)
				return
			}

			result := evaluate(tt.assertion, r, "req-1")
			assert.Equal(t, tt.wantPassed, result.Passed)
			if !tt.wantPassed {
				require.NotNil(t, result.Violation)
				assert.Equal(t, tt.assertion.Name, result.Violation.Assertion)
				assert.Equal(t, tt.assertion.Severity, result.Violation.Severity)
				assert.Equal(t, "req-1", result.Violation.RequestID)
			}
		})
	}
}

func TestEvaluateBodyBuffering(t *testing.T) {
	t.Run("body can be re-read after evaluation", func(t *testing.T) {
		a := Assertion{
			Name:    "body-check",
			Enabled: true,
			Deny:    &ConditionSpec{On: "body", Condition: "contains", Value: "secret"},
		}
		r := newCondReq(t, "POST", "http://example.com/")
		r.Body = io.NopCloser(strings.NewReader("this has a secret"))

		result := evaluate(a, r, "req-1")
		assert.False(t, result.Passed)

		// Body should still be readable.
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, "this has a secret", string(body))
	})
}

func TestViolations(t *testing.T) {
	results := []Result{
		{Assertion: "a1", Passed: true},
		{Assertion: "a2", Passed: false, Violation: &Violation{Assertion: "a2", Severity: SeverityHigh}},
		{Assertion: "a3", Passed: true},
		{Assertion: "a4", Passed: false, Violation: &Violation{Assertion: "a4", Severity: SeverityWarning}},
	}

	violations := Violations(results)
	assert.Len(t, violations, 2)
	assert.Equal(t, "a2", violations[0].Assertion)
	assert.Equal(t, "a4", violations[1].Assertion)
}

func TestTLSVersionNumber(t *testing.T) {
	tests := []struct {
		input string
		want  uint16
	}{
		{"1.0", tls.VersionTLS10},
		{"1.1", tls.VersionTLS11},
		{"1.2", tls.VersionTLS12},
		{"1.3", tls.VersionTLS13},
		{"tls1.2", tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13},
		{"unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, tlsVersionNumber(tt.input))
		})
	}
}
