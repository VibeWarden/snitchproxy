package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vibewarden/snitchproxy/internal/assertion"
)

func TestToAssertions(t *testing.T) {
	tests := []struct {
		name  string
		input []AssertionConfig
		check func(t *testing.T, result []assertion.Assertion)
	}{
		{
			name:  "empty input",
			input: []AssertionConfig{},
			check: func(t *testing.T, result []assertion.Assertion) {
				assert.Empty(t, result)
			},
		},
		{
			name: "basic deny assertion",
			input: []AssertionConfig{
				{
					Name:        "no-secret-header",
					Description: "Block secret headers",
					Severity:    "critical",
					Deny: &ConditionConfig{
						Header:    "X-Secret",
						Condition: "present",
					},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				a := result[0]
				assert.Equal(t, "no-secret-header", a.Name)
				assert.Equal(t, "Block secret headers", a.Description)
				assert.Equal(t, assertion.SeverityCritical, a.Severity)
				assert.True(t, a.Enabled)
				assert.Nil(t, a.Match)
				require.NotNil(t, a.Deny)
				assert.Equal(t, "X-Secret", a.Deny.Header)
				assert.Equal(t, "present", a.Deny.Condition)
				assert.Nil(t, a.Allow)
			},
		},
		{
			name: "basic allow assertion",
			input: []AssertionConfig{
				{
					Name:     "require-tls",
					Severity: "high",
					Allow: &ConditionConfig{
						On:        "tls",
						Condition: "version-gte",
						Value:     StringOrSlice{"1.2"},
					},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				a := result[0]
				assert.Nil(t, a.Deny)
				require.NotNil(t, a.Allow)
				assert.Equal(t, "tls", a.Allow.On)
				assert.Equal(t, "version-gte", a.Allow.Condition)
				assert.Equal(t, "1.2", a.Allow.Value)
				assert.Empty(t, a.Allow.Values)
			},
		},
		{
			name: "severity defaults to high",
			input: []AssertionConfig{
				{
					Name: "no-severity",
					Deny: &ConditionConfig{Header: "X-A", Condition: "present"},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				assert.Equal(t, assertion.SeverityHigh, result[0].Severity)
			},
		},
		{
			name: "enabled defaults to true",
			input: []AssertionConfig{
				{
					Name:     "default-enabled",
					Severity: "info",
					Deny:     &ConditionConfig{Header: "X-A", Condition: "present"},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				assert.True(t, result[0].Enabled)
			},
		},
		{
			name: "enabled explicitly false",
			input: []AssertionConfig{
				{
					Name:     "disabled",
					Severity: "info",
					Enabled:  boolPtr(false),
					Deny:     &ConditionConfig{Header: "X-A", Condition: "present"},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				assert.False(t, result[0].Enabled)
			},
		},
		{
			name: "enabled explicitly true",
			input: []AssertionConfig{
				{
					Name:     "explicit-true",
					Severity: "info",
					Enabled:  boolPtr(true),
					Deny:     &ConditionConfig{Header: "X-A", Condition: "present"},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				assert.True(t, result[0].Enabled)
			},
		},
		{
			name: "StringOrSlice single value maps to Value",
			input: []AssertionConfig{
				{
					Name:     "single-value",
					Severity: "high",
					Deny: &ConditionConfig{
						On:        "source-ip",
						Condition: "in-cidr",
						Value:     StringOrSlice{"10.0.0.0/8"},
					},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].Deny)
				assert.Equal(t, "10.0.0.0/8", result[0].Deny.Value)
				assert.Empty(t, result[0].Deny.Values)
			},
		},
		{
			name: "StringOrSlice multiple values maps to Values",
			input: []AssertionConfig{
				{
					Name:     "multi-value",
					Severity: "high",
					Deny: &ConditionConfig{
						On:        "source-ip",
						Condition: "in-cidr",
						Value:     StringOrSlice{"10.0.0.0/8", "172.16.0.0/12"},
					},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].Deny)
				assert.Empty(t, result[0].Deny.Value)
				assert.Equal(t, []string{"10.0.0.0/8", "172.16.0.0/12"}, result[0].Deny.Values)
			},
		},
		{
			name: "match config conversion",
			input: []AssertionConfig{
				{
					Name:     "with-match",
					Severity: "high",
					Match: &MatchConfig{
						Host:   StringOrSlice{"*.stripe.com"},
						Path:   StringOrSlice{"/v1/charges"},
						Method: StringOrSlice{"POST"},
						Header: map[string]string{"Content-Type": "application/json"},
					},
					Deny: &ConditionConfig{Header: "X-A", Condition: "present"},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				m := result[0].Match
				require.NotNil(t, m)
				assert.Equal(t, []string{"*.stripe.com"}, m.Hosts)
				assert.Equal(t, []string{"/v1/charges"}, m.Paths)
				assert.Equal(t, []string{"POST"}, m.Methods)
				assert.Equal(t, map[string]string{"Content-Type": "application/json"}, m.Headers)
			},
		},
		{
			name: "compound all condition",
			input: []AssertionConfig{
				{
					Name:     "compound",
					Severity: "critical",
					Allow: &ConditionConfig{
						All: []ConditionConfig{
							{Header: "Content-Type", Condition: "equals", Value: StringOrSlice{"application/json"}},
							{Header: "Idempotency-Key", Condition: "present"},
							{On: "tls", Condition: "version-gte", Value: StringOrSlice{"1.2"}},
						},
					},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				allow := result[0].Allow
				require.NotNil(t, allow)
				require.Len(t, allow.All, 3)
				assert.Equal(t, "Content-Type", allow.All[0].Header)
				assert.Equal(t, "equals", allow.All[0].Condition)
				assert.Equal(t, "application/json", allow.All[0].Value)
				assert.Equal(t, "present", allow.All[1].Condition)
				assert.Equal(t, "tls", allow.All[2].On)
				assert.Equal(t, "version-gte", allow.All[2].Condition)
				assert.Equal(t, "1.2", allow.All[2].Value)
			},
		},
		{
			name: "pattern preserved",
			input: []AssertionConfig{
				{
					Name:     "with-pattern",
					Severity: "high",
					Deny: &ConditionConfig{
						On:        "body",
						Condition: "matches",
						Pattern:   `\b\d{16}\b`,
					},
				},
			},
			check: func(t *testing.T, result []assertion.Assertion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].Deny)
				assert.Equal(t, `\b\d{16}\b`, result[0].Deny.Pattern)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToAssertions(tt.input)
			tt.check(t, result)
		})
	}
}
