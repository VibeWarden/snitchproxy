package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func boolPtr(b bool) *bool {
	return &b
}

func validAssertion() AssertionConfig {
	return AssertionConfig{
		Name:     "test-assertion",
		Severity: "high",
		Deny: &ConditionConfig{
			Header:    "X-Secret",
			Condition: "present",
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *Config
		wantErr    bool
		errCount   int
		errContain string
	}{
		{
			name: "valid config",
			cfg: &Config{
				Assertions: []AssertionConfig{validAssertion()},
			},
		},
		{
			name: "empty name",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "",
						Severity: "high",
						Deny: &ConditionConfig{
							Header:    "X-Secret",
							Condition: "present",
						},
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "must not be empty",
		},
		{
			name: "duplicate names",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "duplicate",
						Severity: "high",
						Deny:     &ConditionConfig{Header: "X-A", Condition: "present"},
					},
					{
						Name:     "duplicate",
						Severity: "high",
						Deny:     &ConditionConfig{Header: "X-B", Condition: "present"},
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "duplicate assertion name",
		},
		{
			name: "both deny and allow",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "both",
						Severity: "high",
						Deny:     &ConditionConfig{Header: "X-A", Condition: "present"},
						Allow:    &ConditionConfig{Header: "X-B", Condition: "present"},
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "not both",
		},
		{
			name: "neither deny nor allow",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "neither",
						Severity: "high",
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "must have exactly one of deny or allow",
		},
		{
			name: "invalid severity",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "bad-severity",
						Severity: "extreme",
						Deny:     &ConditionConfig{Header: "X-A", Condition: "present"},
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "invalid severity",
		},
		{
			name: "valid severities",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{Name: "a", Severity: "critical", Deny: &ConditionConfig{Header: "X-A", Condition: "present"}},
					{Name: "b", Severity: "high", Deny: &ConditionConfig{Header: "X-A", Condition: "present"}},
					{Name: "c", Severity: "warning", Deny: &ConditionConfig{Header: "X-A", Condition: "present"}},
					{Name: "d", Severity: "info", Deny: &ConditionConfig{Header: "X-A", Condition: "present"}},
				},
			},
		},
		{
			name: "invalid condition for header context",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "bad-condition",
						Severity: "high",
						Deny: &ConditionConfig{
							Header:    "X-A",
							Condition: "in-cidr",
						},
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "invalid condition",
		},
		{
			name: "invalid condition for body context",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "bad-body",
						Severity: "high",
						Deny: &ConditionConfig{
							On:        "body",
							Condition: "present",
						},
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "invalid condition",
		},
		{
			name: "invalid condition for tls context",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "bad-tls",
						Severity: "high",
						Deny: &ConditionConfig{
							On:        "tls",
							Condition: "present",
						},
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "invalid condition",
		},
		{
			name: "invalid on value",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "bad-on",
						Severity: "high",
						Deny: &ConditionConfig{
							On:        "invalid-context",
							Condition: "present",
						},
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "invalid on value",
		},
		{
			name: "invalid regex pattern",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "bad-regex",
						Severity: "high",
						Deny: &ConditionConfig{
							On:        "body",
							Condition: "matches",
							Pattern:   "[invalid",
						},
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "invalid regex pattern",
		},
		{
			name: "valid regex pattern",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "good-regex",
						Severity: "high",
						Deny: &ConditionConfig{
							On:        "body",
							Condition: "matches",
							Pattern:   `\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`,
						},
					},
				},
			},
		},
		{
			name: "valid all compound condition",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "compound",
						Severity: "critical",
						Allow: &ConditionConfig{
							All: []ConditionConfig{
								{Header: "Content-Type", Condition: "equals", Value: StringOrSlice{"application/json"}},
								{On: "tls", Condition: "version-gte", Value: StringOrSlice{"1.2"}},
							},
						},
					},
				},
			},
		},
		{
			name: "invalid condition inside all block",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "bad-compound",
						Severity: "critical",
						Allow: &ConditionConfig{
							All: []ConditionConfig{
								{On: "tls", Condition: "contains"},
							},
						},
					},
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "invalid condition",
		},
		{
			name: "multiple errors collected",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "",
						Severity: "extreme",
					},
					{
						Name:     "valid-name",
						Severity: "high",
						Deny:     &ConditionConfig{Header: "X-A", Condition: "present"},
						Allow:    &ConditionConfig{Header: "X-B", Condition: "present"},
					},
				},
			},
			wantErr:  true,
			errCount: 4, // empty name + neither deny/allow + invalid severity + both deny/allow
		},
		{
			name: "empty assertions list is valid",
			cfg: &Config{
				Assertions: []AssertionConfig{},
			},
		},
		{
			name: "invalid fail-on value",
			cfg: &Config{
				FailOn: "extreme",
				Assertions: []AssertionConfig{
					validAssertion(),
				},
			},
			wantErr:    true,
			errCount:   1,
			errContain: "invalid fail-on value",
		},
		{
			name: "valid fail-on values",
			cfg: &Config{
				FailOn:     "critical",
				Assertions: []AssertionConfig{validAssertion()},
			},
		},
		{
			name: "empty all block",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "empty-all",
						Severity: "high",
						Deny:     &ConditionConfig{All: []ConditionConfig{}},
					},
				},
			},
			wantErr:    true,
			errContain: "must not be empty",
		},
		{
			name: "leaf condition missing condition field",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "no-condition",
						Severity: "high",
						Deny:     &ConditionConfig{Header: "X-A"},
					},
				},
			},
			wantErr:    true,
			errContain: "condition: must not be empty",
		},
		{
			name: "header context missing header field",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "no-header",
						Severity: "high",
						Deny:     &ConditionConfig{Condition: "present"},
					},
				},
			},
			wantErr:    true,
			errContain: "header",
		},
		{
			name: "query context missing param field",
			cfg: &Config{
				Assertions: []AssertionConfig{
					{
						Name:     "no-param",
						Severity: "high",
						Deny:     &ConditionConfig{On: "query", Condition: "present"},
					},
				},
			},
			wantErr:    true,
			errContain: "param",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.cfg)
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)

			var ve ValidationErrors
			require.ErrorAs(t, err, &ve)

			if tt.errCount > 0 {
				assert.Len(t, ve, tt.errCount, "expected %d validation errors, got %d: %v", tt.errCount, len(ve), ve)
			}

			if tt.errContain != "" {
				assert.Contains(t, err.Error(), tt.errContain)
			}
		})
	}
}

func TestValidationErrorsImplementsError(t *testing.T) {
	errs := ValidationErrors{
		{Field: "assertions[0].name", Message: "must not be empty"},
		{Field: "assertions[1].severity", Message: "invalid severity"},
	}

	msg := errs.Error()
	assert.Contains(t, msg, "assertions[0].name: must not be empty")
	assert.Contains(t, msg, "assertions[1].severity: invalid severity")
}
