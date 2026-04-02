package preset

import "github.com/vibewarden/snitchproxy/internal/assertion"

func commonAuth() []assertion.Assertion {
	return []assertion.Assertion{
		{
			Name:        "common-auth/authorization-header",
			Description: "Authorization header present in outbound request",
			Severity:    assertion.SeverityHigh,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				Header:    "Authorization",
				Condition: "present",
			},
		},
		{
			Name:        "common-auth/cookie-header",
			Description: "Cookie header present in outbound request",
			Severity:    assertion.SeverityWarning,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				Header:    "Cookie",
				Condition: "present",
			},
		},
		{
			Name:        "common-auth/x-api-key-header",
			Description: "X-API-Key header present in outbound request",
			Severity:    assertion.SeverityHigh,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				Header:    "X-API-Key",
				Condition: "present",
			},
		},
		{
			Name:        "common-auth/bearer-in-body",
			Description: "Bearer token detected in request body",
			Severity:    assertion.SeverityHigh,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`,
			},
		},
		{
			Name:        "common-auth/set-cookie-header",
			Description: "Set-Cookie header present in outbound request",
			Severity:    assertion.SeverityWarning,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				Header:    "Set-Cookie",
				Condition: "present",
			},
		},
	}
}
