package preset

import "github.com/vibewarden/snitchproxy/internal/assertion"

func pii() []assertion.Assertion {
	return []assertion.Assertion{
		{
			Name:        "pii/ssn-in-body",
			Description: "Social Security Number detected in request body",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `\b\d{3}-\d{2}-\d{4}\b`,
			},
		},
		{
			Name:        "pii/email-in-body",
			Description: "Email address detected in request body",
			Severity:    assertion.SeverityWarning,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			},
		},
		{
			Name:        "pii/phone-in-body",
			Description: "Phone number detected in request body",
			Severity:    assertion.SeverityWarning,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`,
			},
		},
		{
			Name:        "pii/dob-in-body",
			Description: "Date of birth detected in request body",
			Severity:    assertion.SeverityWarning,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `\b(?:19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b`,
			},
		},
	}
}
