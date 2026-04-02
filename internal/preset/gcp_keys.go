package preset

import "github.com/vibewarden/snitchproxy/internal/assertion"

func gcpKeys() []assertion.Assertion {
	return []assertion.Assertion{
		{
			Name:        "gcp-keys/api-key-in-body",
			Description: "GCP API key detected in request body",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `AIza[0-9A-Za-z\-_]{35}`,
			},
		},
		{
			Name:        "gcp-keys/api-key-in-query",
			Description: "GCP API key detected in query string",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "query",
				Condition: "matches",
				Pattern:   `AIza[0-9A-Za-z\-_]{35}`,
			},
		},
		{
			Name:        "gcp-keys/service-account-in-body",
			Description: "GCP service account key detected in request body",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `"type"\s*:\s*"service_account"`,
			},
		},
	}
}
