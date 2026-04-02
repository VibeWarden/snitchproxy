package preset

import "github.com/vibewarden/snitchproxy/internal/assertion"

func awsKeys() []assertion.Assertion {
	return []assertion.Assertion{
		{
			Name:        "aws-keys/access-key-in-body",
			Description: "AWS access key ID detected in request body",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `AKIA[0-9A-Z]{16}`,
			},
		},
		{
			Name:        "aws-keys/access-key-in-query",
			Description: "AWS access key ID detected in query string",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "query",
				Condition: "matches",
				Pattern:   `AKIA[0-9A-Z]{16}`,
			},
		},
		{
			Name:        "aws-keys/secret-key-in-body",
			Description: "AWS secret access key detected in request body",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `(?i)aws_secret_access_key\s*[:=]\s*\S+`,
			},
		},
		{
			Name:        "aws-keys/sts-token-in-body",
			Description: "AWS STS session token detected in request body",
			Severity:    assertion.SeverityHigh,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `(?i)aws_session_token\s*[:=]\s*\S+`,
			},
		},
	}
}
