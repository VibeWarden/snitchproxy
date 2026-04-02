package preset

import "github.com/vibewarden/snitchproxy/internal/assertion"

func privateNet() []assertion.Assertion {
	return []assertion.Assertion{
		{
			Name:        "private-net/rfc1918-in-x-forwarded-for",
			Description: "RFC 1918 private IP address detected in X-Forwarded-For header",
			Severity:    assertion.SeverityWarning,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				Header:    "X-Forwarded-For",
				Condition: "matches",
				Pattern:   `(?:^|,\s*)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`,
			},
		},
		{
			Name:        "private-net/rfc1918-in-x-real-ip",
			Description: "RFC 1918 private IP address detected in X-Real-IP header",
			Severity:    assertion.SeverityWarning,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				Header:    "X-Real-IP",
				Condition: "matches",
				Pattern:   `^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})$`,
			},
		},
		{
			Name:        "private-net/rfc1918-in-host",
			Description: "RFC 1918 private IP address detected in Host header",
			Severity:    assertion.SeverityWarning,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				Header:    "Host",
				Condition: "matches",
				Pattern:   `^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?$`,
			},
		},
	}
}
