package preset

import "github.com/vibewarden/snitchproxy/internal/assertion"

func pciDSS() []assertion.Assertion {
	return []assertion.Assertion{
		{
			Name:        "pci-dss/credit-card-in-body",
			Description: "Credit card number detected in request body",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `\b(?:\d[ -]*?){13,19}\b`,
			},
		},
		{
			Name:        "pci-dss/credit-card-in-query",
			Description: "Credit card number detected in query string",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "query",
				Condition: "matches",
				Pattern:   `\b(?:\d[ -]*?){13,19}\b`,
			},
		},
		{
			Name:        "pci-dss/track-data-in-body",
			Description: "Magnetic stripe track data detected in request body",
			Severity:    assertion.SeverityCritical,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `%B\d{13,19}\^\w+`,
			},
		},
		{
			Name:        "pci-dss/cvv-in-body",
			Description: "CVV/CVC code detected in request body",
			Severity:    assertion.SeverityHigh,
			Enabled:     true,
			Deny: &assertion.ConditionSpec{
				On:        "body",
				Condition: "matches",
				Pattern:   `\b\d{3,4}\b`,
			},
		},
	}
}
