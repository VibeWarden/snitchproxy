package config

import (
	"github.com/vibewarden/snitchproxy/internal/assertion"
)

// ToAssertions converts validated config assertions into domain types.
// Call Validate first; this function assumes valid input.
func ToAssertions(cfgAssertions []AssertionConfig) []assertion.Assertion {
	result := make([]assertion.Assertion, 0, len(cfgAssertions))

	for _, ca := range cfgAssertions {
		a := assertion.Assertion{
			Name:        ca.Name,
			Description: ca.Description,
			Severity:    convertSeverity(ca.Severity),
			Enabled:     convertEnabled(ca.Enabled),
		}

		if ca.Match != nil {
			a.Match = convertMatch(ca.Match)
		}

		if ca.Deny != nil {
			a.Deny = convertCondition(ca.Deny)
		}

		if ca.Allow != nil {
			a.Allow = convertCondition(ca.Allow)
		}

		result = append(result, a)
	}

	return result
}

// convertSeverity maps a config severity string to the domain type.
// Defaults to high if empty.
func convertSeverity(s string) assertion.Severity {
	if s == "" {
		return assertion.SeverityHigh
	}
	return assertion.Severity(s)
}

// convertEnabled maps a *bool to a bool, defaulting to true.
func convertEnabled(b *bool) bool {
	if b == nil {
		return true
	}
	return *b
}

// convertMatch converts a config MatchConfig to the domain MatchSpec.
func convertMatch(m *MatchConfig) *assertion.MatchSpec {
	return &assertion.MatchSpec{
		Hosts:   []string(m.Host),
		Paths:   []string(m.Path),
		Methods: []string(m.Method),
		Headers: m.Header,
	}
}

// convertCondition recursively converts a config ConditionConfig to a domain ConditionSpec.
func convertCondition(c *ConditionConfig) *assertion.ConditionSpec {
	spec := &assertion.ConditionSpec{
		Header:    c.Header,
		On:        c.On,
		Param:     c.Param,
		Condition: c.Condition,
		Pattern:   c.Pattern,
	}

	// Map StringOrSlice to Value/Values.
	if len(c.Value) > 1 {
		spec.Values = []string(c.Value)
	} else if len(c.Value) == 1 {
		spec.Value = c.Value[0]
	}

	// Convert compound conditions.
	if len(c.All) > 0 {
		spec.All = make([]assertion.ConditionSpec, 0, len(c.All))
		for _, sub := range c.All {
			spec.All = append(spec.All, *convertCondition(&sub))
		}
	}

	return spec
}
