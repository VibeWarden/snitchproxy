package config

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidationError represents a single validation problem.
type ValidationError struct {
	Field   string // e.g. "assertions[2].deny.condition"
	Message string
}

func (ve ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", ve.Field, ve.Message)
}

// ValidationErrors is a collection of validation problems.
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	msgs := make([]string, len(ve))
	for i, e := range ve {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "; ")
}

// validSeverities is the set of allowed severity values.
var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"warning":  true,
	"info":     true,
}

// validConditions maps each context (on value) to its valid conditions.
var validConditions = map[string]map[string]bool{
	"": {
		"present":     true,
		"equals":      true,
		"matches":     true,
		"not-matches": true,
	},
	"body": {
		"matches":  true,
		"contains": true,
	},
	"query": {
		"present": true,
		"matches": true,
	},
	"tls": {
		"version-gte":         true,
		"client-cert-present": true,
	},
	"source-ip": {
		"in-cidr": true,
	},
}

// validOnValues is the set of allowed on values.
var validOnValues = map[string]bool{
	"":          true,
	"body":      true,
	"query":     true,
	"tls":       true,
	"source-ip": true,
}

// Validate checks the parsed config for structural and semantic errors.
// It collects all errors rather than failing fast.
// Returns nil if the config is valid, or ValidationErrors with all problems.
func Validate(cfg *Config) error {
	var errs ValidationErrors

	// Validate fail-on value.
	if cfg.FailOn != "" && !validSeverities[string(cfg.FailOn)] {
		errs = append(errs, ValidationError{
			Field:   "fail-on",
			Message: fmt.Sprintf("invalid fail-on value %q; must be one of: critical, high, warning, info", cfg.FailOn),
		})
	}

	names := make(map[string]bool)

	for i, a := range cfg.Assertions {
		prefix := fmt.Sprintf("assertions[%d]", i)

		// Non-empty name.
		if a.Name == "" {
			errs = append(errs, ValidationError{
				Field:   prefix + ".name",
				Message: "must not be empty",
			})
		} else {
			// Unique name.
			if names[a.Name] {
				errs = append(errs, ValidationError{
					Field:   prefix + ".name",
					Message: fmt.Sprintf("duplicate assertion name %q", a.Name),
				})
			}
			names[a.Name] = true
		}

		// Exactly one of deny or allow.
		hasDeny := a.Deny != nil
		hasAllow := a.Allow != nil
		if hasDeny && hasAllow {
			errs = append(errs, ValidationError{
				Field:   prefix,
				Message: "must have exactly one of deny or allow, not both",
			})
		} else if !hasDeny && !hasAllow {
			errs = append(errs, ValidationError{
				Field:   prefix,
				Message: "must have exactly one of deny or allow",
			})
		}

		// Severity validation.
		if a.Severity != "" && !validSeverities[a.Severity] {
			errs = append(errs, ValidationError{
				Field:   prefix + ".severity",
				Message: fmt.Sprintf("invalid severity %q; must be one of: critical, high, warning, info", a.Severity),
			})
		}

		// Validate condition blocks.
		if a.Deny != nil {
			validateCondition(&errs, prefix+".deny", a.Deny)
		}
		if a.Allow != nil {
			validateCondition(&errs, prefix+".allow", a.Allow)
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errs
}

// validateCondition recursively validates a condition block.
func validateCondition(errs *ValidationErrors, prefix string, c *ConditionConfig) {
	// Compound condition (all block).
	if c.All != nil {
		if len(c.All) == 0 {
			*errs = append(*errs, ValidationError{
				Field:   prefix + ".all",
				Message: "must not be empty",
			})
		}
		for i, sub := range c.All {
			validateCondition(errs, fmt.Sprintf("%s.all[%d]", prefix, i), &sub)
		}
		return
	}

	// Leaf condition must have a condition field.
	if c.Condition == "" {
		*errs = append(*errs, ValidationError{
			Field:   prefix + ".condition",
			Message: "must not be empty",
		})
		return
	}

	// Validate on value.
	if !validOnValues[c.On] {
		*errs = append(*errs, ValidationError{
			Field:   prefix + ".on",
			Message: fmt.Sprintf("invalid on value %q; must be one of: body, query, tls, source-ip, or empty for header context", c.On),
		})
		return
	}

	// Validate condition is valid for the given on context.
	conditions, ok := validConditions[c.On]
	if ok && !conditions[c.Condition] {
		*errs = append(*errs, ValidationError{
			Field:   prefix + ".condition",
			Message: fmt.Sprintf("invalid condition %q for on=%q", c.Condition, c.On),
		})
	}

	// Context-specific field requirements.
	if c.On == "" && c.Header == "" {
		*errs = append(*errs, ValidationError{
			Field:   prefix + ".header",
			Message: "required for header context (on is empty)",
		})
	}
	if c.On == "query" && c.Param == "" {
		*errs = append(*errs, ValidationError{
			Field:   prefix + ".param",
			Message: "required for query context",
		})
	}

	// Validate pattern is a valid regex.
	if c.Pattern != "" {
		if _, err := regexp.Compile(c.Pattern); err != nil {
			*errs = append(*errs, ValidationError{
				Field:   prefix + ".pattern",
				Message: fmt.Sprintf("invalid regex pattern: %v", err),
			})
		}
	}
}
