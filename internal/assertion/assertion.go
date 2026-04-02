// Package assertion implements the core assertion evaluation engine.
//
// An assertion defines a security check against outbound HTTP traffic.
// Each assertion has a match scope (which requests it applies to) and
// an allow/deny condition (what constitutes a violation).
package assertion

import (
	"net/http"
)

// Severity represents the impact level of an assertion violation.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

// Assertion is a single security check to evaluate against a request.
type Assertion struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Severity    Severity       `json:"severity"`
	Enabled     bool           `json:"enabled"`
	Match       *MatchSpec     `json:"match,omitempty"`
	Deny        *ConditionSpec `json:"deny,omitempty"`
	Allow       *ConditionSpec `json:"allow,omitempty"`
}

// MatchSpec defines which requests an assertion applies to.
// All specified fields are AND'd. Multiple values within a field are OR'd.
// A nil MatchSpec matches all requests.
type MatchSpec struct {
	Hosts   []string          `json:"hosts,omitempty"`   // glob patterns, OR'd
	Paths   []string          `json:"paths,omitempty"`   // glob patterns with ** support, OR'd
	Methods []string          `json:"methods,omitempty"` // HTTP methods, OR'd
	Headers map[string]string `json:"headers,omitempty"` // header name→glob pattern, AND'd
}

// ConditionSpec defines what to check in a request.
// For compound conditions, use the All field.
type ConditionSpec struct {
	// Simple condition fields
	Header    string `json:"header,omitempty"`    // header name to inspect
	On        string `json:"on,omitempty"`        // "body", "query", "tls", "source-ip"
	Param     string `json:"param,omitempty"`     // query parameter name (when On == "query")
	Condition string `json:"condition,omitempty"` // "present", "absent", "equals", "matches", "not-matches", "contains", "version-gte", "in-cidr", "client-cert-present"
	Value     string `json:"value,omitempty"`     // expected value for equals, version-gte, in-cidr
	Values    []string `json:"values,omitempty"`  // multi-value (e.g., multiple CIDRs for in-cidr)
	Pattern   string `json:"pattern,omitempty"`   // regex pattern for matches, not-matches

	// Compound: all conditions must pass (AND semantics)
	All []ConditionSpec `json:"all,omitempty"`
}

// Violation is the result of a failed assertion evaluation.
type Violation struct {
	Assertion   string   `json:"assertion"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Detail      string   `json:"detail"`
	RequestID   string   `json:"request_id"`
}

// Result is the outcome of evaluating a single assertion against a request.
type Result struct {
	Assertion string
	Passed    bool
	Violation *Violation // nil if passed
}

// Engine evaluates assertions against incoming requests.
type Engine struct {
	assertions []Assertion
}

// NewEngine creates an assertion engine with the given assertions.
func NewEngine(assertions []Assertion) *Engine {
	return &Engine{assertions: assertions}
}

// Evaluate runs all assertions against the given request and returns results.
func (e *Engine) Evaluate(r *http.Request, requestID string) []Result {
	var results []Result
	for _, a := range e.assertions {
		if !a.Enabled {
			continue
		}
		result := evaluate(a, r, requestID)
		results = append(results, result)
	}
	return results
}

// Violations returns only the failed results from an evaluation.
func Violations(results []Result) []Violation {
	var violations []Violation
	for _, r := range results {
		if !r.Passed && r.Violation != nil {
			violations = append(violations, *r.Violation)
		}
	}
	return violations
}

func evaluate(a Assertion, r *http.Request, requestID string) Result {
	// 1. Check match scope.
	if !Matches(a.Match, r) {
		return Result{Assertion: a.Name, Passed: true} // not in scope, auto-pass
	}

	// 2. Evaluate condition.
	var cond *ConditionSpec
	var isDeny bool
	if a.Deny != nil {
		cond = a.Deny
		isDeny = true
	} else {
		cond = a.Allow
		isDeny = false
	}

	cr := evalCondition(cond, r)

	// 3. Apply deny/allow semantics.
	var violated bool
	if isDeny {
		violated = cr.met // deny: condition true = violation
	} else {
		violated = !cr.met // allow: condition false = violation
	}

	if violated {
		return Result{
			Assertion: a.Name,
			Passed:    false,
			Violation: &Violation{
				Assertion:   a.Name,
				Description: a.Description,
				Severity:    a.Severity,
				Detail:      cr.detail,
				RequestID:   requestID,
			},
		}
	}
	return Result{Assertion: a.Name, Passed: true}
}
