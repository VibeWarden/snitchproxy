// Package engine wires together request handling and assertion evaluation.
// It receives HTTP requests (from either the proxy or decoy adapter),
// runs them through the assertion engine, and collects results.
package engine

import (
	"sync"

	"github.com/vibewarden/snitchproxy/internal/assertion"
)

// Report holds the accumulated results of all assertion evaluations.
type Report struct {
	mu         sync.Mutex
	violations []assertion.Violation
	total      int
}

// NewReport creates an empty report.
func NewReport() *Report {
	return &Report{}
}

// Record adds assertion results to the report.
func (r *Report) Record(results []assertion.Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, res := range results {
		r.total++
		if !res.Passed && res.Violation != nil {
			r.violations = append(r.violations, *res.Violation)
		}
	}
}

// Violations returns all recorded violations.
func (r *Report) Violations() []assertion.Violation {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]assertion.Violation, len(r.violations))
	copy(out, r.violations)
	return out
}

// TotalEvaluations returns the total number of assertion evaluations performed.
func (r *Report) TotalEvaluations() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

// HasViolationsAtOrAbove returns true if any violation meets or exceeds the given severity.
func (r *Report) HasViolationsAtOrAbove(threshold assertion.Severity) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.violations {
		if severityRank(v.Severity) >= severityRank(threshold) {
			return true
		}
	}
	return false
}

// Reset clears all collected violations and counters.
func (r *Report) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.violations = nil
	r.total = 0
}

func severityRank(s assertion.Severity) int {
	switch s {
	case assertion.SeverityCritical:
		return 4
	case assertion.SeverityHigh:
		return 3
	case assertion.SeverityWarning:
		return 2
	case assertion.SeverityInfo:
		return 1
	default:
		return 0
	}
}
