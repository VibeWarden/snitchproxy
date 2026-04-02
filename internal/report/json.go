package report

import (
	"encoding/json"

	"github.com/vibewarden/snitchproxy/internal/assertion"
)

// JSONReport is the top-level JSON report structure.
type JSONReport struct {
	TotalEvaluations int                   `json:"total_evaluations"`
	ViolationCount   int                   `json:"violation_count"`
	Violations       []assertion.Violation  `json:"violations"`
}

// FormatJSON formats violations as indented JSON.
func FormatJSON(violations []assertion.Violation, totalEvaluations int) ([]byte, error) {
	r := JSONReport{
		TotalEvaluations: totalEvaluations,
		ViolationCount:   len(violations),
		Violations:       violations,
	}
	if r.Violations == nil {
		r.Violations = []assertion.Violation{}
	}
	return json.MarshalIndent(r, "", "  ")
}
