package report

import (
	"encoding/json"

	"github.com/vibewarden/snitchproxy/internal/assertion"
)

// SARIF v2.1.0 types (only what we need, not the full spec).

// SARIFReport is the top-level SARIF report.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the tool that produced the results.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the primary component of the tool.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule describes a single analysis rule.
type SARIFRule struct {
	ID               string             `json:"id"`
	ShortDescription SARIFMessage       `json:"shortDescription"`
	DefaultConfig    SARIFDefaultConfig `json:"defaultConfiguration"`
}

// SARIFDefaultConfig holds default configuration for a rule.
type SARIFDefaultConfig struct {
	Level string `json:"level"`
}

// SARIFMessage is a simple text message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFResult represents a single finding.
type SARIFResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message SARIFMessage `json:"message"`
}

// sarifLevel maps assertion severity to SARIF level.
func sarifLevel(s assertion.Severity) string {
	switch s {
	case assertion.SeverityCritical, assertion.SeverityHigh:
		return "error"
	case assertion.SeverityWarning:
		return "warning"
	case assertion.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// FormatSARIF formats violations as a SARIF v2.1.0 JSON document.
func FormatSARIF(violations []assertion.Violation, totalEvaluations int) ([]byte, error) {
	// Build unique rules from violations.
	ruleIndex := map[string]int{}
	var rules []SARIFRule
	for _, v := range violations {
		if _, ok := ruleIndex[v.Assertion]; ok {
			continue
		}
		ruleIndex[v.Assertion] = len(rules)
		rules = append(rules, SARIFRule{
			ID:               v.Assertion,
			ShortDescription: SARIFMessage{Text: v.Description},
			DefaultConfig:    SARIFDefaultConfig{Level: sarifLevel(v.Severity)},
		})
	}

	// Build results.
	results := make([]SARIFResult, 0, len(violations))
	for _, v := range violations {
		results = append(results, SARIFResult{
			RuleID:  v.Assertion,
			Level:   sarifLevel(v.Severity),
			Message: SARIFMessage{Text: v.Detail},
		})
	}

	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "snitchproxy",
						Version:        "0.1.0",
						InformationURI: "https://github.com/vibewarden/snitchproxy",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	if report.Runs[0].Tool.Driver.Rules == nil {
		report.Runs[0].Tool.Driver.Rules = []SARIFRule{}
	}

	return json.MarshalIndent(report, "", "  ")
}
