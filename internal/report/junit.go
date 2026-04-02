package report

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/vibewarden/snitchproxy/internal/assertion"
)

// JUnit XML types.

// JUnitTestSuites is the top-level element.
type JUnitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []JUnitTestSuite `xml:"testsuite"`
}

// JUnitTestSuite represents a single test suite.
type JUnitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Cases    []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase represents a single test case.
type JUnitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
}

// JUnitFailure records a test case failure.
type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// FormatJUnit formats violations as JUnit XML.
// Each unique assertion name becomes a test case. Violated assertions get a failure element.
func FormatJUnit(violations []assertion.Violation, totalEvaluations int) ([]byte, error) {
	// Group violations by assertion name (preserving first-seen order).
	type caseInfo struct {
		name      string
		failure   *JUnitFailure
	}

	seen := map[string]int{}
	var cases []caseInfo

	for _, v := range violations {
		if idx, ok := seen[v.Assertion]; ok {
			// Append detail to existing failure text.
			cases[idx].failure.Text += "\n" + v.Detail
			continue
		}
		seen[v.Assertion] = len(cases)
		cases = append(cases, caseInfo{
			name: v.Assertion,
			failure: &JUnitFailure{
				Message: v.Description,
				Type:    string(v.Severity),
				Text:    v.Detail,
			},
		})
	}

	// Build JUnit test cases.
	junitCases := make([]JUnitTestCase, 0, len(cases))
	for _, c := range cases {
		junitCases = append(junitCases, JUnitTestCase{
			Name:      c.name,
			ClassName: "snitchproxy",
			Failure:   c.failure,
		})
	}

	failures := len(cases)
	suite := JUnitTestSuite{
		Name:     "snitchproxy",
		Tests:    totalEvaluations,
		Failures: failures,
		Cases:    junitCases,
	}

	suites := JUnitTestSuites{
		Suites: []JUnitTestSuite{suite},
	}

	var buf strings.Builder
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(suites); err != nil {
		return nil, fmt.Errorf("encoding JUnit XML: %w", err)
	}
	return []byte(buf.String()), nil
}
