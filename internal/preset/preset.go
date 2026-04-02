// Package preset provides built-in assertion rule packs for common
// compliance and security scenarios (PCI-DSS, AWS keys, PII, etc.).
package preset

import (
	"fmt"

	"github.com/vibewarden/snitchproxy/internal/assertion"
)

// registry maps preset names to their assertion-generating functions.
var registry = map[string]func() []assertion.Assertion{
	"pci-dss":     pciDSS,
	"aws-keys":    awsKeys,
	"common-auth": commonAuth,
	"pii":         pii,
	"gcp-keys":    gcpKeys,
	"private-net": privateNet,
}

// registryOrder defines the stable iteration order for registry keys.
var registryOrder = []string{
	"pci-dss",
	"aws-keys",
	"common-auth",
	"pii",
	"gcp-keys",
	"private-net",
}

// Expand returns all assertions for the named presets.
// Returns an error if any preset name is unknown.
// Duplicate preset names in input are deduplicated silently.
func Expand(names []string) ([]assertion.Assertion, error) {
	seen := make(map[string]bool, len(names))
	var result []assertion.Assertion
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		fn, ok := registry[name]
		if !ok {
			return nil, fmt.Errorf("unknown preset: %q", name)
		}
		result = append(result, fn()...)
	}
	return result, nil
}

// Merge combines preset assertions with user assertions.
// User assertions whose name matches a preset assertion override the preset version.
// If the user assertion sets Enabled=false, the preset rule is removed.
// Non-matching user assertions are appended.
func Merge(presetAssertions, userAssertions []assertion.Assertion) []assertion.Assertion {
	// Build ordered map of preset assertions by name.
	presetMap := make(map[string]assertion.Assertion, len(presetAssertions))
	var presetOrder []string
	for _, a := range presetAssertions {
		presetMap[a.Name] = a
		presetOrder = append(presetOrder, a.Name)
	}

	// Process user assertions.
	var appended []assertion.Assertion
	for _, ua := range userAssertions {
		if _, exists := presetMap[ua.Name]; exists {
			if !ua.Enabled {
				// Delete from preset map.
				delete(presetMap, ua.Name)
			} else {
				// Replace in preset map.
				presetMap[ua.Name] = ua
			}
		} else {
			appended = append(appended, ua)
		}
	}

	// Collect remaining presets in stable order + appended user assertions.
	var result []assertion.Assertion
	for _, name := range presetOrder {
		if a, ok := presetMap[name]; ok {
			result = append(result, a)
		}
	}
	result = append(result, appended...)
	return result
}
