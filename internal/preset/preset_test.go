package preset

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vibewarden/snitchproxy/internal/assertion"
)

func TestExpand(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		wantErr   string
		wantMin   int  // minimum number of assertions expected
		wantEmpty bool // expect empty (but no error)
	}{
		{
			name:    "single valid preset",
			input:   []string{"pci-dss"},
			wantMin: 1,
		},
		{
			name:    "multiple valid presets",
			input:   []string{"pci-dss", "aws-keys"},
			wantMin: 2,
		},
		{
			name:    "unknown preset returns error",
			input:   []string{"pci-dss", "nonexistent"},
			wantErr: `unknown preset: "nonexistent"`,
		},
		{
			name:      "empty list returns nil",
			input:     []string{},
			wantEmpty: true,
		},
		{
			name:    "nil list returns nil",
			input:   nil,
			wantEmpty: true,
		},
		{
			name:    "duplicate preset names are deduplicated",
			input:   []string{"pci-dss", "pci-dss"},
			wantMin: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Expand(tt.input)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.wantEmpty {
				assert.Empty(t, got)
				return
			}
			assert.GreaterOrEqual(t, len(got), tt.wantMin)
		})
	}
}

func TestExpand_DuplicatesReturnSameCount(t *testing.T) {
	single, err := Expand([]string{"pci-dss"})
	require.NoError(t, err)

	doubled, err := Expand([]string{"pci-dss", "pci-dss"})
	require.NoError(t, err)

	assert.Equal(t, len(single), len(doubled), "duplicate preset names should be deduplicated")
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name    string
		presets []assertion.Assertion
		user    []assertion.Assertion
		want    []assertion.Assertion
	}{
		{
			name: "user overrides preset by name",
			presets: []assertion.Assertion{
				{Name: "pci-dss/credit-card-in-body", Severity: assertion.SeverityCritical, Enabled: true},
				{Name: "pci-dss/cvv-in-body", Severity: assertion.SeverityHigh, Enabled: true},
			},
			user: []assertion.Assertion{
				{Name: "pci-dss/credit-card-in-body", Severity: assertion.SeverityWarning, Enabled: true},
			},
			want: []assertion.Assertion{
				{Name: "pci-dss/credit-card-in-body", Severity: assertion.SeverityWarning, Enabled: true},
				{Name: "pci-dss/cvv-in-body", Severity: assertion.SeverityHigh, Enabled: true},
			},
		},
		{
			name: "user disables preset rule",
			presets: []assertion.Assertion{
				{Name: "pci-dss/credit-card-in-body", Severity: assertion.SeverityCritical, Enabled: true},
				{Name: "pci-dss/cvv-in-body", Severity: assertion.SeverityHigh, Enabled: true},
			},
			user: []assertion.Assertion{
				{Name: "pci-dss/credit-card-in-body", Enabled: false},
			},
			want: []assertion.Assertion{
				{Name: "pci-dss/cvv-in-body", Severity: assertion.SeverityHigh, Enabled: true},
			},
		},
		{
			name: "non-matching user assertions are appended",
			presets: []assertion.Assertion{
				{Name: "pci-dss/credit-card-in-body", Severity: assertion.SeverityCritical, Enabled: true},
			},
			user: []assertion.Assertion{
				{Name: "custom/my-rule", Severity: assertion.SeverityInfo, Enabled: true},
			},
			want: []assertion.Assertion{
				{Name: "pci-dss/credit-card-in-body", Severity: assertion.SeverityCritical, Enabled: true},
				{Name: "custom/my-rule", Severity: assertion.SeverityInfo, Enabled: true},
			},
		},
		{
			name: "stable order preserved",
			presets: []assertion.Assertion{
				{Name: "a", Enabled: true},
				{Name: "b", Enabled: true},
				{Name: "c", Enabled: true},
			},
			user: []assertion.Assertion{
				{Name: "b", Severity: assertion.SeverityWarning, Enabled: true},
				{Name: "extra", Enabled: true},
			},
			want: []assertion.Assertion{
				{Name: "a", Enabled: true},
				{Name: "b", Severity: assertion.SeverityWarning, Enabled: true},
				{Name: "c", Enabled: true},
				{Name: "extra", Enabled: true},
			},
		},
		{
			name:    "empty presets with user assertions",
			presets: nil,
			user: []assertion.Assertion{
				{Name: "custom/rule", Enabled: true},
			},
			want: []assertion.Assertion{
				{Name: "custom/rule", Enabled: true},
			},
		},
		{
			name: "empty user assertions returns presets unchanged",
			presets: []assertion.Assertion{
				{Name: "a", Enabled: true},
				{Name: "b", Enabled: true},
			},
			user: nil,
			want: []assertion.Assertion{
				{Name: "a", Enabled: true},
				{Name: "b", Enabled: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Merge(tt.presets, tt.user)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPresetFunctions(t *testing.T) {
	tests := []struct {
		name   string
		fn     func() []assertion.Assertion
		prefix string
	}{
		{"pci-dss", pciDSS, "pci-dss/"},
		{"aws-keys", awsKeys, "aws-keys/"},
		{"common-auth", commonAuth, "common-auth/"},
		{"pii", pii, "pii/"},
		{"gcp-keys", gcpKeys, "gcp-keys/"},
		{"private-net", privateNet, "private-net/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertions := tt.fn()
			require.NotEmpty(t, assertions, "preset %s should return non-empty assertions", tt.name)

			for _, a := range assertions {
				assert.True(t, strings.HasPrefix(a.Name, tt.prefix),
					"assertion %q should have prefix %q", a.Name, tt.prefix)
				assert.NotEmpty(t, a.Description, "assertion %q should have a description", a.Name)
				assert.NotEmpty(t, a.Severity, "assertion %q should have a severity", a.Name)
				assert.True(t, a.Enabled, "assertion %q should be enabled by default", a.Name)
				assert.True(t, a.Deny != nil || a.Allow != nil,
					"assertion %q should have a Deny or Allow condition", a.Name)
			}
		})
	}
}

func TestPresetNamingConvention(t *testing.T) {
	// Verify all assertions from all presets follow the <preset-name>/<rule-name> convention.
	for presetName, fn := range registry {
		assertions := fn()
		for _, a := range assertions {
			parts := strings.SplitN(a.Name, "/", 2)
			require.Len(t, parts, 2, "assertion name %q should contain exactly one /", a.Name)
			assert.Equal(t, presetName, parts[0],
				"assertion %q prefix should match preset name %q", a.Name, presetName)
			assert.NotEmpty(t, parts[1], "assertion %q should have a rule name after /", a.Name)
		}
	}
}

func TestRegistryContainsAllPresets(t *testing.T) {
	expected := []string{"pci-dss", "aws-keys", "common-auth", "pii", "gcp-keys", "private-net"}
	for _, name := range expected {
		_, ok := registry[name]
		assert.True(t, ok, "registry should contain preset %q", name)
	}
}
