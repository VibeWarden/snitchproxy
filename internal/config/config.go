// Package config handles parsing and validation of snitchproxy YAML configuration.
package config

import "github.com/vibewarden/snitchproxy/internal/assertion"

// Config is the top-level snitchproxy configuration.
type Config struct {
	Presets    []string          `yaml:"presets,omitempty"`
	FailOn     assertion.Severity `yaml:"fail-on,omitempty"`
	Assertions []AssertionConfig  `yaml:"assertions"`
}

// AssertionConfig is the YAML representation of a single assertion.
type AssertionConfig struct {
	Name        string          `yaml:"name"`
	Description string          `yaml:"description,omitempty"`
	Severity    string          `yaml:"severity"`
	Enabled     *bool           `yaml:"enabled,omitempty"` // pointer to distinguish unset from false
	Match       *MatchConfig    `yaml:"match,omitempty"`
	Deny        *ConditionConfig `yaml:"deny,omitempty"`
	Allow       *ConditionConfig `yaml:"allow,omitempty"`
}

// MatchConfig is the YAML representation of a match block.
type MatchConfig struct {
	Host    StringOrSlice     `yaml:"host,omitempty"`
	Path    StringOrSlice     `yaml:"path,omitempty"`
	Method  StringOrSlice     `yaml:"method,omitempty"`
	Header  map[string]string `yaml:"header,omitempty"`
}

// ConditionConfig is the YAML representation of a condition block.
type ConditionConfig struct {
	Header    string            `yaml:"header,omitempty"`
	On        string            `yaml:"on,omitempty"`
	Param     string            `yaml:"param,omitempty"`
	Condition string            `yaml:"condition,omitempty"`
	Value     StringOrSlice     `yaml:"value,omitempty"`
	Pattern   string            `yaml:"pattern,omitempty"`
	All       []ConditionConfig `yaml:"all,omitempty"`
}

// StringOrSlice is a YAML type that accepts either a single string or a list of strings.
// This allows users to write both:
//
//	host: "api.stripe.com"
//	host:
//	  - "api.stripe.com"
//	  - "api.adyen.com"
type StringOrSlice []string

// UnmarshalYAML implements custom YAML unmarshaling for StringOrSlice.
func (s *StringOrSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var single string
	if err := unmarshal(&single); err == nil {
		*s = []string{single}
		return nil
	}

	var slice []string
	if err := unmarshal(&slice); err != nil {
		return err
	}
	*s = slice
	return nil
}
