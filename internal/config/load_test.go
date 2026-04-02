package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		check   func(t *testing.T, cfg *Config)
	}{
		{
			name: "valid config file",
			path: filepath.Join("..", "..", "testdata", "example-config.yaml"),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 2, len(cfg.Presets))
				assert.Equal(t, "common-auth", cfg.Presets[0])
				assert.Equal(t, "pii", cfg.Presets[1])
				assert.Equal(t, "high", string(cfg.FailOn))
				assert.Equal(t, 3, len(cfg.Assertions))
				assert.Equal(t, "no-internal-session", cfg.Assertions[0].Name)
				assert.Equal(t, "no-auth-to-analytics", cfg.Assertions[1].Name)
				assert.Equal(t, "stripe-payment-hardening", cfg.Assertions[2].Name)
			},
		},
		{
			name:    "missing file",
			path:    "/nonexistent/path/config.yaml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestLoadFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		check   func(t *testing.T, cfg *Config)
	}{
		{
			name: "valid YAML",
			data: []byte(`
fail-on: critical
assertions:
  - name: test-rule
    severity: high
    deny:
      header: X-Secret
      condition: present
`),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "critical", string(cfg.FailOn))
				require.Len(t, cfg.Assertions, 1)
				assert.Equal(t, "test-rule", cfg.Assertions[0].Name)
				assert.Equal(t, "high", cfg.Assertions[0].Severity)
				require.NotNil(t, cfg.Assertions[0].Deny)
				assert.Equal(t, "X-Secret", cfg.Assertions[0].Deny.Header)
				assert.Equal(t, "present", cfg.Assertions[0].Deny.Condition)
			},
		},
		{
			name: "empty bytes",
			data: []byte(""),
			check: func(t *testing.T, cfg *Config) {
				assert.Empty(t, cfg.Assertions)
			},
		},
		{
			name:    "invalid YAML",
			data:    []byte(":\n  :\n  - :\n  invalid: ["),
			wantErr: true,
		},
		{
			name: "string or slice single value",
			data: []byte(`
assertions:
  - name: test
    severity: high
    match:
      host: "api.example.com"
    deny:
      header: X-Token
      condition: present
`),
			check: func(t *testing.T, cfg *Config) {
				require.Len(t, cfg.Assertions, 1)
				require.NotNil(t, cfg.Assertions[0].Match)
				assert.Equal(t, StringOrSlice{"api.example.com"}, cfg.Assertions[0].Match.Host)
			},
		},
		{
			name: "string or slice multiple values",
			data: []byte(`
assertions:
  - name: test
    severity: high
    match:
      host:
        - "api.example.com"
        - "api.other.com"
    deny:
      header: X-Token
      condition: present
`),
			check: func(t *testing.T, cfg *Config) {
				require.Len(t, cfg.Assertions, 1)
				require.NotNil(t, cfg.Assertions[0].Match)
				assert.Equal(t, StringOrSlice{"api.example.com", "api.other.com"}, cfg.Assertions[0].Match.Host)
			},
		},
		{
			name: "all compound condition",
			data: []byte(`
assertions:
  - name: compound
    severity: critical
    allow:
      all:
        - header: Content-Type
          condition: equals
          value: "application/json"
        - on: tls
          condition: version-gte
          value: "1.2"
`),
			check: func(t *testing.T, cfg *Config) {
				require.Len(t, cfg.Assertions, 1)
				require.NotNil(t, cfg.Assertions[0].Allow)
				require.Len(t, cfg.Assertions[0].Allow.All, 2)
				assert.Equal(t, "Content-Type", cfg.Assertions[0].Allow.All[0].Header)
				assert.Equal(t, "tls", cfg.Assertions[0].Allow.All[1].On)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadFromBytes(tt.data)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestLoadExampleConfig(t *testing.T) {
	// Verify the example config file from testdata can be fully loaded.
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "example-config.yaml"))
	require.NoError(t, err)

	cfg, err := LoadFromBytes(data)
	require.NoError(t, err)

	// Verify the stripe assertion has an allow block with all conditions.
	stripe := cfg.Assertions[2]
	assert.Equal(t, "stripe-payment-hardening", stripe.Name)
	require.NotNil(t, stripe.Allow)
	require.Len(t, stripe.Allow.All, 3)
}
