package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    cliFlags
		wantErr string
	}{
		{
			name: "all flags provided",
			args: []string{"--mode", "proxy", "--config", "/etc/sp.yaml", "--listen", ":9090", "--admin", ":9999", "--fail-on", "critical"},
			want: cliFlags{
				mode:       "proxy",
				configPath: "/etc/sp.yaml",
				listenAddr: ":9090",
				adminAddr:  ":9999",
				failOn:     "critical",
			},
		},
		{
			name: "defaults applied",
			args: []string{"--mode", "decoy", "--config", "config.yaml"},
			want: cliFlags{
				mode:       "decoy",
				configPath: "config.yaml",
				listenAddr: ":8080",
				adminAddr:  ":9484",
			},
		},
		{
			name: "version flag short-circuits validation",
			args: []string{"--version"},
			want: cliFlags{
				version:    true,
				listenAddr: ":8080",
				adminAddr:  ":9484",
			},
		},
		{
			name:    "missing mode",
			args:    []string{"--config", "config.yaml"},
			wantErr: "--mode is required",
		},
		{
			name:    "invalid mode",
			args:    []string{"--mode", "mirror", "--config", "config.yaml"},
			wantErr: `--mode must be proxy or decoy, got "mirror"`,
		},
		{
			name:    "invalid fail-on",
			args:    []string{"--mode", "proxy", "--config", "c.yaml", "--fail-on", "extreme"},
			wantErr: `--fail-on must be one of critical, high, warning, info; got "extreme"`,
		},
		{
			name:    "unknown flag",
			args:    []string{"--unknown"},
			wantErr: "flag provided but not defined: -unknown",
		},
		{
			name: "fail-on warning",
			args: []string{"--mode", "decoy", "--config", "c.yaml", "--fail-on", "warning"},
			want: cliFlags{
				mode:       "decoy",
				configPath: "c.yaml",
				listenAddr: ":8080",
				adminAddr:  ":9484",
				failOn:     "warning",
			},
		},
		{
			name: "fail-on info",
			args: []string{"--mode", "proxy", "--config", "c.yaml", "--fail-on", "info"},
			want: cliFlags{
				mode:       "proxy",
				configPath: "c.yaml",
				listenAddr: ":8080",
				adminAddr:  ":9484",
				failOn:     "info",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFlags(tt.args)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
