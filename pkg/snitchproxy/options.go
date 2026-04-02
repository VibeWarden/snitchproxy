package snitchproxy

import "log/slog"

// Option configures a SnitchProxy instance.
type Option func(*options)

type options struct {
	configFile string
	configData []byte
	mode       Mode
	listenAddr string
	adminAddr  string
	failOn     string
	logger     *slog.Logger
}

// WithConfigFile sets the path to a YAML config file.
func WithConfigFile(path string) Option {
	return func(o *options) {
		o.configFile = path
	}
}

// WithConfigBytes sets the raw YAML config data.
func WithConfigBytes(data []byte) Option {
	return func(o *options) {
		o.configData = data
	}
}

// WithMode sets the operating mode (proxy or decoy).
func WithMode(mode Mode) Option {
	return func(o *options) {
		o.mode = mode
	}
}

// WithListenAddr sets the listen address for the mode server.
func WithListenAddr(addr string) Option {
	return func(o *options) {
		o.listenAddr = addr
	}
}

// WithAdminAddr sets the listen address for the admin API server.
func WithAdminAddr(addr string) Option {
	return func(o *options) {
		o.adminAddr = addr
	}
}

// WithFailOn sets the severity threshold for failure.
// Valid values: "critical", "high", "warning", "info".
func WithFailOn(severity string) Option {
	return func(o *options) {
		o.failOn = severity
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) {
		o.logger = logger
	}
}
