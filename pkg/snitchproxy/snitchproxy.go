// Package snitchproxy provides the public API for embedding snitchproxy
// in other Go applications.
//
// This is the only public package in the module. Use it to programmatically
// start a snitchproxy instance, configure assertions, and retrieve results.
//
// Example:
//
//	sp, err := snitchproxy.New(
//	    snitchproxy.WithConfigFile("snitchproxy.yaml"),
//	    snitchproxy.WithMode(snitchproxy.ModeProxy),
//	    snitchproxy.WithListenAddr(":8080"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer sp.Close()
//
//	if err := sp.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// ... run your tests ...
//
//	violations := sp.Violations()
package snitchproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/vibewarden/snitchproxy/internal/admin"
	"github.com/vibewarden/snitchproxy/internal/assertion"
	"github.com/vibewarden/snitchproxy/internal/config"
	"github.com/vibewarden/snitchproxy/internal/decoy"
	"github.com/vibewarden/snitchproxy/internal/engine"
	"github.com/vibewarden/snitchproxy/internal/preset"
	"github.com/vibewarden/snitchproxy/internal/proxy"
)

// Mode represents the operating mode of snitchproxy.
type Mode string

const (
	ModeProxy Mode = "proxy"
	ModeDecoy Mode = "decoy"
)

// SnitchProxy is an embedded snitchproxy instance.
type SnitchProxy struct {
	cfg            *config.Config
	assertions     []assertion.Assertion
	engine         *assertion.Engine
	report         *engine.Report
	failOn         assertion.Severity
	mode           Mode
	listenAddr     string
	adminAddr      string
	modeServer     *http.Server
	adminServer    *http.Server
	modeListener   net.Listener
	adminListener  net.Listener
	logger         *slog.Logger
}

// New creates a configured SnitchProxy instance.
// It applies options, loads config, validates, expands presets, merges
// assertions, and creates the assertion engine and report collector.
func New(opts ...Option) (*SnitchProxy, error) {
	o := &options{
		mode:       ModeDecoy,
		listenAddr: ":0",
		adminAddr:  ":0",
	}
	for _, opt := range opts {
		opt(o)
	}

	if o.logger == nil {
		o.logger = slog.Default()
	}

	// Load config.
	var cfg *config.Config
	var err error
	switch {
	case o.configFile != "":
		cfg, err = config.Load(o.configFile)
		if err != nil {
			return nil, fmt.Errorf("loading config file: %w", err)
		}
	case len(o.configData) > 0:
		cfg, err = config.LoadFromBytes(o.configData)
		if err != nil {
			return nil, fmt.Errorf("loading config bytes: %w", err)
		}
	default:
		return nil, errors.New("no config provided: use WithConfigFile or WithConfigBytes")
	}

	// Validate.
	if err := config.Validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	// Expand presets.
	presetAssertions, err := preset.Expand(cfg.Presets)
	if err != nil {
		return nil, fmt.Errorf("expanding presets: %w", err)
	}

	// Convert and merge assertions.
	userAssertions := config.ToAssertions(cfg.Assertions)
	merged := preset.Merge(presetAssertions, userAssertions)

	// Resolve fail-on threshold.
	failOnValue := string(cfg.FailOn)
	if o.failOn != "" {
		failOnValue = o.failOn
	}
	failOn := config.ResolveFailOn(failOnValue)

	// Override mode if set in options.
	mode := o.mode

	// Create engine and report.
	eng := assertion.NewEngine(merged)
	rpt := engine.NewReport()

	return &SnitchProxy{
		cfg:        cfg,
		assertions: merged,
		engine:     eng,
		report:     rpt,
		failOn:     failOn,
		mode:       mode,
		listenAddr: o.listenAddr,
		adminAddr:  o.adminAddr,
		logger:     o.logger,
	}, nil
}

// Start starts the mode server and admin server in goroutines.
// Use the context for cancellation. When the context is cancelled,
// servers will be shut down gracefully.
func (sp *SnitchProxy) Start(ctx context.Context) error {
	// Create mode handler.
	var modeHandler http.Handler
	switch sp.mode {
	case ModeDecoy:
		modeHandler = decoy.NewHandler(sp.engine, sp.report, decoy.WithLogger(sp.logger))
	case ModeProxy:
		modeHandler = proxy.NewHandler(sp.engine, sp.report, proxy.WithLogger(sp.logger))
	default:
		return fmt.Errorf("unknown mode: %s", sp.mode)
	}

	// Create admin handler.
	adminHandler := admin.Handler(sp.report, sp.assertions, sp.logger)

	// Create listeners.
	modeListener, err := net.Listen("tcp", sp.listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", sp.listenAddr, err)
	}

	adminListener, err := net.Listen("tcp", sp.adminAddr)
	if err != nil {
		modeListener.Close()
		return fmt.Errorf("listen on %s: %w", sp.adminAddr, err)
	}

	sp.modeListener = modeListener
	sp.adminListener = adminListener
	sp.modeServer = &http.Server{Handler: modeHandler}
	sp.adminServer = &http.Server{Handler: adminHandler}

	// Start servers in goroutines.
	go func() {
		if err := sp.modeServer.Serve(modeListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			sp.logger.Error("mode server error", "error", err)
		}
	}()
	go func() {
		if err := sp.adminServer.Serve(adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			sp.logger.Error("admin server error", "error", err)
		}
	}()

	sp.logger.Info("snitchproxy started",
		"mode", sp.mode,
		"listen", modeListener.Addr().String(),
		"admin", adminListener.Addr().String(),
		"assertions", len(sp.assertions),
		"fail_on", string(sp.failOn),
	)

	return nil
}

// Close performs graceful shutdown of both servers with a 10-second timeout.
func (sp *SnitchProxy) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var errs []error
	if sp.modeServer != nil {
		if err := sp.modeServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("mode server shutdown: %w", err))
		}
	}
	if sp.adminServer != nil {
		if err := sp.adminServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("admin server shutdown: %w", err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Violations returns all recorded violations.
func (sp *SnitchProxy) Violations() []assertion.Violation {
	return sp.report.Violations()
}

// HasViolationsAtOrAbove reports whether any violation meets or exceeds the given severity.
func (sp *SnitchProxy) HasViolationsAtOrAbove(severity assertion.Severity) bool {
	return sp.report.HasViolationsAtOrAbove(severity)
}

// Reset clears all collected violations.
func (sp *SnitchProxy) Reset() {
	sp.report.Reset()
}

// ListenAddr returns the actual address the mode server is listening on.
// Useful when configured with ":0" for OS-assigned ports.
func (sp *SnitchProxy) ListenAddr() string {
	if sp.modeListener == nil {
		return ""
	}
	return sp.modeListener.Addr().String()
}

// AdminAddr returns the actual address the admin server is listening on.
func (sp *SnitchProxy) AdminAddr() string {
	if sp.adminListener == nil {
		return ""
	}
	return sp.adminListener.Addr().String()
}
