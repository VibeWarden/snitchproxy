package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vibewarden/snitchproxy/internal/admin"
	"github.com/vibewarden/snitchproxy/internal/assertion"
	"github.com/vibewarden/snitchproxy/internal/config"
	"github.com/vibewarden/snitchproxy/internal/decoy"
	"github.com/vibewarden/snitchproxy/internal/engine"
	"github.com/vibewarden/snitchproxy/internal/preset"
	"github.com/vibewarden/snitchproxy/internal/proxy"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "snitchproxy: %v\n", err)
		os.Exit(1)
	}
}

// run is the main logic, separated from main() for testability.
func run(args []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// 1. Parse flags.
	flags, err := parseFlags(args)
	if err != nil {
		return fmt.Errorf("parsing flags: %w", err)
	}

	// 2. If --version, print and return.
	if flags.version {
		fmt.Printf("snitchproxy %s\n", version)
		return nil
	}

	// 3. Load config.
	cfg, err := loadConfig(flags.configPath)
	if err != nil {
		return err
	}

	// 4. Validate config.
	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// 5. Expand presets.
	presetAssertions, err := preset.Expand(cfg.Presets)
	if err != nil {
		return fmt.Errorf("expanding presets: %w", err)
	}

	// 6. Convert user assertions.
	userAssertions := config.ToAssertions(cfg.Assertions)

	// 7. Merge preset and user assertions.
	merged := preset.Merge(presetAssertions, userAssertions)

	// 8. Resolve fail-on threshold.
	failOnValue := string(cfg.FailOn)
	if flags.failOn != "" {
		failOnValue = flags.failOn
	}
	failOnThreshold := config.ResolveFailOn(failOnValue)

	// 9. Create assertion engine.
	eng := assertion.NewEngine(merged)

	// 10. Create report.
	rpt := engine.NewReport()

	// 11. Create mode handler.
	var modeHandler http.Handler
	switch flags.mode {
	case "decoy":
		modeHandler = decoy.NewHandler(eng, rpt, decoy.WithLogger(logger))
	case "proxy":
		modeHandler = proxy.NewHandler(eng, rpt, proxy.WithLogger(logger))
	default:
		return fmt.Errorf("unknown mode: %s", flags.mode)
	}

	// 12. Create admin handler.
	adminHandler := admin.Handler(rpt, logger)

	// 13-14. Start servers.
	modeListener, err := net.Listen("tcp", flags.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", flags.listenAddr, err)
	}

	adminListener, err := net.Listen("tcp", flags.adminAddr)
	if err != nil {
		modeListener.Close()
		return fmt.Errorf("failed to listen on %s: %w", flags.adminAddr, err)
	}

	modeServer := &http.Server{Handler: modeHandler}
	adminServer := &http.Server{Handler: adminHandler}

	// Start serving in goroutines.
	serverErrCh := make(chan error, 2)
	go func() {
		if err := modeServer.Serve(modeListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- fmt.Errorf("mode server error: %w", err)
		}
	}()
	go func() {
		if err := adminServer.Serve(adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- fmt.Errorf("admin server error: %w", err)
		}
	}()

	// 15. Log startup info.
	logger.Info("snitchproxy started",
		"version", version,
		"mode", flags.mode,
		"listen", modeListener.Addr().String(),
		"admin", adminListener.Addr().String(),
		"assertions", len(merged),
		"fail_on", string(failOnThreshold),
	)

	// 16. Wait for signal or server error.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-serverErrCh:
		logger.Error("server error, shutting down", "error", err)
	}

	// 17. Graceful shutdown with 10s timeout.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var shutdownErrs []error
	if err := modeServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("mode server shutdown error", "error", err)
		shutdownErrs = append(shutdownErrs, err)
	}
	if err := adminServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("admin server shutdown error", "error", err)
		shutdownErrs = append(shutdownErrs, err)
	}

	// 18. Log final violation summary.
	violations := rpt.Violations()
	logger.Info("final violation summary",
		"total_evaluations", rpt.TotalEvaluations(),
		"violation_count", len(violations),
		"fail_on", string(failOnThreshold),
	)

	if len(shutdownErrs) > 0 {
		return fmt.Errorf("shutdown errors: %w", errors.Join(shutdownErrs...))
	}

	// 19. Return error if violations at or above fail-on threshold.
	if rpt.HasViolationsAtOrAbove(failOnThreshold) {
		return fmt.Errorf("violations detected at or above %s severity", failOnThreshold)
	}

	return nil
}

// loadConfig resolves the config from the --config flag or SNITCHPROXY_CONFIG env var.
func loadConfig(configPath string) (*config.Config, error) {
	if configPath != "" {
		cfg, err := config.Load(configPath)
		if err != nil {
			return nil, fmt.Errorf("loading config from %s: %w", configPath, err)
		}
		return cfg, nil
	}

	envVal := os.Getenv("SNITCHPROXY_CONFIG")
	if envVal == "" {
		return nil, errors.New("no config provided: use --config flag or set SNITCHPROXY_CONFIG env var")
	}

	// Heuristic: if it contains newlines and doesn't look like a file path, treat as inline YAML.
	if strings.Contains(envVal, "\n") && !strings.HasSuffix(envVal, ".yaml") && !strings.HasSuffix(envVal, ".yml") {
		cfg, err := config.LoadFromBytes([]byte(envVal))
		if err != nil {
			return nil, fmt.Errorf("loading inline config from SNITCHPROXY_CONFIG: %w", err)
		}
		return cfg, nil
	}

	cfg, err := config.Load(envVal)
	if err != nil {
		return nil, fmt.Errorf("loading config from SNITCHPROXY_CONFIG path %s: %w", envVal, err)
	}
	return cfg, nil
}
