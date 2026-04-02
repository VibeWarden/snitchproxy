package main

import (
	"errors"
	"flag"
	"fmt"
)

// cliFlags holds parsed command-line arguments.
type cliFlags struct {
	mode       string // "proxy" or "decoy"
	configPath string // path to config file
	listenAddr string // e.g. ":8080"
	adminAddr  string // e.g. ":9484"
	failOn     string // severity override, empty means use config value
	version    bool   // print version and exit
}

// parseFlags parses CLI flags from the given args.
// Uses the standard library flag package.
func parseFlags(args []string) (cliFlags, error) {
	fs := flag.NewFlagSet("snitchproxy", flag.ContinueOnError)

	var f cliFlags
	fs.StringVar(&f.mode, "mode", "", "operating mode: proxy or decoy")
	fs.StringVar(&f.configPath, "config", "", "path to YAML config file")
	fs.StringVar(&f.listenAddr, "listen", ":8080", "listen address for proxy/decoy server")
	fs.StringVar(&f.adminAddr, "admin", ":9484", "listen address for admin API server")
	fs.StringVar(&f.failOn, "fail-on", "", "severity threshold override (critical, high, warning, info)")
	fs.BoolVar(&f.version, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return cliFlags{}, err
	}

	if f.version {
		return f, nil
	}

	var errs []error

	if f.mode == "" {
		errs = append(errs, errors.New("--mode is required (proxy or decoy)"))
	} else if f.mode != "proxy" && f.mode != "decoy" {
		errs = append(errs, fmt.Errorf("--mode must be proxy or decoy, got %q", f.mode))
	}

	if f.failOn != "" {
		switch f.failOn {
		case "critical", "high", "warning", "info":
			// valid
		default:
			errs = append(errs, fmt.Errorf("--fail-on must be one of critical, high, warning, info; got %q", f.failOn))
		}
	}

	if len(errs) > 0 {
		return cliFlags{}, errors.Join(errs...)
	}

	return f, nil
}
