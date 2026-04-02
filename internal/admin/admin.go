// Package admin exposes the SnitchProxy admin HTTP API.
// This runs on a separate port from the proxy/decoy and provides
// health checks, report retrieval, and runtime management.
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/vibewarden/snitchproxy/internal/assertion"
	"github.com/vibewarden/snitchproxy/internal/engine"
	reportpkg "github.com/vibewarden/snitchproxy/internal/report"
)

const pathPrefix = "/__snitchproxy"

// Handler creates the admin API HTTP handler.
func Handler(report *engine.Report, assertions []assertion.Assertion, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(pathPrefix+"/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc(pathPrefix+"/report", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		violations := report.Violations()
		total := report.TotalEvaluations()

		format := r.URL.Query().Get("format")
		switch format {
		case "", "json":
			data, err := reportpkg.FormatJSON(violations, total)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
		case "sarif":
			data, err := reportpkg.FormatSARIF(violations, total)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
		case "junit":
			data, err := reportpkg.FormatJUnit(violations, total)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/xml")
			w.Write(data)
		default:
			http.Error(w, "unknown format: "+format, http.StatusBadRequest)
		}
	})

	mux.HandleFunc(pathPrefix+"/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(assertions)
	})

	mux.HandleFunc(pathPrefix+"/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		report.Reset()
		logger.Info("report reset via admin API")
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}
