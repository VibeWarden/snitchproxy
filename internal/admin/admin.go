// Package admin exposes the SnitchProxy admin HTTP API.
// This runs on a separate port from the proxy/decoy and provides
// health checks, report retrieval, and runtime management.
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/vibewarden/snitchproxy/internal/engine"
)

const pathPrefix = "/__snitchproxy"

// Handler creates the admin API HTTP handler.
func Handler(report *engine.Report, logger *slog.Logger) http.Handler {
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

		format := r.URL.Query().Get("format")
		switch format {
		case "sarif":
			// TODO: SARIF output
			http.Error(w, "sarif format not yet implemented", http.StatusNotImplemented)
		case "junit":
			// TODO: JUnit output
			http.Error(w, "junit format not yet implemented", http.StatusNotImplemented)
		default:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"total_evaluations": report.TotalEvaluations(),
				"violations":        report.Violations(),
			})
		}
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
