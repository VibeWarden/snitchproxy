package decoy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/vibewarden/snitchproxy/internal/assertion"
)

// Evaluator runs assertions against a request.
type Evaluator interface {
	Evaluate(r *http.Request, requestID string) []assertion.Result
}

// Recorder stores assertion results.
type Recorder interface {
	Record(results []assertion.Result)
}

// EchoResponse is the JSON response returned by the decoy endpoint.
type EchoResponse struct {
	RequestID string              `json:"request_id"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Headers   map[string][]string `json:"headers"`
	Body      string              `json:"body"`
	Query     map[string][]string `json:"query,omitempty"`
}

// Handler is an http.Handler that echoes requests and evaluates assertions.
type Handler struct {
	evaluator Evaluator
	recorder  Recorder
	logger    *slog.Logger
	counter   atomic.Uint64
}

// Option configures a Handler.
type Option func(*Handler)

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(h *Handler) {
		h.logger = logger
	}
}

// NewHandler creates a decoy handler.
func NewHandler(evaluator Evaluator, recorder Recorder, opts ...Option) *Handler {
	h := &Handler{
		evaluator: evaluator,
		recorder:  recorder,
		logger:    slog.Default(),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := fmt.Sprintf("req-%d", h.counter.Add(1))

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("failed to read request body", "request_id", requestID, "error", err)
		http.Error(w, "failed to read request body", http.StatusInternalServerError)
		return
	}

	results := h.evaluator.Evaluate(r, requestID)
	h.recorder.Record(results)

	violations := assertion.Violations(results)
	h.logger.Info("request evaluated",
		"request_id", requestID,
		"method", r.Method,
		"path", r.URL.Path,
		"violations", len(violations),
	)

	resp := EchoResponse{
		RequestID: requestID,
		Method:    r.Method,
		Path:      r.URL.Path,
		Headers:   r.Header,
		Body:      string(body),
		Query:     r.URL.Query(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode response", "request_id", requestID, "error", err)
	}
}
