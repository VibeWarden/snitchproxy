package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

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

// Option configures a Handler.
type Option func(*Handler)

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(h *Handler) {
		h.logger = logger
	}
}

// WithTransport sets the HTTP transport for upstream requests.
func WithTransport(transport http.RoundTripper) Option {
	return func(h *Handler) {
		h.transport = transport
	}
}

// Handler is an HTTP forward proxy that inspects traffic.
type Handler struct {
	evaluator Evaluator
	recorder  Recorder
	logger    *slog.Logger
	transport http.RoundTripper

	requestCounter uint64
	mu             sync.Mutex
}

// NewHandler creates a proxy handler.
func NewHandler(evaluator Evaluator, recorder Recorder, opts ...Option) *Handler {
	h := &Handler{
		evaluator: evaluator,
		recorder:  recorder,
		logger:    slog.Default(),
		transport: http.DefaultTransport,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ServeHTTP implements http.Handler.
// Handles both plain HTTP proxy requests and CONNECT tunneling.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	h.handlePlainHTTP(w, r)
}

func (h *Handler) nextRequestID() string {
	h.mu.Lock()
	h.requestCounter++
	id := h.requestCounter
	h.mu.Unlock()
	return fmt.Sprintf("req-%d", id)
}

func (h *Handler) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := h.nextRequestID()

	// Buffer request body for assertion evaluation.
	var bodyBuf bytes.Buffer
	if r.Body != nil {
		if _, err := io.Copy(&bodyBuf, r.Body); err != nil {
			h.logger.Warn("failed to read request body", "request_id", requestID, "error", err)
		}
		r.Body.Close()
		// Restore body so assertions and forwarding both see it.
		r.Body = io.NopCloser(bytes.NewReader(bodyBuf.Bytes()))
	}

	// Evaluate assertions.
	results := h.evaluator.Evaluate(r, requestID)
	h.recorder.Record(results)

	h.logger.Info("proxy request",
		"request_id", requestID,
		"method", r.Method,
		"url", r.URL.String(),
		"violations", len(assertion.Violations(results)),
	)

	// Prepare outgoing request.
	outReq := r.Clone(r.Context())
	outReq.RequestURI = "" // must be cleared for client requests
	// Reset body from buffer for forwarding.
	outReq.Body = io.NopCloser(bytes.NewReader(bodyBuf.Bytes()))

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		h.logger.Error("upstream request failed", "request_id", requestID, "error", err)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
			return
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers.
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body.
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.logger.Warn("failed to copy response body", "request_id", requestID, "error", err)
	}
}

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	requestID := h.nextRequestID()

	// Evaluate assertions on CONNECT request metadata (host, method).
	results := h.evaluator.Evaluate(r, requestID)
	h.recorder.Record(results)

	h.logger.Info("CONNECT request",
		"request_id", requestID,
		"host", r.Host,
		"violations", len(assertion.Violations(results)),
	)

	// Dial target.
	targetConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		h.logger.Error("failed to dial target", "request_id", requestID, "host", r.Host, "error", err)
		http.Error(w, fmt.Sprintf("Bad Gateway: %v", err), http.StatusBadGateway)
		return
	}

	// Hijack the client connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		h.logger.Error("hijack not supported", "request_id", requestID)
		http.Error(w, "Internal Server Error: hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		h.logger.Error("hijack failed", "request_id", requestID, "error", err)
		return
	}

	// Write 200 Connection Established after hijacking to avoid
	// http.ResponseWriter adding extra headers.
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy.
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		io.Copy(targetConn, clientConn) //nolint:errcheck
	}()
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		io.Copy(clientConn, targetConn) //nolint:errcheck
	}()
}
