package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vibewarden/snitchproxy/internal/assertion"
)

// mockEvaluator records calls and returns configurable results.
type mockEvaluator struct {
	mu       sync.Mutex
	calls    []evaluateCall
	resultFn func(r *http.Request, requestID string) []assertion.Result
}

type evaluateCall struct {
	Method    string
	URL       string
	Host      string
	RequestID string
}

func (m *mockEvaluator) Evaluate(r *http.Request, requestID string) []assertion.Result {
	m.mu.Lock()
	m.calls = append(m.calls, evaluateCall{
		Method:    r.Method,
		URL:       r.URL.String(),
		Host:      r.Host,
		RequestID: requestID,
	})
	m.mu.Unlock()
	if m.resultFn != nil {
		return m.resultFn(r, requestID)
	}
	return []assertion.Result{{Assertion: "test", Passed: true}}
}

func (m *mockEvaluator) getCalls() []evaluateCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]evaluateCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// mockRecorder records calls to Record.
type mockRecorder struct {
	mu      sync.Mutex
	batches [][]assertion.Result
}

func (m *mockRecorder) Record(results []assertion.Result) {
	m.mu.Lock()
	m.batches = append(m.batches, results)
	m.mu.Unlock()
}

func (m *mockRecorder) getBatches() [][]assertion.Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]assertion.Result, len(m.batches))
	copy(out, m.batches)
	return out
}

// proxyClient returns an *http.Client configured to use proxyURL as its HTTP proxy.
func proxyClient(proxyURL string) *http.Client {
	pURL, _ := url.Parse(proxyURL)
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pURL),
		},
	}
}

func TestHandler_PlainHTTP(t *testing.T) {
	tests := []struct {
		name           string
		upstreamStatus int
		upstreamBody   string
		upstreamHeader map[string]string
		requestMethod  string
		requestBody    string
	}{
		{
			name:           "GET request forwarded and response returned",
			upstreamStatus: http.StatusOK,
			upstreamBody:   `{"status":"ok"}`,
			upstreamHeader: map[string]string{"X-Custom": "value"},
			requestMethod:  http.MethodGet,
		},
		{
			name:           "POST request with body forwarded",
			upstreamStatus: http.StatusCreated,
			upstreamBody:   `{"id":1}`,
			requestMethod:  http.MethodPost,
			requestBody:    `{"name":"test"}`,
		},
		{
			name:           "upstream returns 500",
			upstreamStatus: http.StatusInternalServerError,
			upstreamBody:   "error",
			requestMethod:  http.MethodGet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up upstream server.
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tt.upstreamHeader {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tt.upstreamStatus)
				w.Write([]byte(tt.upstreamBody)) //nolint:errcheck
			}))
			defer upstream.Close()

			eval := &mockEvaluator{}
			rec := &mockRecorder{}
			handler := NewHandler(eval, rec, WithLogger(slog.Default()))

			// Create proxy server.
			proxySrv := httptest.NewServer(handler)
			defer proxySrv.Close()

			// Build request with absolute URL (as forward proxy expects).
			var body io.Reader
			if tt.requestBody != "" {
				body = strings.NewReader(tt.requestBody)
			}
			req, err := http.NewRequest(tt.requestMethod, upstream.URL+"/test", body)
			require.NoError(t, err)

			// Send request through the proxy using a proxy-configured client.
			client := proxyClient(proxySrv.URL)
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Verify response matches upstream.
			assert.Equal(t, tt.upstreamStatus, resp.StatusCode)
			respBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, tt.upstreamBody, string(respBody))

			for k, v := range tt.upstreamHeader {
				assert.Equal(t, v, resp.Header.Get(k))
			}

			// Verify evaluator was called.
			calls := eval.getCalls()
			require.Len(t, calls, 1)
			assert.Equal(t, tt.requestMethod, calls[0].Method)
			assert.NotEmpty(t, calls[0].RequestID)

			// Verify recorder was called.
			batches := rec.getBatches()
			require.Len(t, batches, 1)
		})
	}
}

func TestHandler_CONNECT_Evaluation(t *testing.T) {
	eval := &mockEvaluator{
		resultFn: func(r *http.Request, requestID string) []assertion.Result {
			return []assertion.Result{
				{
					Assertion: "connect-check",
					Passed:    false,
					Violation: &assertion.Violation{
						Assertion:   "connect-check",
						Description: "CONNECT to blocked host",
						Severity:    assertion.SeverityHigh,
						Detail:      "host: " + r.Host,
						RequestID:   requestID,
					},
				},
			}
		},
	}
	rec := &mockRecorder{}
	handler := NewHandler(eval, rec, WithLogger(slog.Default()))

	// Use httptest.NewServer as a target to CONNECT to.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello")) //nolint:errcheck
	}))
	defer target.Close()

	// Create the proxy server.
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	// Issue a CONNECT request via the proxy-configured client transport.
	targetAddr := strings.TrimPrefix(target.URL, "http://")
	proxyURL, _ := url.Parse(proxySrv.URL)

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	// Make a CONNECT request by requesting an HTTPS URL through the proxy.
	// The transport will issue CONNECT to the proxy for any non-HTTP scheme,
	// but we can also directly issue CONNECT via RoundTrip.
	req, err := http.NewRequest(http.MethodConnect, "http://"+targetAddr, nil)
	require.NoError(t, err)
	req.Host = targetAddr
	// Set URL to point at the proxy so transport sends it there.
	req.URL = &url.URL{
		Scheme: "http",
		Host:   proxyURL.Host,
		Opaque: targetAddr,
	}

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify evaluator was called with CONNECT method.
	calls := eval.getCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, http.MethodConnect, calls[0].Method)
	assert.NotEmpty(t, calls[0].RequestID)

	// Verify recorder received results with violation.
	batches := rec.getBatches()
	require.Len(t, batches, 1)
	require.Len(t, batches[0], 1)
	assert.False(t, batches[0][0].Passed)
	assert.Equal(t, "connect-check", batches[0][0].Assertion)
}

func TestHandler_UnreachableUpstream(t *testing.T) {
	eval := &mockEvaluator{}
	rec := &mockRecorder{}
	handler := NewHandler(eval, rec, WithLogger(slog.Default()))

	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	// Request to an unreachable host, sent through the proxy.
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/unreachable", nil)
	require.NoError(t, err)

	client := proxyClient(proxySrv.URL)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "Bad Gateway")

	// Evaluator and recorder should still have been called.
	calls := eval.getCalls()
	require.Len(t, calls, 1)
	batches := rec.getBatches()
	require.Len(t, batches, 1)
}

func TestNewHandler_Defaults(t *testing.T) {
	eval := &mockEvaluator{}
	rec := &mockRecorder{}
	h := NewHandler(eval, rec)

	assert.NotNil(t, h.logger)
	assert.NotNil(t, h.transport)
	assert.NotNil(t, h.evaluator)
	assert.NotNil(t, h.recorder)
}

func TestNewHandler_Options(t *testing.T) {
	eval := &mockEvaluator{}
	rec := &mockRecorder{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &http.Transport{}

	h := NewHandler(eval, rec, WithLogger(logger), WithTransport(transport))

	assert.Equal(t, logger, h.logger)
	assert.Equal(t, transport, h.transport)
}
