package decoy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vibewarden/snitchproxy/internal/assertion"
)

// stubEvaluator records calls and returns configured results.
type stubEvaluator struct {
	mu      sync.Mutex
	calls   []evaluateCall
	results []assertion.Result
}

type evaluateCall struct {
	RequestID string
	Method    string
	Path      string
}

func (e *stubEvaluator) Evaluate(r *http.Request, requestID string) []assertion.Result {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, evaluateCall{
		RequestID: requestID,
		Method:    r.Method,
		Path:      r.URL.Path,
	})
	return e.results
}

func (e *stubEvaluator) getCalls() []evaluateCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]evaluateCall, len(e.calls))
	copy(out, e.calls)
	return out
}

// stubRecorder records calls to Record.
type stubRecorder struct {
	mu    sync.Mutex
	calls [][]assertion.Result
}

func (r *stubRecorder) Record(results []assertion.Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, results)
}

func (r *stubRecorder) getCalls() [][]assertion.Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]assertion.Result, len(r.calls))
	copy(out, r.calls)
	return out
}

func TestHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		path            string
		query           string
		headers         map[string]string
		body            string
		evalResults     []assertion.Result
		wantMethod      string
		wantPath        string
		wantBody        string
		wantQueryKeys   []string
		wantEvalCalled  bool
		wantRecordCount int
	}{
		{
			name:   "GET request echoes method and path",
			method: http.MethodGet,
			path:   "/api/test",
			wantMethod:      http.MethodGet,
			wantPath:        "/api/test",
			wantBody:        "",
			wantEvalCalled:  true,
			wantRecordCount: 1,
		},
		{
			name:   "POST request echoes body",
			method: http.MethodPost,
			path:   "/submit",
			body:   `{"key":"value"}`,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			wantMethod:      http.MethodPost,
			wantPath:        "/submit",
			wantBody:        `{"key":"value"}`,
			wantEvalCalled:  true,
			wantRecordCount: 1,
		},
		{
			name:   "request with query parameters",
			method: http.MethodGet,
			path:   "/search",
			query:  "q=hello&page=1",
			wantMethod:      http.MethodGet,
			wantPath:        "/search",
			wantBody:        "",
			wantQueryKeys:   []string{"q", "page"},
			wantEvalCalled:  true,
			wantRecordCount: 1,
		},
		{
			name:   "request with custom headers",
			method: http.MethodGet,
			path:   "/headers",
			headers: map[string]string{
				"X-Custom-Header": "custom-value",
				"Authorization":   "Bearer token123",
			},
			wantMethod:      http.MethodGet,
			wantPath:        "/headers",
			wantBody:        "",
			wantEvalCalled:  true,
			wantRecordCount: 1,
		},
		{
			name:   "evaluator results are recorded",
			method: http.MethodGet,
			path:   "/with-results",
			evalResults: []assertion.Result{
				{Assertion: "test-rule", Passed: true},
				{Assertion: "deny-auth", Passed: false, Violation: &assertion.Violation{
					Assertion: "deny-auth",
					Severity:  assertion.SeverityHigh,
					Detail:    "auth header present",
				}},
			},
			wantMethod:      http.MethodGet,
			wantPath:        "/with-results",
			wantBody:        "",
			wantEvalCalled:  true,
			wantRecordCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval := &stubEvaluator{results: tt.evalResults}
			rec := &stubRecorder{}
			logger := slog.Default()
			handler := NewHandler(eval, rec, WithLogger(logger))

			target := tt.path
			if tt.query != "" {
				target += "?" + tt.query
			}
			var bodyReader *strings.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := httptest.NewRequest(tt.method, target, bodyReader)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			var resp EchoResponse
			err := json.NewDecoder(w.Body).Decode(&resp)
			require.NoError(t, err)

			assert.Equal(t, tt.wantMethod, resp.Method)
			assert.Equal(t, tt.wantPath, resp.Path)
			assert.Equal(t, tt.wantBody, resp.Body)
			assert.NotEmpty(t, resp.RequestID)

			for k, v := range tt.headers {
				assert.Equal(t, v, http.Header(resp.Headers).Get(k),
					"expected header %s=%s in echo response", k, v)
			}

			if len(tt.wantQueryKeys) > 0 {
				for _, key := range tt.wantQueryKeys {
					assert.Contains(t, resp.Query, key)
				}
			}

			if tt.wantEvalCalled {
				calls := eval.getCalls()
				require.Len(t, calls, 1)
				assert.Equal(t, tt.wantMethod, calls[0].Method)
				assert.Equal(t, tt.wantPath, calls[0].Path)
			}

			recCalls := rec.getCalls()
			assert.Len(t, recCalls, tt.wantRecordCount)
			if tt.evalResults != nil && len(recCalls) > 0 {
				assert.Equal(t, tt.evalResults, recCalls[0])
			}
		})
	}
}

func TestHandler_RequestIDUniqueness(t *testing.T) {
	eval := &stubEvaluator{}
	rec := &stubRecorder{}
	handler := NewHandler(eval, rec)

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		var resp EchoResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)

		assert.False(t, ids[resp.RequestID], "duplicate request ID: %s", resp.RequestID)
		ids[resp.RequestID] = true
	}

	assert.Len(t, ids, 100)
}

func TestHandler_EvaluatorCalled(t *testing.T) {
	eval := &stubEvaluator{
		results: []assertion.Result{
			{Assertion: "test", Passed: true},
		},
	}
	rec := &stubRecorder{}
	handler := NewHandler(eval, rec)

	req := httptest.NewRequest(http.MethodPost, "/api/data", strings.NewReader("secret"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	calls := eval.getCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, http.MethodPost, calls[0].Method)
	assert.Equal(t, "/api/data", calls[0].Path)
	assert.NotEmpty(t, calls[0].RequestID)
}

func TestHandler_RecorderCalled(t *testing.T) {
	results := []assertion.Result{
		{Assertion: "rule-1", Passed: true},
		{Assertion: "rule-2", Passed: false, Violation: &assertion.Violation{
			Assertion: "rule-2",
			Severity:  assertion.SeverityCritical,
		}},
	}
	eval := &stubEvaluator{results: results}
	rec := &stubRecorder{}
	handler := NewHandler(eval, rec)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	recCalls := rec.getCalls()
	require.Len(t, recCalls, 1)
	assert.Equal(t, results, recCalls[0])
}
