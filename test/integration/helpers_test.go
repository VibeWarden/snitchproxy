package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/vibewarden/snitchproxy/pkg/snitchproxy"
)

// startDecoy creates and starts a snitchproxy in decoy mode with the given config YAML.
// Returns the SnitchProxy instance and the base URLs for mode and admin servers.
func startDecoy(t *testing.T, configYAML string) (sp *snitchproxy.SnitchProxy, modeURL string, adminURL string) {
	t.Helper()

	sp, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(configYAML)),
		snitchproxy.WithMode(snitchproxy.ModeDecoy),
		snitchproxy.WithListenAddr(":0"),
		snitchproxy.WithAdminAddr(":0"),
	)
	if err != nil {
		t.Fatalf("creating decoy snitchproxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		sp.Close()
	})

	if err := sp.Start(ctx); err != nil {
		t.Fatalf("starting decoy snitchproxy: %v", err)
	}

	modeURL = fmt.Sprintf("http://%s", sp.ListenAddr())
	adminURL = fmt.Sprintf("http://%s", sp.AdminAddr())
	return sp, modeURL, adminURL
}

// startProxy creates and starts a snitchproxy in proxy mode with the given config YAML.
// Returns the SnitchProxy instance and the mode/admin URLs.
func startProxy(t *testing.T, configYAML string) (sp *snitchproxy.SnitchProxy, proxyURL string, adminURL string) {
	t.Helper()

	sp, err := snitchproxy.New(
		snitchproxy.WithConfigBytes([]byte(configYAML)),
		snitchproxy.WithMode(snitchproxy.ModeProxy),
		snitchproxy.WithListenAddr(":0"),
		snitchproxy.WithAdminAddr(":0"),
	)
	if err != nil {
		t.Fatalf("creating proxy snitchproxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		sp.Close()
	})

	if err := sp.Start(ctx); err != nil {
		t.Fatalf("starting proxy snitchproxy: %v", err)
	}

	proxyURL = fmt.Sprintf("http://%s", sp.ListenAddr())
	adminURL = fmt.Sprintf("http://%s", sp.AdminAddr())
	return sp, proxyURL, adminURL
}

// recordedRequest stores a request received by the backend.
type recordedRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   string
}

// testBackend is a test HTTP server that records all requests.
type testBackend struct {
	Server   *httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
}

// startBackend creates a test HTTP server that records requests and returns 200 OK.
func startBackend(t *testing.T) *testBackend {
	t.Helper()

	tb := &testBackend{}
	tb.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		if r.Body != nil {
			var err error
			body, err = readAll(r.Body)
			if err != nil {
				t.Errorf("backend: failed to read body: %v", err)
			}
		}

		tb.mu.Lock()
		tb.requests = append(tb.requests, recordedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Header: r.Header.Clone(),
			Body:   string(body),
		})
		tb.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(tb.Server.Close)

	return tb
}

// Requests returns a copy of the recorded requests.
func (tb *testBackend) Requests() []recordedRequest {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	out := make([]recordedRequest, len(tb.requests))
	copy(out, tb.requests)
	return out
}

// readAll reads all bytes from a reader, handling nil.
func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf []byte
	tmp := make([]byte, 1024)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return buf, err
		}
	}
	return buf, nil
}
