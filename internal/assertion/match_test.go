package assertion

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newRequest(method, url string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, url, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestMatches(t *testing.T) {
	tests := []struct {
		name string
		spec *MatchSpec
		req  *http.Request
		want bool
	}{
		// nil spec matches everything
		{
			name: "nil spec matches any request",
			spec: nil,
			req:  newRequest("GET", "http://example.com/foo", nil),
			want: true,
		},
		// empty spec matches everything
		{
			name: "empty spec matches any request",
			spec: &MatchSpec{},
			req:  newRequest("POST", "http://example.com/bar", nil),
			want: true,
		},

		// --- Host matching ---
		{
			name: "host exact match",
			spec: &MatchSpec{Hosts: []string{"api.stripe.com"}},
			req:  newRequest("GET", "http://api.stripe.com/v1/charges", nil),
			want: true,
		},
		{
			name: "host exact no match",
			spec: &MatchSpec{Hosts: []string{"api.stripe.com"}},
			req:  newRequest("GET", "http://api.github.com/repos", nil),
			want: false,
		},
		{
			name: "host wildcard matches single segment",
			spec: &MatchSpec{Hosts: []string{"*.stripe.com"}},
			req:  newRequest("GET", "http://api.stripe.com/v1", nil),
			want: true,
		},
		{
			name: "host wildcard does not match multi-segment",
			spec: &MatchSpec{Hosts: []string{"*.stripe.com"}},
			req:  newRequest("GET", "http://a.b.stripe.com/v1", nil),
			want: false,
		},
		{
			name: "host multiple patterns OR'd",
			spec: &MatchSpec{Hosts: []string{"api.stripe.com", "api.github.com"}},
			req:  newRequest("GET", "http://api.github.com/repos", nil),
			want: true,
		},
		{
			name: "host multiple patterns none match",
			spec: &MatchSpec{Hosts: []string{"api.stripe.com", "api.github.com"}},
			req:  newRequest("GET", "http://api.slack.com/channels", nil),
			want: false,
		},
		{
			name: "host with port stripped",
			spec: &MatchSpec{Hosts: []string{"localhost"}},
			req:  newRequest("GET", "http://localhost:8080/foo", nil),
			want: true,
		},
		{
			name: "host empty in request",
			spec: &MatchSpec{Hosts: []string{"example.com"}},
			req: func() *http.Request {
				r := newRequest("GET", "/foo", nil)
				r.Host = ""
				return r
			}(),
			want: false,
		},

		// --- Path matching ---
		{
			name: "path exact match",
			spec: &MatchSpec{Paths: []string{"/v1/charges"}},
			req:  newRequest("GET", "http://example.com/v1/charges", nil),
			want: true,
		},
		{
			name: "path exact no match",
			spec: &MatchSpec{Paths: []string{"/v1/charges"}},
			req:  newRequest("GET", "http://example.com/v2/charges", nil),
			want: false,
		},
		{
			name: "path single wildcard",
			spec: &MatchSpec{Paths: []string{"/v1/*"}},
			req:  newRequest("GET", "http://example.com/v1/charges", nil),
			want: true,
		},
		{
			name: "path single wildcard does not cross segments",
			spec: &MatchSpec{Paths: []string{"/v1/*"}},
			req:  newRequest("GET", "http://example.com/v1/charges/123", nil),
			want: false,
		},
		{
			name: "path double wildcard matches multiple segments",
			spec: &MatchSpec{Paths: []string{"/api/**"}},
			req:  newRequest("GET", "http://example.com/api/v1/users/123", nil),
			want: true,
		},
		{
			name: "path double wildcard matches zero segments",
			spec: &MatchSpec{Paths: []string{"/api/**"}},
			req:  newRequest("GET", "http://example.com/api", nil),
			want: true,
		},
		{
			name: "path double wildcard in middle",
			spec: &MatchSpec{Paths: []string{"/api/**/info"}},
			req:  newRequest("GET", "http://example.com/api/v1/users/info", nil),
			want: true,
		},
		{
			name: "path double wildcard in middle zero segments",
			spec: &MatchSpec{Paths: []string{"/api/**/info"}},
			req:  newRequest("GET", "http://example.com/api/info", nil),
			want: true,
		},
		{
			name: "path root",
			spec: &MatchSpec{Paths: []string{"/"}},
			req:  newRequest("GET", "http://example.com/", nil),
			want: true,
		},
		{
			name: "path root does not match subpath",
			spec: &MatchSpec{Paths: []string{"/"}},
			req:  newRequest("GET", "http://example.com/foo", nil),
			want: false,
		},
		{
			name: "path trailing slash normalization",
			spec: &MatchSpec{Paths: []string{"/api/v1"}},
			req:  newRequest("GET", "http://example.com/api/v1/", nil),
			want: true,
		},
		{
			name: "path multiple patterns OR'd",
			spec: &MatchSpec{Paths: []string{"/v1/*", "/v2/*"}},
			req:  newRequest("GET", "http://example.com/v2/charges", nil),
			want: true,
		},
		{
			name: "path no match",
			spec: &MatchSpec{Paths: []string{"/v1/*", "/v2/*"}},
			req:  newRequest("GET", "http://example.com/v3/charges", nil),
			want: false,
		},

		// --- Method matching ---
		{
			name: "method exact match",
			spec: &MatchSpec{Methods: []string{"GET"}},
			req:  newRequest("GET", "http://example.com/foo", nil),
			want: true,
		},
		{
			name: "method case insensitive",
			spec: &MatchSpec{Methods: []string{"get"}},
			req:  newRequest("GET", "http://example.com/foo", nil),
			want: true,
		},
		{
			name: "method multiple OR'd",
			spec: &MatchSpec{Methods: []string{"GET", "POST"}},
			req:  newRequest("POST", "http://example.com/foo", nil),
			want: true,
		},
		{
			name: "method no match",
			spec: &MatchSpec{Methods: []string{"GET", "POST"}},
			req:  newRequest("DELETE", "http://example.com/foo", nil),
			want: false,
		},

		// --- Header matching ---
		{
			name: "header exact match",
			spec: &MatchSpec{Headers: map[string]string{"Content-Type": "application/json"}},
			req:  newRequest("GET", "http://example.com/foo", map[string]string{"Content-Type": "application/json"}),
			want: true,
		},
		{
			name: "header glob match",
			spec: &MatchSpec{Headers: map[string]string{"Content-Type": "application/*"}},
			req:  newRequest("GET", "http://example.com/foo", map[string]string{"Content-Type": "application/json"}),
			want: true,
		},
		{
			name: "header no match",
			spec: &MatchSpec{Headers: map[string]string{"Content-Type": "text/*"}},
			req:  newRequest("GET", "http://example.com/foo", map[string]string{"Content-Type": "application/json"}),
			want: false,
		},
		{
			name: "header missing",
			spec: &MatchSpec{Headers: map[string]string{"Authorization": "Bearer *"}},
			req:  newRequest("GET", "http://example.com/foo", nil),
			want: false,
		},
		{
			name: "header glob with dots in value (JWT)",
			spec: &MatchSpec{Headers: map[string]string{"Authorization": "Bearer *"}},
			req:  newRequest("GET", "http://example.com/foo", map[string]string{"Authorization": "Bearer eyJ0.eXAi.OiJK"}),
			want: true,
		},
		{
			name: "headers multiple AND'd all match",
			spec: &MatchSpec{Headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer *",
			}},
			req: newRequest("GET", "http://example.com/foo", map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer tok_123",
			}),
			want: true,
		},
		{
			name: "headers multiple AND'd one fails",
			spec: &MatchSpec{Headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer *",
			}},
			req: newRequest("GET", "http://example.com/foo", map[string]string{
				"Content-Type": "application/json",
			}),
			want: false,
		},

		// --- Combined fields ---
		{
			name: "combined all match",
			spec: &MatchSpec{
				Hosts:   []string{"*.stripe.com"},
				Paths:   []string{"/v1/**"},
				Methods: []string{"POST"},
				Headers: map[string]string{"Authorization": "Bearer *"},
			},
			req: newRequest("POST", "http://api.stripe.com/v1/charges", map[string]string{
				"Authorization": "Bearer sk_test_123",
			}),
			want: true,
		},
		{
			name: "combined host fails",
			spec: &MatchSpec{
				Hosts:   []string{"*.stripe.com"},
				Paths:   []string{"/v1/**"},
				Methods: []string{"POST"},
			},
			req:  newRequest("POST", "http://api.github.com/v1/charges", nil),
			want: false,
		},
		{
			name: "combined method fails",
			spec: &MatchSpec{
				Hosts:   []string{"*.stripe.com"},
				Methods: []string{"POST"},
			},
			req:  newRequest("GET", "http://api.stripe.com/v1/charges", nil),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Matches(tt.spec, tt.req)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{"exact", "api.stripe.com", "api.stripe.com", true},
		{"exact no match", "api.stripe.com", "api.github.com", false},
		{"wildcard single segment", "*.stripe.com", "api.stripe.com", true},
		{"wildcard does not cross dot", "*.stripe.com", "a.b.stripe.com", false},
		{"wildcard at end", "api.*", "api.com", true},
		{"wildcard in middle", "api.*.com", "api.stripe.com", true},
		{"empty pattern empty value", "", "", true},
		{"question mark", "api.stripe.co?", "api.stripe.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := globMatch(tt.pattern, tt.value)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPathGlobMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"exact", "/v1/charges", "/v1/charges", true},
		{"exact no match", "/v1/charges", "/v2/charges", false},
		{"single wildcard", "/v1/*", "/v1/charges", true},
		{"single wildcard no cross", "/v1/*", "/v1/charges/123", false},
		{"double wildcard end", "/api/**", "/api/v1/users/123", true},
		{"double wildcard zero", "/api/**", "/api", true},
		{"double wildcard middle", "/api/**/info", "/api/v1/users/info", true},
		{"double wildcard middle zero", "/api/**/info", "/api/info", true},
		{"double wildcard middle no match", "/api/**/info", "/api/v1/users/detail", false},
		{"root matches root", "/", "/", true},
		{"root no match subpath", "/", "/foo", false},
		{"trailing slash ignored", "/api/v1", "/api/v1/", true},
		{"question mark", "/v?/charges", "/v1/charges", true},
		{"just double wildcard", "/**", "/anything/at/all", true},
		{"double wildcard matches root", "/**", "/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathGlobMatch(tt.pattern, tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}
