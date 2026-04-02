package assertion

import (
	"net/http"
	"path"
	"strings"
)

// Matches reports whether the request matches the given spec.
// A nil spec matches all requests.
func Matches(spec *MatchSpec, r *http.Request) bool {
	if spec == nil {
		return true
	}
	if len(spec.Hosts) > 0 && !matchHost(spec.Hosts, r.Host) {
		return false
	}
	if len(spec.Paths) > 0 && !matchPath(spec.Paths, r.URL.Path) {
		return false
	}
	if len(spec.Methods) > 0 && !matchMethod(spec.Methods, r.Method) {
		return false
	}
	if len(spec.Headers) > 0 && !matchHeaders(spec.Headers, r.Header) {
		return false
	}
	return true
}

// matchHost checks if the request host matches any of the glob patterns.
func matchHost(patterns []string, host string) bool {
	// Strip port if present.
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	for _, p := range patterns {
		if globMatch(p, host) {
			return true
		}
	}
	return false
}

// matchPath checks if the request path matches any of the glob patterns (supports **).
func matchPath(patterns []string, reqPath string) bool {
	for _, p := range patterns {
		if pathGlobMatch(p, reqPath) {
			return true
		}
	}
	return false
}

// matchMethod checks if the request method matches any of the methods (case-insensitive).
func matchMethod(methods []string, method string) bool {
	upper := strings.ToUpper(method)
	for _, m := range methods {
		if strings.ToUpper(m) == upper {
			return true
		}
	}
	return false
}

// matchHeaders checks if all specified header patterns match (AND'd).
func matchHeaders(specs map[string]string, headers http.Header) bool {
	for name, pattern := range specs {
		values := headers.Values(name)
		if len(values) == 0 {
			return false
		}
		matched := false
		for _, v := range values {
			if globMatch(pattern, v) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// globMatch performs glob pattern matching where * matches any sequence of
// non-dot characters. This is used for host patterns.
func globMatch(pattern, value string) bool {
	// path.Match uses / as separator; for host matching we need . as separator.
	// We convert dots to slashes so path.Match's * behavior (non-separator match)
	// gives us the "non-dot" semantics we want.
	p := strings.ReplaceAll(pattern, ".", "/")
	v := strings.ReplaceAll(value, ".", "/")
	matched, err := path.Match(p, v)
	if err != nil {
		return false
	}
	return matched
}

// pathGlobMatch performs glob pattern matching with ** support for paths.
// * matches a single non-slash segment, ** matches zero or more segments.
func pathGlobMatch(pattern, reqPath string) bool {
	// Normalize: ensure leading slash, remove trailing slash (unless root).
	pattern = normalizePath(pattern)
	reqPath = normalizePath(reqPath)

	patParts := splitPath(pattern)
	pathParts := splitPath(reqPath)

	return matchParts(patParts, pathParts)
}

// normalizePath ensures consistent path representation.
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Remove trailing slash unless root.
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}

// splitPath splits a path into segments, skipping empty parts.
func splitPath(p string) []string {
	var parts []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

// matchParts recursively matches pattern parts against path parts.
func matchParts(patParts, pathParts []string) bool {
	pi := 0 // pattern index
	si := 0 // path segment index

	for pi < len(patParts) {
		if patParts[pi] == "**" {
			// ** matches zero or more segments.
			// If this is the last pattern part, match everything remaining.
			if pi == len(patParts)-1 {
				return true
			}
			// Try matching the rest of the pattern against every suffix of pathParts.
			for k := si; k <= len(pathParts); k++ {
				if matchParts(patParts[pi+1:], pathParts[k:]) {
					return true
				}
			}
			return false
		}

		// No more path segments but pattern still has parts.
		if si >= len(pathParts) {
			return false
		}

		// Use path.Match for single-segment glob (handles * and ?).
		matched, err := path.Match(patParts[pi], pathParts[si])
		if err != nil || !matched {
			return false
		}

		pi++
		si++
	}

	// Both must be exhausted.
	return si == len(pathParts)
}
