package assertion

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// conditionResult holds the outcome of a single condition check.
type conditionResult struct {
	met    bool   // whether the condition was met
	detail string // human-readable explanation
}

// evalCondition evaluates a single ConditionSpec against a request.
func evalCondition(spec *ConditionSpec, r *http.Request) conditionResult {
	if spec == nil {
		return conditionResult{met: false, detail: "no condition specified"}
	}

	// Compound: all conditions must pass (AND semantics).
	if len(spec.All) > 0 {
		return evalAll(spec.All, r)
	}

	// Route to the appropriate condition evaluator.
	if spec.Header != "" {
		return evalHeaderCondition(spec, r)
	}
	switch spec.On {
	case "body":
		return evalBodyCondition(spec, r)
	case "query":
		return evalQueryCondition(spec, r)
	case "tls":
		return evalTLSCondition(spec, r)
	case "source-ip":
		return evalSourceIPCondition(spec, r)
	default:
		return conditionResult{met: false, detail: fmt.Sprintf("unknown condition context: %q", spec.On)}
	}
}

// evalHeaderCondition handles header-based conditions (present, equals, matches, not-matches).
func evalHeaderCondition(spec *ConditionSpec, r *http.Request) conditionResult {
	headerVal := r.Header.Get(spec.Header)

	switch spec.Condition {
	case "present":
		if headerVal != "" {
			return conditionResult{met: true, detail: fmt.Sprintf("header %q is present", spec.Header)}
		}
		return conditionResult{met: false, detail: fmt.Sprintf("header %q is not present", spec.Header)}

	case "equals":
		if headerVal == spec.Value {
			return conditionResult{met: true, detail: fmt.Sprintf("header %q equals %q", spec.Header, spec.Value)}
		}
		return conditionResult{met: false, detail: fmt.Sprintf("header %q is %q, expected %q", spec.Header, headerVal, spec.Value)}

	case "matches":
		matched, err := regexp.MatchString(spec.Pattern, headerVal)
		if err != nil {
			return conditionResult{met: false, detail: fmt.Sprintf("invalid regex %q: %v", spec.Pattern, err)}
		}
		if matched {
			return conditionResult{met: true, detail: fmt.Sprintf("header %q matches pattern %q", spec.Header, spec.Pattern)}
		}
		return conditionResult{met: false, detail: fmt.Sprintf("header %q does not match pattern %q", spec.Header, spec.Pattern)}

	case "not-matches":
		matched, err := regexp.MatchString(spec.Pattern, headerVal)
		if err != nil {
			return conditionResult{met: false, detail: fmt.Sprintf("invalid regex %q: %v", spec.Pattern, err)}
		}
		if !matched {
			return conditionResult{met: true, detail: fmt.Sprintf("header %q does not match pattern %q", spec.Header, spec.Pattern)}
		}
		return conditionResult{met: false, detail: fmt.Sprintf("header %q matches pattern %q", spec.Header, spec.Pattern)}

	default:
		return conditionResult{met: false, detail: fmt.Sprintf("unknown header condition: %q", spec.Condition)}
	}
}

// evalBodyCondition handles body-based conditions (matches, contains).
func evalBodyCondition(spec *ConditionSpec, r *http.Request) conditionResult {
	body, err := readBody(r)
	if err != nil {
		return conditionResult{met: false, detail: fmt.Sprintf("failed to read body: %v", err)}
	}

	switch spec.Condition {
	case "matches":
		matched, err := regexp.Match(spec.Pattern, body)
		if err != nil {
			return conditionResult{met: false, detail: fmt.Sprintf("invalid regex %q: %v", spec.Pattern, err)}
		}
		if matched {
			return conditionResult{met: true, detail: fmt.Sprintf("body matches pattern %q", spec.Pattern)}
		}
		return conditionResult{met: false, detail: fmt.Sprintf("body does not match pattern %q", spec.Pattern)}

	case "contains":
		if bytes.Contains(body, []byte(spec.Value)) {
			return conditionResult{met: true, detail: fmt.Sprintf("body contains %q", spec.Value)}
		}
		return conditionResult{met: false, detail: fmt.Sprintf("body does not contain %q", spec.Value)}

	default:
		return conditionResult{met: false, detail: fmt.Sprintf("unknown body condition: %q", spec.Condition)}
	}
}

// evalQueryCondition handles query parameter conditions (present, matches).
func evalQueryCondition(spec *ConditionSpec, r *http.Request) conditionResult {
	query := r.URL.Query()

	switch spec.Condition {
	case "present":
		if query.Has(spec.Param) {
			return conditionResult{met: true, detail: fmt.Sprintf("query param %q is present", spec.Param)}
		}
		return conditionResult{met: false, detail: fmt.Sprintf("query param %q is not present", spec.Param)}

	case "matches":
		val := query.Get(spec.Param)
		matched, err := regexp.MatchString(spec.Pattern, val)
		if err != nil {
			return conditionResult{met: false, detail: fmt.Sprintf("invalid regex %q: %v", spec.Pattern, err)}
		}
		if matched {
			return conditionResult{met: true, detail: fmt.Sprintf("query param %q matches pattern %q", spec.Param, spec.Pattern)}
		}
		return conditionResult{met: false, detail: fmt.Sprintf("query param %q does not match pattern %q", spec.Param, spec.Pattern)}

	default:
		return conditionResult{met: false, detail: fmt.Sprintf("unknown query condition: %q", spec.Condition)}
	}
}

// evalTLSCondition handles TLS conditions (version-gte, client-cert-present).
func evalTLSCondition(spec *ConditionSpec, r *http.Request) conditionResult {
	switch spec.Condition {
	case "version-gte":
		if r.TLS == nil {
			return conditionResult{met: false, detail: "no TLS connection"}
		}
		minVersion := tlsVersionNumber(spec.Value)
		if minVersion == 0 {
			return conditionResult{met: false, detail: fmt.Sprintf("unknown TLS version: %q", spec.Value)}
		}
		if r.TLS.Version >= minVersion {
			return conditionResult{met: true, detail: fmt.Sprintf("TLS version %s >= %s", tlsVersionName(r.TLS.Version), spec.Value)}
		}
		return conditionResult{met: false, detail: fmt.Sprintf("TLS version %s < %s", tlsVersionName(r.TLS.Version), spec.Value)}

	case "client-cert-present":
		if r.TLS == nil {
			return conditionResult{met: false, detail: "no TLS connection"}
		}
		if len(r.TLS.PeerCertificates) > 0 {
			return conditionResult{met: true, detail: "client certificate is present"}
		}
		return conditionResult{met: false, detail: "no client certificate"}

	default:
		return conditionResult{met: false, detail: fmt.Sprintf("unknown TLS condition: %q", spec.Condition)}
	}
}

// evalSourceIPCondition handles source IP conditions (in-cidr).
func evalSourceIPCondition(spec *ConditionSpec, r *http.Request) conditionResult {
	switch spec.Condition {
	case "in-cidr":
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// RemoteAddr might not have a port.
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return conditionResult{met: false, detail: fmt.Sprintf("cannot parse remote address: %q", r.RemoteAddr)}
		}

		cidrs := spec.Values
		if len(cidrs) == 0 && spec.Value != "" {
			cidrs = []string{spec.Value}
		}

		for _, cidrStr := range cidrs {
			_, cidrNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				return conditionResult{met: false, detail: fmt.Sprintf("invalid CIDR %q: %v", cidrStr, err)}
			}
			if cidrNet.Contains(ip) {
				return conditionResult{met: true, detail: fmt.Sprintf("source IP %s is in CIDR %s", ip, cidrStr)}
			}
		}
		return conditionResult{met: false, detail: fmt.Sprintf("source IP %s is not in any specified CIDR", ip)}

	default:
		return conditionResult{met: false, detail: fmt.Sprintf("unknown source-ip condition: %q", spec.Condition)}
	}
}

// evalAll evaluates a compound all block (AND, short-circuit on first failure).
func evalAll(specs []ConditionSpec, r *http.Request) conditionResult {
	for i := range specs {
		cr := evalCondition(&specs[i], r)
		if !cr.met {
			return cr
		}
	}
	return conditionResult{met: true, detail: "all conditions met"}
}

// tlsVersionNumber converts a TLS version string to its numeric constant.
func tlsVersionNumber(name string) uint16 {
	switch strings.ToLower(name) {
	case "1.0", "tls1.0":
		return tls.VersionTLS10
	case "1.1", "tls1.1":
		return tls.VersionTLS11
	case "1.2", "tls1.2":
		return tls.VersionTLS12
	case "1.3", "tls1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

// tlsVersionName converts a TLS version number to a human-readable string.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}
