// Package ruleshttp provides an http.RoundTripper that uses the Expr expression
// language (github.com/expr-lang/expr) to enforce rules on HTTP
// requests and responses.
//
// Two hook types are supported:
//
//   - pre_request: rules evaluated against the outgoing request before it
//     is sent.  The default decision is deny; the first rule whose match
//     expression is true and whose authorize expression is true allows the
//     request to proceed.
//
//   - pre_response: rules evaluated against the incoming response after it
//     is received.  The same logic applies.
//
// If no rules are configured for a phase, that phase denies all traffic.
//
// Configuration is loaded from a YAML file via [NewFromFile] or built
// programmatically with a [Config] value passed to [New].
package ruleshttp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"
)

// ErrDenied is returned when a request or response is denied by rules.
// Callers can use errors.Is to detect this case.
var ErrDenied = errors.New("ruleshttp: denied")

// RequestEnv is the environment exposed to pre_request Expr expressions.
// Field names are used directly in expression strings, e.g. Method == "GET".
type RequestEnv struct {
	// Method is the HTTP method (GET, POST, …).
	Method string `yaml:"method"`
	// Scheme is the URL scheme (http or https).
	Scheme string `yaml:"scheme"`
	// Path is the URL path component.
	Path string `yaml:"path"`
	// Host is the request host (from the Host header or URL).
	Host string `yaml:"host"`
	// Headers contains canonicalized header names mapped to all their values.
	// Keys follow Go's http.CanonicalHeaderKey format, e.g. "Content-Type".
	Headers map[string][]string `yaml:"headers"`
	// Body is the full request body decoded as a UTF-8 string.
	Body string `yaml:"body"`
	// Query contains URL query parameters mapped to all their values.
	Query map[string][]string `yaml:"query"`
}

// ResponseEnv is the environment exposed to pre_response Expr expressions.
type ResponseEnv struct {
	// StatusCode is the numeric HTTP status code, e.g. 200.
	StatusCode int `yaml:"status_code"`
	// Headers contains canonicalized response header names mapped to all their values.
	Headers map[string][]string `yaml:"headers"`
	// Body is the full response body decoded as a UTF-8 string.
	Body string `yaml:"body"`
	// Request is the original request environment.
	Request RequestEnv `yaml:"request"`
}

// Rule is a named pair of match and authorize Expr expressions.
// A rule applies to a request when match returns true.
// It allows the request when authorize returns true.
type Rule struct {
	Name      string `yaml:"name"`
	Match     string `yaml:"match"`
	Authorize string `yaml:"authorize"`
}

// Config holds the pre_request and pre_response rule lists loaded from YAML.
type Config struct {
	PreRequest  []Rule `yaml:"pre_request"`
	PreResponse []Rule `yaml:"pre_response"`
}

// parseConfig parses YAML bytes into a Config and validates it.
func parseConfig(data []byte) (Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("ruleshttp: parsing config: %w", err)
	}
	if len(cfg.PreRequest) == 0 && len(cfg.PreResponse) == 0 {
		return Config{}, fmt.Errorf("ruleshttp: no rules set")
	}
	for i, r := range cfg.PreRequest {
		if r.Match == "" {
			return Config{}, fmt.Errorf("ruleshttp: pre_request[%d] %q: match must not be empty (use ALL to match all)", i, r.Name)
		}
		if r.Authorize == "" {
			return Config{}, fmt.Errorf("ruleshttp: pre_request[%d] %q: authorize must not be empty (use ALL to allow all matches)", i, r.Name)
		}
	}
	for i, r := range cfg.PreResponse {
		if r.Match == "" {
			return Config{}, fmt.Errorf("ruleshttp: pre_response[%d] %q: match must not be empty (use ALL to match all)", i, r.Name)
		}
		if r.Authorize == "" {
			return Config{}, fmt.Errorf("ruleshttp: pre_response[%d] %q: authorize must not be empty (use ALL to allow all matches)", i, r.Name)
		}
	}
	return cfg, nil
}

// compiledRule pairs compiled Expr programs for match and authorize
// conditions with the rule's human-readable name for error messages.
type compiledRule struct {
	name      string
	match     *vm.Program
	authorize *vm.Program
}

// Transport is an http.RoundTripper that evaluates Expr expressions before
// sending requests and before returning responses.
type Transport struct {
	wrapped     http.RoundTripper
	preRequest  []compiledRule
	preResponse []compiledRule
	logger      *slog.Logger
	logAllows   bool
	logDenials  bool
}

// Option configures a Transport. If multiple logger options are provided,
// the last one takes effect.
type Option func(*Transport)

// WithRoundTripper sets the underlying RoundTripper used to make real HTTP
// calls. Defaults to http.DefaultTransport when not provided.
func WithRoundTripper(rt http.RoundTripper) Option {
	return func(t *Transport) {
		t.wrapped = rt
	}
}

// WithLogger attaches a [slog.Logger] that records only non-rule errors
// (transport failures, body read errors) at Error level.  Rule outcomes
// (allows and denials) are not logged.
//
// Every log entry includes the fields:
//   - err                      – the error returned by RoundTrip, if any
//   - pre_request_allowed      – whether the pre_request rules passed
//   - pre_request_allowed_rule – name of the rule that allowed the request
//   - pre_response_allowed     – whether the pre_response rules passed
//   - pre_response_allowed_rule – name of the rule that allowed the response
func WithLogger(logger *slog.Logger) Option {
	return func(t *Transport) {
		t.logger = logger
		t.logAllows = false
		t.logDenials = false
	}
}

// WithDenialLogger attaches a [slog.Logger] that records rule denials at
// Info level in addition to non-rule errors at Error level.
func WithDenialLogger(logger *slog.Logger) Option {
	return func(t *Transport) {
		t.logger = logger
		t.logAllows = false
		t.logDenials = true
	}
}

// WithAllowLogger attaches a [slog.Logger] that records rule allows at
// Info level in addition to non-rule errors at Error level.
func WithAllowLogger(logger *slog.Logger) Option {
	return func(t *Transport) {
		t.logger = logger
		t.logAllows = true
		t.logDenials = false
	}
}

// WithAllLogger attaches a [slog.Logger] that records every roundtrip —
// rule allows and denials at Info level, non-rule errors at Error level.
func WithAllLogger(logger *slog.Logger) Option {
	return func(t *Transport) {
		t.logger = logger
		t.logAllows = true
		t.logDenials = true
	}
}

// New creates a Transport from cfg.  It compiles all Expr expressions eagerly
// so that configuration errors are surfaced immediately rather than at
// request-time.
func New(cfg Config, opts ...Option) (*Transport, error) {
	// Because rules are default deny this is likely an error. It otherwise creates a Transport that denies all requests.
	if len(cfg.PreRequest) == 0 && len(cfg.PreResponse) == 0 {
		return nil, fmt.Errorf("ruleshttp: no rules set")
	}
	t := &Transport{wrapped: http.DefaultTransport}
	for _, o := range opts {
		o(t)
	}

	for i, rule := range cfg.PreRequest {
		matchProg, err := expr.Compile(resolveAlias(rule.Match), expr.Env(RequestEnv{}), expr.AsBool())
		if err != nil {
			return nil, fmt.Errorf("ruleshttp: pre_request[%d] %q match compile error: %w", i, rule.Name, err)
		}
		authProg, err := expr.Compile(resolveAlias(rule.Authorize), expr.Env(RequestEnv{}), expr.AsBool())
		if err != nil {
			return nil, fmt.Errorf("ruleshttp: pre_request[%d] %q authorize compile error: %w", i, rule.Name, err)
		}
		t.preRequest = append(t.preRequest, compiledRule{name: rule.Name, match: matchProg, authorize: authProg})
	}

	for i, rule := range cfg.PreResponse {
		matchProg, err := expr.Compile(resolveAlias(rule.Match), expr.Env(ResponseEnv{}), expr.AsBool())
		if err != nil {
			return nil, fmt.Errorf("ruleshttp: pre_response[%d] %q match compile error: %w", i, rule.Name, err)
		}
		authProg, err := expr.Compile(resolveAlias(rule.Authorize), expr.Env(ResponseEnv{}), expr.AsBool())
		if err != nil {
			return nil, fmt.Errorf("ruleshttp: pre_response[%d] %q authorize compile error: %w", i, rule.Name, err)
		}
		t.preResponse = append(t.preResponse, compiledRule{name: rule.Name, match: matchProg, authorize: authProg})
	}

	return t, nil
}

// NewFromFile reads a YAML config file at path and creates a Transport from it.
// It parses and validates the YAML, then calls [New].
func NewFromFile(path string, opts ...Option) (*Transport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ruleshttp: reading config %q: %w", path, err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		return nil, err
	}
	return New(cfg, opts...)
}

// roundtripLogEntry is the structured log record emitted once per RoundTrip.
// JSON tags match the slog output keys so tests can unmarshal directly into
// this type instead of using map[string]any.
type roundtripLogEntry struct {
	Level                  string  `json:"level"`
	Err                    *string `json:"err"`
	PreRequestAllowed      bool    `json:"pre_request_allowed"`
	PreRequestAllowedRule  string  `json:"pre_request_allowed_rule"`
	PreResponseAllowed     bool    `json:"pre_response_allowed"`
	PreResponseAllowedRule string  `json:"pre_response_allowed_rule"`
}

// logArgs returns the key-value pairs for a slog call. Level and Err are
// omitted — Level is controlled by the caller (Info vs Error) and Err is
// passed as-is so slog can render nil as JSON null.
func (e roundtripLogEntry) logArgs(err error) []any {
	return []any{
		"err", err,
		"pre_request_allowed", e.PreRequestAllowed,
		"pre_request_allowed_rule", e.PreRequestAllowedRule,
		"pre_response_allowed", e.PreResponseAllowed,
		"pre_response_allowed_rule", e.PreResponseAllowedRule,
	}
}

// RoundTrip implements http.RoundTripper.
//
// When pre_request rules are configured, they are evaluated in order; the
// first rule whose match expression is true and whose authorize expression
// is true allows the request.  If no rule allows, the request is rejected
// with ErrDenied.  An empty rules list denies all traffic.
// The same logic applies to pre_response rules.
//
// If a logger is configured via [WithLogger], a single wide log entry is
// emitted after the roundtrip completes.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, entry, err := t.roundtrip(req)
	if t.logger != nil {
		denied := errors.Is(err, ErrDenied)
		args := entry.logArgs(err)
		switch {
		case err != nil && !denied:
			// Transport or internal error: always log at Error.
			t.logger.Error("ruleshttp roundtrip", args...)
		case denied && t.logDenials:
			t.logger.Info("ruleshttp roundtrip", args...)
		case !denied && t.logAllows:
			t.logger.Info("ruleshttp roundtrip", args...)
		}
	}
	return resp, err
}

// roundtrip executes the full request/response cycle and returns the response,
// any error, and per-phase rule outcomes for logging.
func (t *Transport) roundtrip(req *http.Request) (*http.Response, roundtripLogEntry, error) {
	var entry roundtripLogEntry

	reqEnv, err := buildRequestEnv(req)
	if err != nil {
		return nil, entry, err
	}

	allowed, rule, err := evalRules(t.preRequest, reqEnv)
	if err != nil {
		return nil, entry, fmt.Errorf("ruleshttp: pre_request: %w", err)
	}
	entry.PreRequestAllowed = allowed
	entry.PreRequestAllowedRule = rule
	if !allowed {
		return nil, entry, fmt.Errorf("%w: pre_request denied %s %s", ErrDenied, req.Method, req.URL.Path)
	}

	resp, err := t.wrapped.RoundTrip(req)
	if err != nil {
		return nil, entry, err
	}
	origBody := resp.Body

	respEnv, err := buildResponseEnv(resp, reqEnv)
	if err != nil {
		origBody.Close()
		return nil, entry, err
	}
	// buildResponseEnv replaced resp.Body with a buffered copy;
	// close the original (now drained) body.
	origBody.Close()

	allowed, rule, err = evalRules(t.preResponse, respEnv)
	if err != nil {
		return nil, entry, fmt.Errorf("ruleshttp: pre_response: %w", err)
	}
	entry.PreResponseAllowed = allowed
	entry.PreResponseAllowedRule = rule
	if !allowed {
		return nil, entry, fmt.Errorf("%w: pre_response denied status %d %s %s",
			ErrDenied, resp.StatusCode, req.Method, req.URL.Path)
	}

	return resp, entry, nil
}

// evalRules evaluates each rule in order.  For each rule, it runs the
// match expression then the authorize expression.  The first rule that both
// matches and authorizes short-circuits and returns true.
//
// An empty rules slice denies all traffic (returns false).
func evalRules(rules []compiledRule, env any) (bool, string, error) {
	for _, r := range rules {
		matched, err := expr.Run(r.match, env)
		if err != nil {
			return false, "", fmt.Errorf("rule %q match: %w", r.name, err)
		}
		if !matched.(bool) {
			continue
		}
		authorized, err := expr.Run(r.authorize, env)
		if err != nil {
			return false, "", fmt.Errorf("rule %q authorize: %w", r.name, err)
		}
		if authorized.(bool) {
			return true, r.name, nil
		}
	}
	return false, "", nil
}

// resolveAlias substitutes well-known shorthand tokens before Expr compilation.
// ANY expands to "true", conveying "applies to any request" in match expressions.
// ALL expands to "true", conveying "authorize all matches" in authorize expressions.
func resolveAlias(s string) string {
	switch s {
	case "ANY", "ALL":
		return "true"
	}
	return s
}

// CheckRequest evaluates the pre_request rules against env and returns
// whether the request is allowed, the name of the matching rule, and any
// expression evaluation error.
func (t *Transport) CheckRequest(env RequestEnv) (bool, string, error) {
	return evalRules(t.preRequest, env)
}

// CheckResponse evaluates the pre_response rules against env and returns
// whether the response is allowed, the name of the matching rule, and any
// expression evaluation error.
func (t *Transport) CheckResponse(env ResponseEnv) (bool, string, error) {
	return evalRules(t.preResponse, env)
}

// buildRequestEnv constructs a RequestEnv from req.  If the request has a
// body it is fully read and restored so the wrapped transport can re-read it.
func buildRequestEnv(req *http.Request) (RequestEnv, error) {
	env := RequestEnv{
		Method:  req.Method,
		Scheme:  req.URL.Scheme,
		Path:    req.URL.Path,
		Host:    req.Host,
		Headers: map[string][]string(req.Header),
		Query:   map[string][]string(req.URL.Query()),
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return RequestEnv{}, fmt.Errorf("ruleshttp: reading request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		env.Body = string(body)
	}

	return env, nil
}

// buildResponseEnv constructs a ResponseEnv from resp.  The response body is
// fully read and restored so the caller can still read it.
func buildResponseEnv(resp *http.Response, reqEnv RequestEnv) (ResponseEnv, error) {
	env := ResponseEnv{
		StatusCode: resp.StatusCode,
		Headers:    map[string][]string(resp.Header),
		Request:    reqEnv,
	}

	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return ResponseEnv{}, fmt.Errorf("ruleshttp: reading response body: %w", err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		env.Body = string(body)
	}

	return env, nil
}
