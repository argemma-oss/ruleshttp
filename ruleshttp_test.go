package ruleshttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

func mustNewFromFile(t *testing.T, path string, opts ...Option) *Transport {
	t.Helper()
	tp, err := NewFromFile(path, opts...)
	if err != nil {
		t.Fatalf("NewFromFile(%q): %v", path, err)
	}
	return tp
}

func mustNew(t *testing.T, cfg Config, opts ...Option) *Transport {
	t.Helper()
	tp, err := New(cfg, opts...)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return tp
}

// allowAll is a rule that matches and authorizes every request/response.
// Used to fill the unconfigured phase in single-phase test configs.
var allowAll = Rule{Name: "allow-all", Match: "true", Authorize: "true"}

// simplePreRequestConfig builds a Config with a single pre_request rule
// containing one match and one authorize expression, without loading YAML.
// pre_response is set to allow-all so it does not interfere with the test.
func simplePreRequestConfig(match, authorize string) Config {
	return Config{
		PreRequest:  []Rule{{Name: "test", Match: match, Authorize: authorize}},
		PreResponse: []Rule{allowAll},
	}
}

// simplePreResponseConfig builds a Config with a single pre_response rule
// containing one match and one authorize expression, without loading YAML.
// pre_request is set to allow-all so it does not interfere with the test.
func simplePreResponseConfig(match, authorize string) Config {
	return Config{
		PreRequest:  []Rule{allowAll},
		PreResponse: []Rule{{Name: "test", Match: match, Authorize: authorize}},
	}
}

// mockTransport is an http.RoundTripper that returns a fixed response.
type mockTransport struct {
	resp *http.Response
	err  error
}

func (m *mockTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return m.resp, m.err
}

func makeResponse(code int, body string, headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: code,
		Status:     http.StatusText(code),
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestParseConfigValidFile(t *testing.T) {
	t.Parallel()
	path := "testdata/config.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", path, err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("parseConfig(%q) error = %v, want nil", path, err)
	}
	if got, want := len(cfg.PreRequest), 2; got != want {
		t.Errorf("cfg.PreRequest length = %v, want %v", got, want)
	}
	if got, want := len(cfg.PreResponse), 2; got != want {
		t.Errorf("cfg.PreResponse length = %v, want %v", got, want)
	}
}

func TestNewFromFileInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
	}{
		{
			name: "missing file",
			path: "/no/such/file.yaml",
		},
		{
			name: "empty config",
			path: "testdata/invalid/empty.yaml",
		},
		{
			name: "invalid YAML",
			path: "testdata/invalid/yaml.yaml",
		},
		{
			name: "pre_request rule missing match",
			path: "testdata/invalid/pre_request_no_match.yaml",
		},
		{
			name: "pre_request rule missing authorize",
			path: "testdata/invalid/pre_request_no_authorize.yaml",
		},
		{
			name: "pre_response rule missing match",
			path: "testdata/invalid/pre_response_no_match.yaml",
		},
		{
			name: "pre_response rule missing authorize",
			path: "testdata/invalid/pre_response_no_authorize.yaml",
		},
		{
			name: "invalid pre_request expr",
			path: "testdata/invalid/pre_request_expr.yaml",
		},
		{
			name: "invalid pre_response expr",
			path: "testdata/invalid/pre_response_expr.yaml",
		},
		{
			name: "non-bool pre_request expr",
			path: "testdata/invalid/non_bool_pre_request_expr.yaml",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewFromFile(tc.path); err == nil {
				t.Errorf("NewFromFile(%q) = nil, want error", tc.path)
			}
		})
	}
}

func TestNewEmptyConfig(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Error("New(Config{}) = nil, want error")
	}
}

// TestPreRequest covers the common case of a single pre_request rule with a
// single match expression and a single authorize expression. The want field
// indicates the expected outcome: allow (nil error) or deny (ErrDenied).
func TestPreRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		match     string
		authorize string
		reqFn     func() *http.Request
		wantDeny  bool
	}{
		// Method matching
		{
			name:      "GET allowed by method match",
			match:     `Method == "GET"`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("GET", "/foo", nil) },
		},
		{
			name:      "POST denied when only GET matches",
			match:     `Method == "GET"`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("POST", "/foo", nil) },
			wantDeny:  true,
		},
		// Path matching
		{
			name:      "path prefix allowed",
			match:     `Path startsWith "/api/"`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("GET", "/api/users", nil) },
		},
		{
			name:      "path prefix denied",
			match:     `Path startsWith "/api/"`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("GET", "/admin", nil) },
			wantDeny:  true,
		},
		// RequestEnv field coverage
		{
			name:      "Method field PUT",
			match:     `Method == "PUT"`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("PUT", "/x", nil) },
		},
		{
			name:      "Path field exact match",
			match:     `Path == "/foo/bar"`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("GET", "/foo/bar", nil) },
		},
		{
			name:      "Header field present allows",
			match:     `"hello" in Headers["X-Custom"]`,
			authorize: "ALL",
			reqFn: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Set("X-Custom", "hello")
				return r
			},
		},
		{
			name:      "Header field absent denies",
			match:     `"hello" in Headers["X-Custom"]`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("GET", "/", nil) },
			wantDeny:  true,
		},
		{
			name:      "Query field token present allows",
			match:     `"secret" in Query["token"]`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("GET", "/?token=secret", nil) },
		},
		{
			name:      "Body field matches",
			match:     `Body == "hello"`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("POST", "/", strings.NewReader("hello")) },
		},
		{
			name:      "Host field matches",
			match:     `Host == "example.com"`,
			authorize: "ALL",
			reqFn: func() *http.Request {
				r := httptest.NewRequest("GET", "http://example.com/", nil)
				r.Host = "example.com"
				return r
			},
		},
		{
			name:      "Scheme field http",
			match:     `Scheme == "http"`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("GET", "http://example.com/", nil) },
		},
		{
			name:      "Scheme field https",
			match:     `Scheme == "https"`,
			authorize: "ALL",
			reqFn:     func() *http.Request { return httptest.NewRequest("GET", "https://example.com/", nil) },
		},
		// Authorize expression (match passes, authorize rejects)
		{
			name:      "authorize expression denies",
			match:     "ANY",
			authorize: `Method == "GET"`,
			reqFn:     func() *http.Request { return httptest.NewRequest("POST", "/", nil) },
			wantDeny:  true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := simplePreRequestConfig(tc.match, tc.authorize)
			ok := &mockTransport{resp: makeResponse(200, "ok", nil)}
			transport := mustNew(t, cfg, WithRoundTripper(ok))
			_, err := transport.RoundTrip(tc.reqFn())
			if tc.wantDeny {
				if !errors.Is(err, ErrDenied) {
					t.Errorf("RoundTrip() error = %v, want ErrDenied", err)
				}
			} else {
				if err != nil {
					t.Errorf("RoundTrip() error = %v, want nil", err)
				}
			}
		})
	}
}

// TestPreResponse covers the common case of a single pre_response rule with a
// single match expression and a single authorize expression. reqFn is
// optional; nil uses GET /test. The wantDeny field indicates the expected outcome.
func TestPreResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		match     string
		authorize string
		respFn    func() *http.Response
		reqFn     func() *http.Request // nil → GET /test
		wantDeny  bool
	}{
		// StatusCode matching
		{
			name:      "2xx StatusCode allowed",
			match:     `StatusCode >= 200 && StatusCode < 300`,
			authorize: "ALL",
			respFn:    func() *http.Response { return makeResponse(200, "", nil) },
		},
		{
			name:      "5xx denied",
			match:     `StatusCode >= 200 && StatusCode < 300`,
			authorize: "ALL",
			respFn:    func() *http.Response { return makeResponse(503, "", nil) },
			wantDeny:  true,
		},
		// Body authorize expression
		{
			name:      "non-empty body allows",
			match:     "ANY",
			authorize: `Body != ""`,
			respFn:    func() *http.Response { return makeResponse(200, "some content", nil) },
		},
		{
			name:      "empty body denied",
			match:     "ANY",
			authorize: `Body != ""`,
			respFn:    func() *http.Response { return makeResponse(200, "", nil) },
			wantDeny:  true,
		},
		// Header authorize expression
		{
			name:      "json content-type allows",
			match:     "ANY",
			authorize: `any(Headers["Content-Type"], {# startsWith "application/json"})`,
			respFn: func() *http.Response {
				return makeResponse(200, "", map[string]string{"Content-Type": "application/json; charset=utf-8"})
			},
		},
		{
			name:      "missing content-type denied",
			match:     "ANY",
			authorize: `any(Headers["Content-Type"], {# startsWith "application/json"})`,
			respFn:    func() *http.Response { return makeResponse(200, "", nil) },
			wantDeny:  true,
		},
		// Request context available in pre_response expressions
		{
			name:      "request method in response match allows",
			match:     `Request.Method == "GET"`,
			authorize: `StatusCode == 200`,
			respFn:    func() *http.Response { return makeResponse(200, "", nil) },
		},
		{
			name:      "request method in response match skips non-GET",
			match:     `Request.Method == "GET"`,
			authorize: `StatusCode == 200`,
			respFn:    func() *http.Response { return makeResponse(200, "", nil) },
			reqFn:     func() *http.Request { return httptest.NewRequest("POST", "/test", nil) },
			wantDeny:  true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := simplePreResponseConfig(tc.match, tc.authorize)
			mock := &mockTransport{resp: tc.respFn()}
			transport := mustNew(t, cfg, WithRoundTripper(mock))
			req := httptest.NewRequest("GET", "/test", nil)
			if tc.reqFn != nil {
				req = tc.reqFn()
			}
			_, err := transport.RoundTrip(req)
			if tc.wantDeny {
				if !errors.Is(err, ErrDenied) {
					t.Errorf("RoundTrip() error = %v, want ErrDenied", err)
				}
			} else {
				if err != nil {
					t.Errorf("RoundTrip() error = %v, want nil", err)
				}
			}
		})
	}
}

func TestIntegration(t *testing.T) {
	t.Parallel()

	adminHit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/data":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"ok":true}`)
		case "/admin":
			adminHit = true
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)

	transport := mustNewFromFile(t, "testdata/integration.yaml")
	client := &http.Client{Transport: transport}

	// GET /data is allowed: pre_request checks Method AND Path (multiple conditions),
	// pre_response checks StatusCode AND Body. Body must still be readable after eval.
	resp, err := client.Get(srv.URL + "/data")
	if err != nil {
		t.Fatalf("GET /data error = %v, want nil", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("reading /data body: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("GET /data body = %q, want %q", body, `{"ok":true}`)
	}

	// GET /admin is stopped at pre_request; the server handler must never be reached.
	_, err = client.Get(srv.URL + "/admin")
	if !errors.Is(err, ErrDenied) {
		t.Errorf("GET /admin error = %v, want ErrDenied", err)
	}
	if adminHit {
		t.Error("/admin handler was called, want it never reached")
	}
}

// TestResponseBodyReadableAfterRules verifies that after pre_response rules
// evaluate the body, the caller still receives a full, unread body, and that
// the original response body is properly closed.
func TestResponseBodyReadableAfterRules(t *testing.T) {
	t.Parallel()
	const want = "hello world"

	closed := false
	origBody := &trackingCloser{
		ReadCloser: io.NopCloser(strings.NewReader(want)),
		onClose:    func() { closed = true },
	}

	mock := &mockTransport{
		resp: &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
			Body:       origBody,
		},
	}

	cfg := simplePreResponseConfig("ANY", "ALL")
	transport := mustNew(t, cfg, WithRoundTripper(mock))

	resp, err := transport.RoundTrip(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatalf("RoundTrip() error = %v, want nil", err)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if string(got) != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if !closed {
		t.Error("original response body was not closed")
	}
}

// trackingCloser wraps an io.ReadCloser and calls onClose when Close is called.
type trackingCloser struct {
	io.ReadCloser
	onClose func()
}

func (tc *trackingCloser) Close() error {
	tc.onClose()
	return tc.ReadCloser.Close()
}

// TestRoundTripTransportError ensures that errors from allowed request are returned to the caller.
func TestRoundTripTransportError(t *testing.T) {
	t.Parallel()
	transportErr := errors.New("connection refused")
	mock := &mockTransport{err: transportErr}
	transport := mustNewFromFile(t, "testdata/allow_all_pre_request.yaml", WithRoundTripper(mock))
	req := httptest.NewRequest("GET", "/", nil)
	_, err := transport.RoundTrip(req)
	if !errors.Is(err, transportErr) {
		t.Errorf("RoundTrip() error = %v, want transportErr", err)
	}
}

func newJSONLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

func parseLogEntry(t *testing.T, buf *bytes.Buffer) roundtripLogEntry {
	t.Helper()
	if buf.Len() == 0 {
		t.Fatal("expected a log entry, buffer is empty")
	}
	var entry roundtripLogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("parsing log entry: %v\nraw: %s", err, buf.Bytes())
	}
	return entry
}

func TestWithLogger(t *testing.T) {
	t.Parallel()

	// All subtests share this config: GET requests pass pre_request ("allow-get"),
	// 2xx responses pass pre_response ("allow-2xx"). POST and non-2xx are denied.
	// Each subtest creates its own mockTransport so parallel subtests don't race
	// on the shared *http.Response body read/replace.
	const loggerYAML = "testdata/logger.yaml"
	data, err := os.ReadFile(loggerYAML)
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", loggerYAML, err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("parseConfig(%q): %v", loggerYAML, err)
	}

	t.Run("logs allow with WithAllowLogger", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		transport := mustNew(t, cfg,
			WithRoundTripper(&mockTransport{resp: makeResponse(200, "", nil)}),
			WithAllowLogger(newJSONLogger(&buf)),
		)

		req := httptest.NewRequest("GET", "/", nil)
		if _, err := transport.RoundTrip(req); err != nil {
			t.Fatalf("RoundTrip(GET /) error = %v, want nil", err)
		}

		entry := parseLogEntry(t, &buf)
		if !entry.PreRequestAllowed {
			t.Errorf("pre_request_allowed = false, want true")
		}
		if entry.PreRequestAllowedRule != "allow-get" {
			t.Errorf("pre_request_allowed_rule = %q, want %q", entry.PreRequestAllowedRule, "allow-get")
		}
		if !entry.PreResponseAllowed {
			t.Errorf("pre_response_allowed = false, want true")
		}
		if entry.Err != nil {
			t.Errorf("err = %q, want nil", *entry.Err)
		}
	})

	t.Run("does not log allow with WithLogger", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		transport := mustNew(t, cfg,
			WithRoundTripper(&mockTransport{resp: makeResponse(200, "", nil)}),
			WithLogger(newJSONLogger(&buf)),
		)

		req := httptest.NewRequest("GET", "/", nil)
		if _, err := transport.RoundTrip(req); err != nil {
			t.Fatalf("RoundTrip(GET /) error = %v, want nil", err)
		}

		if buf.Len() != 0 {
			t.Errorf("expected no log output, got: %s", buf.Bytes())
		}
	})

	t.Run("logs denial with WithDenialLogger", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		transport := mustNew(t, cfg,
			WithRoundTripper(&mockTransport{resp: makeResponse(200, "", nil)}),
			WithDenialLogger(newJSONLogger(&buf)),
		)

		req := httptest.NewRequest("POST", "/", nil)
		_, err := transport.RoundTrip(req)
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("RoundTrip(POST /) error = %v, want ErrDenied", err)
		}

		entry := parseLogEntry(t, &buf)
		if entry.PreRequestAllowed {
			t.Errorf("pre_request_allowed = true, want false")
		}
		if entry.PreRequestAllowedRule != "" {
			t.Errorf("pre_request_allowed_rule = %q, want %q", entry.PreRequestAllowedRule, "")
		}
	})

	t.Run("does not log denial with WithLogger", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		transport := mustNew(t, cfg,
			WithRoundTripper(&mockTransport{resp: makeResponse(200, "", nil)}),
			WithLogger(newJSONLogger(&buf)),
		)

		req := httptest.NewRequest("POST", "/", nil)
		if _, err := transport.RoundTrip(req); !errors.Is(err, ErrDenied) {
			t.Fatalf("RoundTrip(POST /) error = %v, want ErrDenied", err)
		}

		if buf.Len() != 0 {
			t.Errorf("expected no log output, got: %s", buf.Bytes())
		}
	})

	t.Run("pre_response denial includes all fields", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		transport := mustNew(t, cfg,
			WithRoundTripper(&mockTransport{resp: makeResponse(503, "", nil)}),
			WithDenialLogger(newJSONLogger(&buf)),
		)

		req := httptest.NewRequest("GET", "/", nil)
		_, err := transport.RoundTrip(req)
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("RoundTrip(GET /) error = %v, want ErrDenied", err)
		}

		entry := parseLogEntry(t, &buf)
		if !entry.PreRequestAllowed {
			t.Errorf("pre_request_allowed = false, want true")
		}
		if entry.PreRequestAllowedRule != "allow-get" {
			t.Errorf("pre_request_allowed_rule = %q, want %q", entry.PreRequestAllowedRule, "allow-get")
		}
		if entry.PreResponseAllowed {
			t.Errorf("pre_response_allowed = true, want false")
		}
		if entry.PreResponseAllowedRule != "" {
			t.Errorf("pre_response_allowed_rule = %q, want %q", entry.PreResponseAllowedRule, "")
		}
	})

	t.Run("single log entry per roundtrip", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		transport := mustNew(t, cfg,
			WithRoundTripper(&mockTransport{resp: makeResponse(200, "", nil)}),
			WithAllLogger(newJSONLogger(&buf)),
		)

		req := httptest.NewRequest("GET", "/", nil)
		if _, err := transport.RoundTrip(req); err != nil {
			t.Fatalf("RoundTrip(GET /) error = %v, want nil", err)
		}

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 1 {
			t.Errorf("log line count = %d, want 1\n%s", len(lines), buf.String())
		}
	})

	t.Run("transport error logged unconditionally at Error level", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		transportErr := errors.New("connection refused")
		transport := mustNew(t, cfg,
			WithRoundTripper(&mockTransport{err: transportErr}),
			WithLogger(newJSONLogger(&buf)),
		)

		req := httptest.NewRequest("GET", "/", nil)
		if _, err := transport.RoundTrip(req); !errors.Is(err, transportErr) {
			t.Fatalf("RoundTrip(GET /) error = %v, want transportErr", err)
		}

		entry := parseLogEntry(t, &buf)
		if entry.Level != "ERROR" {
			t.Errorf("level = %q, want ERROR", entry.Level)
		}
	})
}

// TestLogic exhaustively verifies evalRules for all 16 possible boolean
// combinations of two rules, each with one match and one authorize
// expression, plus the zero-rule deny case.
//
// The reference function f encodes the expected semantics in plain Go:
// first-match-wins, empty slice denies all.
func TestLogic(t *testing.T) {
	t.Parallel()

	compile := func(s string) *vm.Program {
		p, err := expr.Compile(s, expr.Env(RequestEnv{}), expr.AsBool())
		if err != nil {
			t.Fatalf("expr.Compile(%q): %v", s, err)
		}
		return p
	}
	// T and F are pre-compiled constant expressions used to build rules
	// whose match/authorize results are fully controlled by the test.
	T, F := compile("true"), compile("false")
	prog := func(b bool) *vm.Program {
		if b {
			return T
		}
		return F
	}

	// ruleSpec describes one rule in boolean terms.
	// m is the match expression; a is the authorize expression.
	type ruleSpec struct {
		name string
		m    bool // match expr
		a    bool // authorize expr
	}

	// f is the reference implementation of the rule evaluation logic,
	// written in plain Go so its correctness is easy to verify by inspection.
	f := func(specs []ruleSpec) (bool, string) {
		for _, s := range specs {
			if s.m && s.a {
				return true, s.name // first matching+authorized rule wins
			}
		}
		return false, "" // no rules, or none matched+authorized → deny
	}

	// toRules converts boolean specs into compiledRules suitable for
	// evalRules, wiring each bool to a pre-compiled true/false expression.
	toRules := func(specs []ruleSpec) []compiledRule {
		rules := make([]compiledRule, len(specs))
		for i, s := range specs {
			rules[i] = compiledRule{
				name:      s.name,
				match:     prog(s.m),
				authorize: prog(s.a),
			}
		}
		return rules
	}

	// check asserts that evalRules agrees with the reference f for the given specs.
	check := func(specs []ruleSpec) {
		t.Helper()
		wantAllowed, wantRule := f(specs)
		gotAllowed, gotRule, err := evalRules(toRules(specs), RequestEnv{})
		if err != nil {
			t.Fatalf("evalRules() error = %v", err)
		}
		if gotAllowed != wantAllowed || gotRule != wantRule {
			t.Errorf("rules %+v: got (allowed=%v, rule=%q), want (allowed=%v, rule=%q)",
				specs, gotAllowed, gotRule, wantAllowed, wantRule)
		}
	}

	// Zero-rule → deny.
	check(nil)

	// Exhaustively check all 16 combinations of two rules × 2 booleans each.
	// i encodes all 4 booleans as bits: bits 0–1 are (m,a) for rule "a",
	// bits 2–3 are (m,a) for rule "b".
	bit := func(i, n int) bool { return i>>n&1 == 1 }
	for i := range 16 {
		check([]ruleSpec{
			{"a", bit(i, 0), bit(i, 1)},
			{"b", bit(i, 2), bit(i, 3)},
		})
	}
}
