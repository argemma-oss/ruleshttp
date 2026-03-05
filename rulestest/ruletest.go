// Package rulestest provides test helpers for evaluating [ruleshttp.Transport]
// rules against declarative test cases.
package rulestest

import (
	"fmt"

	"github.com/argemma-oss/ruleshttp"
)

// ConfigTestCase holds request and response test cases for use with [Run].
type ConfigTestCase struct {
	Requests  []RequestTestCase  `yaml:"requests"`
	Responses []ResponseTestCase `yaml:"responses"`
}

// RequestTestCase is a single pre_request rule test.
type RequestTestCase struct {
	Name    string              `yaml:"name"`
	Want    string              `yaml:"want"` // "allow" or "deny"
	Request ruleshttp.RequestEnv `yaml:"request"`
}

// ResponseTestCase is a single pre_response rule test.
type ResponseTestCase struct {
	Name     string               `yaml:"name"`
	Want     string               `yaml:"want"` // "allow" or "deny"
	Response ruleshttp.ResponseEnv `yaml:"response"`
}

// CaseResult reports the outcome of a single test case.
type CaseResult struct {
	// Phase is "request" or "response".
	Phase string
	// Name is the test case name.
	Name string
	// Pass is true when the outcome matched Want.
	Pass bool
	// Reason is non-empty when Pass is false and describes why the case failed.
	Reason string
}

// Run evaluates all request and response cases in tests against transport,
// returning one [CaseResult] per case in input order.
//
// A ruleshttp evaluation error is recorded as a failure in the relevant
// CaseResult rather than returned.
func Run(transport *ruleshttp.Transport, tests ConfigTestCase) []CaseResult {
	var results []CaseResult

	for _, tc := range tests.Requests {
		r := CaseResult{Phase: "request", Name: tc.Name}

		if tc.Want != "allow" && tc.Want != "deny" {
			r.Reason = fmt.Sprintf("invalid want %q: must be allow or deny", tc.Want)
			results = append(results, r)
			continue
		}

		allowed, _, err := transport.CheckRequest(tc.Request)
		if err != nil {
			r.Reason = fmt.Sprintf("ruleshttp error: %v", err)
			results = append(results, r)
			continue
		}

		wantAllow := tc.Want == "allow"
		if allowed == wantAllow {
			r.Pass = true
		} else {
			got := "deny"
			if allowed {
				got = "allow"
			}
			r.Reason = fmt.Sprintf("got %s, want %s", got, tc.Want)
		}
		results = append(results, r)
	}

	for _, tc := range tests.Responses {
		r := CaseResult{Phase: "response", Name: tc.Name}

		if tc.Want != "allow" && tc.Want != "deny" {
			r.Reason = fmt.Sprintf("invalid want %q: must be allow or deny", tc.Want)
			results = append(results, r)
			continue
		}

		allowed, _, err := transport.CheckResponse(tc.Response)
		if err != nil {
			r.Reason = fmt.Sprintf("ruleshttp error: %v", err)
			results = append(results, r)
			continue
		}

		wantAllow := tc.Want == "allow"
		if allowed == wantAllow {
			r.Pass = true
		} else {
			got := "deny"
			if allowed {
				got = "allow"
			}
			r.Reason = fmt.Sprintf("got %s, want %s", got, tc.Want)
		}
		results = append(results, r)
	}

	return results
}
