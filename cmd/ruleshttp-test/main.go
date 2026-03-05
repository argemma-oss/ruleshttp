// Command ruleshttp-test evaluates ruleshttp rules against a test file.
//
// Usage:
//
//	ruleshttp-test <rules.yaml>
//
// The test file is derived from the rules path by inserting "_test" before
// the ".yaml" extension, e.g. "rules.yaml" → "rules_test.yaml".
//
// Test file format:
//
//	requests:
//	  - name: "plain English description"
//	    want: allow        # or deny
//	    request:
//	      method: GET      # optional, defaults to GET
//	      path: /foo/bar
//
//	responses:
//	  - name: "plain English description"
//	    want: allow        # or deny
//	    response:
//	      status_code: 200
//
// A ruleshttp evaluation error counts as a failure.
// The process exits 1 if any test fails, 0 otherwise.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/argemma-oss/ruleshttp"
	"github.com/argemma-oss/ruleshttp/rulestest"
	"gopkg.in/yaml.v3"
)

func testFilePath(rulesPath string) string {
	base := strings.TrimSuffix(rulesPath, ".yaml")
	return base + "_test.yaml"
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: ruleshttp-test <rules.yaml>\n")
		os.Exit(2)
	}

	rulesPath := os.Args[1]
	testPath := testFilePath(rulesPath)

	transport, err := ruleshttp.NewFromFile(rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading rules %q: %v\n", rulesPath, err)
		os.Exit(1)
	}

	data, err := os.ReadFile(testPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading test file %q: %v\n", testPath, err)
		os.Exit(1)
	}

	var tests rulestest.ConfigTestCase
	if err := yaml.Unmarshal(data, &tests); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing test file %q: %v\n", testPath, err)
		os.Exit(1)
	}

	failures := 0
	for _, r := range rulestest.Run(transport, tests) {
		label := r.Phase + "s/" + r.Name
		if r.Pass {
			fmt.Printf("--- PASS: %s\n", label)
		} else {
			fmt.Printf("--- FAIL: %s\n\t%s\n", label, r.Reason)
			failures++
		}
	}

	if failures > 0 {
		fmt.Printf("\nFAIL (%d failure(s))\n", failures)
		os.Exit(1)
	}
	fmt.Println("\nPASS")
}
