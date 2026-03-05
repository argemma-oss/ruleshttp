package rulestest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argemma-oss/ruleshttp"
	"gopkg.in/yaml.v3"
)

func loadTransport(t *testing.T, rulesPath string) *ruleshttp.Transport {
	t.Helper()
	transport, err := ruleshttp.NewFromFile(rulesPath)
	if err != nil {
		t.Fatalf("loading rules %q: %v", rulesPath, err)
	}
	return transport
}

func loadConfigTestCase(t *testing.T, path string) ConfigTestCase {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading test cases %q: %v", path, err)
	}
	var tc ConfigTestCase
	if err := yaml.Unmarshal(data, &tc); err != nil {
		t.Fatalf("parsing test cases %q: %v", path, err)
	}
	return tc
}

// TestRun discovers all rules/test-case pairs under testdata
// using the same naming convention as cmd/ruleshttp-test: rules.yaml + rules_test.yaml.
// Every case in each test file is expected to pass.
func TestRun(t *testing.T) {
	paths, err := filepath.Glob("testdata/*.yaml")
	if err != nil {
		t.Fatalf("globbing testdata: %v", err)
	}

	var found int
	for _, rulesPath := range paths {
		if strings.HasSuffix(rulesPath, "_test.yaml") {
			continue
		}
		testPath := strings.TrimSuffix(rulesPath, ".yaml") + "_test.yaml"
		name := filepath.Base(rulesPath)

		t.Run(name, func(t *testing.T) {
			transport := loadTransport(t, rulesPath)
			tests := loadConfigTestCase(t, testPath)

			results := Run(transport, tests)
			if len(results) == 0 {
				t.Fatal("no results returned")
			}
			for _, r := range results {
				if !r.Pass {
					t.Errorf("%s/%s: %s", r.Phase, r.Name, r.Reason)
				}
			}
		})
		found++
	}

	if found == 0 {
		t.Fatal("no rules files found in testdata")
	}
}

func TestRunFailing(t *testing.T) {
	transport := loadTransport(t, "testdata/rules.yaml")
	tests := ConfigTestCase{
		Requests: []RequestTestCase{
			{
				Name:    "wrong outcome for GET /api/users",
				Want:    "deny",
				Request: ruleshttp.RequestEnv{Method: "GET", Path: "/api/users"},
			},
			{
				Name:    "invalid want value",
				Want:    "maybe",
				Request: ruleshttp.RequestEnv{Method: "GET", Path: "/api/users"},
			},
		},
		Responses: []ResponseTestCase{
			{
				Name:     "wrong outcome for 200",
				Want:     "deny",
				Response: ruleshttp.ResponseEnv{StatusCode: 200},
			},
			{
				Name:     "invalid want value",
				Want:     "perhaps",
				Response: ruleshttp.ResponseEnv{StatusCode: 200},
			},
		},
	}

	results := Run(transport, tests)

	if len(results) == 0 {
		t.Fatal("no results returned")
	}
	for _, r := range results {
		if r.Pass {
			t.Errorf("%s/%s: expected failure, got pass", r.Phase, r.Name)
		}
		if r.Reason == "" {
			t.Errorf("%s/%s: expected non-empty Reason on failure", r.Phase, r.Name)
		}
	}
}
