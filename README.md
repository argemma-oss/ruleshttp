# ruleshttp

[![CI](https://github.com/argemma-oss/ruleshttp/actions/workflows/ci.yml/badge.svg)](https://github.com/argemma-oss/ruleshttp/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/argemma-oss/ruleshttp.svg)](https://pkg.go.dev/argemma-oss/ruleshttp)

> [!NOTE]
> `ruleshttp` is currently a beta-quality library.

`ruleshttp` wraps Go HTTP clients and enforces rules on outgoing HTTP requests and incoming responses using the [Expr](https://github.com/expr-lang/expr) expression language. It is intended to be used in cases where scoped credentials are not sufficiently locked down.

## Example integration

GitHub's [Personal Access Tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) (PATs) can be granted read and write permissions for [pull requests which enables both approving and requesting changes](https://docs.github.com/en/rest/pulls/reviews?apiVersion=2022-11-28#create-a-review-for-a-pull-request). Perhaps you have a code review setup where approved PRs are automatically merged and you want some LLM to request changes but _not_ approve PRs. PAT permissions alone cannot express that! With `ruleshttp` you can solve this with the following rules:

```yaml
# rules.yaml
pre_request:
  - name: allow-request-changes
    match: 'Method == "POST" && Host == "api.github.com" && Path contains "/pulls/" && Path endsWith "/reviews"'
    authorize: 'fromJSON(Body)["event"] == "REQUEST_CHANGES"'

pre_response:
  - name: all-responses
    match: ALL
    authorize: ALL
```

The `ruleshttp.New` functions return a Go `http.RoundTripper` which can be used in an `http.Client` like so:

```go
// Load the rules and create a http.RoundTripper/http.Client.Transport
transport, err := ruleshttp.NewFromFile("rules.yaml")
if err != nil {
    log.Fatal(err)
}

// Using github.com/google/go-github/v84 as an example
client := github.NewClient(&http.Client{Transport: transport}).WithAuthToken(token)
_, _, err = client.PullRequests.CreateReview(ctx, owner, repo, number, &github.PullRequestReviewRequest{
		Body:  github.Ptr("An approval attempt that will be rejected by rules.yaml"),
		Event: github.Ptr("APPROVE"),
	})
if errors.Is(err, ruleshttp.ErrDenied) {
    // request or response was rejected by rules
}
```

## How it works

Rules are defined in YAML and compiled at startup. Each rule has a `match` expression and an `authorize` expression. For each request or response, rules are evaluated in order: the first rule whose `match` expression is true and whose `authorize` expression is true allows the traffic. If no rule allows, the call is rejected. 

Rules are an allowlist-only system. A request/response must be explicitly authorized to be allowed. An empty rules list denies all traffic.

Two hook points are supported:

- **`pre_request`** — evaluated before the request is sent.
- **`pre_response`** — evaluated after the response is received. Has access to the original request via `Request`.

Note that if a request is allowed, a _response can still be rejected_. This is to support cases where you want to allow read-only requests but you may want to reject certain responses. A consequence of this decision is that responses always have to be explicitly allowed.

## Additional Docs

- [Threat Model](docs/threat-model.md)
- [Rules Configuration](docs/rules-configuration.md)
- [Logging](docs/logging.md)
- [Rules Testing](docs/rules-testing.md)
