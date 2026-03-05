# Rules Testing

`ruleshttp` provides a `test` CLI that evaluates rules against a YAML test file without making real HTTP requests.

## Installation

```
go install github.com/argemma-oss/ruleshttp/cmd/ruleshttp-test@latest
```

## Usage

```
ruleshttp-test rules.yaml
```

The test file is derived from the rules path by pairing a rules YAML file with a `_test` YAML file. For example: `rules.yaml` and `rules_test.yaml`.

A test YAML file contains a list of requests/responses and expected outcomes based on the rule file:

```yaml
requests:
  - name: "POST PR review with REQUEST_CHANGES event is allowed"
    want: allow
    request:
      method: POST
      host: api.github.com
      path: /repos/owner/repo/pulls/1/reviews
      body: '{"event":"REQUEST_CHANGES"}'

  - name: "POST PR review with APPROVE event is denied"
    want: deny
    request:
      method: POST
      host: api.github.com
      path: /repos/owner/repo/pulls/1/reviews
      body: '{"event":"APPROVE"}'

responses:
  - name: "200 OK is allowed"
    want: allow
    response:
      status_code: 200
  - name: "404 Not Found is allowed"
    want: allow
    response:
      status_code: 404
```

The process exits 0 on success, 1 on any failure.
