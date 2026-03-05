# Rules Configuration

A rule looks like this:

```yaml
# ANY and ALL are aliases for 'true' to make less restrictive rules read more like English
pre_request:
  - name: rule-allow-api-reads
    match: Path startsWith "/api/"
    authorize: Method == "GET"
  - name: rule-allow-health
    match: ANY
    authorize: Path == "/health"

pre_response:
  - name: rule-allow
    match: ALL
    authorize: ANY
```

A request/response is authorized by the first rule where `match` and `authorize` evaluate to `true`. If no rule matches, the traffic is rejected.

A `pre_request` rule's `match` and `authorize` expressions can access the following fields:

| Field     | Type                  | Description                           |
|-----------|-----------------------|---------------------------------------|
| `Method`  | `string`              | HTTP method (`GET`, `POST`, ...)      |
| `Scheme`  | `string`              | URL scheme (`http` or `https`)        |
| `Host`    | `string`              | Request host                          |
| `Path`    | `string`              | URL path                              |
| `Headers` | `map[string][]string` | Request headers                       |
| `Query`   | `map[string][]string` | Query parameters                      |
| `Body`    | `string`              | Request body decoded as UTF-8         |

A `pre_response` rule's `match` and `authorize` expressions can access the following fields:

| Field        | Type                  | Description                                     |
|--------------|-----------------------|-------------------------------------------------|
| `StatusCode` | `int`                 | HTTP status code                                |
| `Headers`    | `map[string][]string` | Response headers                                |
| `Body`       | `string`              | Response body decoded as UTF-8                  |
| `Request`    | `RequestEnv`          | The original request environment (fields above) |

Both `match` and `authorize` accept [any valid Expr expressions](https://expr-lang.org/docs/language-definition) that return a `boolean` value.
