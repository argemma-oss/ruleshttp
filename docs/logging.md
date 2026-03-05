# Logging

`ruleshttp` supports attaching a `slog.Logger` for logging errors and optionally allow/denial events.

```go
logger := slog.New(slog.NewJSONHandler(logBuf, nil))
// Log denied requests/responses
ruleshttp.New(cfg, ruleshttp.WithDenialLogger(logger))
```

The following logging configurations are available:

| Option               | Logs                              |
|----------------------|-----------------------------------|
| `WithLogger`         | transport errors only             |
| `WithDenialLogger`   | transport errors + denials        |
| `WithAllowLogger`    | transport errors + allows         |
| `WithAllLogger`      | transport errors + allows/denials |

Each log entry is a single wide record with fields `pre_request_allowed`, `pre_request_allowed_rule`, `pre_response_allowed`, `pre_response_allowed_rule`, and `err`.
