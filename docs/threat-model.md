# Threat Model

`ruleshttp` is supplemental to sandboxing, not a replacement for sandboxing:

* What is allowed by `ruleshttp` is defined by a rules file at startup. If an untrusted process can write to that file, it can add a permissive rule and bypass all restrictions. To prevent this, the sandboxed process should not be able to write to the rules file. This can be accomplished with filesystem permissions, or embedding (e.g. `go:embed`) the rules into a signed binary.

* `ruleshttp` restricts what a credential can do through the HTTP client, but it does not protect the credential itself. If untrusted code can read the credential it can make its own HTTP calls and bypass `ruleshttp` entirely. The credential and the ruleshttp-wrapped client should live in a trusted intermediary that untrusted code cannot inspect; the untrusted process should never hold the raw credential.

Additionally, when writing rules, you may want to consider:

* `ruleshttp` rules that match on request bodies parse untrusted content. An allowlist (`field == "expected"`) is safer than a blocklist (`field != "forbidden"`) because a blocklist may not enumerate every dangerous value. Use `ruleshttp-test` with adversarial cases to verify rules behavior on malformed or unexpected input.

* `pre_response` rules take place after a request has already successfully been sent. If a `pre_response` rule is set on a state changing request (e.g. an HTTP POST) the state will have already been changed. Generally, `pre_response` rules are for filtering read-only operations.
