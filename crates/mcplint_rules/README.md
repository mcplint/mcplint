# mcplint-rules

Security rules engine for [mcplint](https://github.com/mcplint/mcplint), a static security analyzer for MCP (Model Context Protocol) configurations.

## Rules

| Rule | Description |
|------|-------------|
| MG001 | Unbounded string parameters flowing to dangerous sinks |
| MG002 | Tool descriptions that understate actual capabilities |
| MG003 | Cross-tool/cross-server escalation chains |
| MG004 | Filesystem access without path confinement |
| MG005 | Missing or weak authentication |
| MG006 | Internal metadata leakage in descriptions |
| MG007 | Overly broad tool parameter scopes |
| MG008 | Insecure transport (HTTP/WS without TLS) |
| MG009 | Sensitive environment variables passed to servers |

## Usage

```rust
use mcplint_rules::default_registry;

let registry = default_registry();
```

`default_registry()` returns a `RuleRegistry` with all built-in rules pre-registered.

## License

Apache-2.0
