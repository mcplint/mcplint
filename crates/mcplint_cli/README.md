# mcplint

Static security analyzer for MCP (Model Context Protocol) configurations.

Scans MCP config files and live servers for security issues such as missing authentication, overly broad permissions, insecure transport, and sensitive data exposure.

## Installation

```bash
cargo install mcplint-cli
```

## Commands

- **`mcplint scan`** — Scan MCP config files or live servers (`--server`)
- **`mcplint list-rules`** — List all available security rules
- **`mcplint explain <rule>`** — Show rule details and remediation guidance
- **`mcplint diff`** — Compare current scan against a baseline
- **`mcplint baseline`** — Create or diff configuration baselines
- **`mcplint export`** — Export detected config to canonical format
- **`mcplint mcp serve`** — Start as an MCP server on stdio

## Output Formats

`--format text|json|markdown|sarif`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success — no findings above threshold |
| 1 | Operational error |
| 2 | Policy violation — findings above threshold |

## License

Apache-2.0
