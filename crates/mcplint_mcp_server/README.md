# mcplint-mcp-server

MCP server and live scanner for [mcplint](https://github.com/mcplint/mcplint), a static security analyzer for MCP (Model Context Protocol) configurations.

## MCP Server

Exposes mcplint scanning as MCP tools for AI agents over stdio transport:

- **`mcplint_scan`** — Scan MCP config content for security issues
- **`mcplint_list_rules`** — List all available security rules
- **`mcplint_explain`** — Explain a rule with remediation guidance

```bash
mcplint mcp serve
```

## Live Server Scanner

Connects to a running MCP server, discovers its tools, and produces security findings:

```rust
use mcplint_mcp_server::scan_live_server;

let result = scan_live_server("http://localhost:3000").await?;
```

## License

Apache-2.0
