# mcplint-report

Output formatters for [mcplint](https://github.com/mcplint/mcplint), a static security analyzer for MCP (Model Context Protocol) configurations.

## Supported Formats

- **Text** — Human-readable terminal output with ANSI colors
- **JSON** — Machine-readable JSON array
- **Markdown** — Markdown tables for documentation and PR comments
- **SARIF** — SARIF 2.1.0 for GitHub Code Scanning integration

## Usage

```rust
use mcplint_report::{render, OutputFormat};

let output = render(&findings, OutputFormat::Json);
```

## License

Apache-2.0
