# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is mcplint?

mcplint is a static security analyzer for MCP (Model Context Protocol) tool configurations. It lints MCP tool definitions for exploitable security issues, outputs compiler-style diagnostics, and can fail CI builds with evidence.

## Build & Test Commands

```bash
# Build
cargo build --release

# Run all tests (unit + integration)
cargo test

# Run tests for a specific crate
cargo test -p mcplint_core
cargo test -p mcplint_rules
cargo test -p mcplint_cli

# Run a single test by name
cargo test test_name_substring

# Update insta snapshots after intentional output changes
cargo insta review
# or accept all: cargo insta accept

# Lint
cargo clippy --all-targets

# Format
cargo fmt --all

# Install locally from source
cargo install --path crates/mcplint_cli
```

## Architecture

Six-crate Rust workspace with a unidirectional dependency flow:

```
mcplint_cli  (binary, clap CLI, subcommands: scan/export/list-rules/explain/baseline/diff/mcp)
  ├── mcplint_core        (data models, adapters, config, rule registry, baseline, findings_baseline, scan context, fix engine)
  ├── mcplint_rules       (9 security rules: MG001–MG009)
  ├── mcplint_report      (output formatters: text, json, markdown, SARIF 2.1.0)
  └── mcplint_mcp_server  (MCP server + live server scanner via rmcp client)
```

### Analysis Pipeline

Input JSON (or live MCP server) → **Adapter** (auto-detects format: Claude Desktop, Cursor, VS Code, Cline, Windsurf, native, generic, **live-server**) → **McpConfig** (canonical form) → **ScanContext** (adds JSON location mapping) → **RuleRegistry** (runs all rules) → **Findings** → **Config Policy** (`.mcplint.toml` filters/overrides) → **Report Formatter** (or **FixEngine** if `--fix`)

### Key Design Patterns

- **Adapters** (`mcplint_core::adapters`): Each format implements `McpAdapter` trait with `detect()` and `load()`. `auto_load()` tries adapters in sequence. Adapters produce a `LoadResult` containing both the canonical `McpConfig` and a JSON pointer map for evidence attribution.
- **Rules** (`mcplint_rules`): Each rule implements the `Rule` trait from `mcplint_core::rule`. Rules receive a `ScanContext` and return `Vec<Finding>`. Registered via `default_registry()`.
- **Evidence tracking**: `ScanContext` carries a `LocationMap` that maps JSON pointers to line/column positions in the original file. Rules reference these pointers so findings point to exact source locations. JSON pointers follow RFC 6901 escaping.
- **Config policy**: `.mcplint.toml` can ignore rules, ignore specific findings (by rule+tool or rule+server), and downgrade severity (never escalate). Discovery walks up from the scan path.
- **Fix engine** (`mcplint_core::fix`): `FixEngine::apply_fixes()` takes original JSON and findings, returns patched JSON and `Vec<FixResult>`. Supports MG001 (maxLength), MG004 (allowedDirectories), MG005 (auth placeholder), MG006 (redact metadata). CLI flags: `--fix` (apply) and `--fix-dry-run` (preview).
- **Stdin support**: `--stdin` flag reads MCP config from stdin. Useful for piping and pre-commit hooks. Mutually exclusive with path arguments and `--fix`.
- **Multi-file scanning**: Multiple paths can be passed as positional args for batch scanning (e.g., pre-commit hook with multiple changed files).
- **Findings baseline** (`mcplint_core::findings_baseline`): `FindingsBaseline` snapshots scan findings (by fingerprint) to a JSON file. `FindingsDiff::compute()` compares current findings against a baseline to detect regressions (new findings) and fixes (resolved). CLI: `mcplint scan --save-baseline FILE` and `mcplint diff PATH --baseline FILE`.

### The Nine Rules

| ID    | CWE | OWASP | OWASP MCP | What it detects |
|-------|-----|-------|-----------|----------------|
| MG001 | CWE-77, 89, 78 | A03:2021 | MCP05, MCP06 | Unbounded string parameters flowing to dangerous sinks (exec, SQL, fs, HTTP) |
| MG002 | CWE-285 | A01:2021 | MCP02 | Tool descriptions that understate actual capabilities |
| MG003 | CWE-269, 284 | A01:2021 | MCP02, MCP03 | Cross-tool/cross-server escalation chains (compositional) |
| MG004 | CWE-22, 73 | A01:2021 | MCP05, MCP10 | Filesystem access without path confinement |
| MG005 | CWE-306, 287 | A07:2021 | MCP01, MCP07 | Missing or weak authentication |
| MG006 | CWE-200, 538 | A01:2021 | MCP01, MCP10 | Internal metadata leakage (env vars, API keys, internal paths in descriptions) |
| MG007 | CWE-20 | A03:2021 | MCP02, MCP05 | Overly broad tool scopes (unconstrained parameters, missing type, open arrays/objects) |
| MG008 | CWE-319 | A02:2021 | MCP01, MCP07 | Insecure transport (HTTP/WS URLs instead of HTTPS/WSS) |
| MG009 | CWE-798, 522 | A07:2021 | MCP01, MCP09 | Environment variable leakage (hardcoded secrets, sensitive env vars) |

Rules provide CWE, OWASP Top 10 2021, and OWASP MCP Top 10 2025 mappings via the `Rule` trait's `cwe_ids()`, `owasp_ids()`, and `owasp_mcp_ids()` methods. Use `mcplint explain <RULE_ID>` to see full references, rationale, and remediation guidance.

### Input Formats (auto-detected)

- `*.tools.json` — single-server native format
- `*.config.json` — multi-server native format
- `claude_desktop_config.json` — Claude Desktop
- `.cursor/mcp.json` — Cursor IDE
- `.vscode/mcp.json` — VS Code (also settings.json with `"mcp"` wrapper)
- `.cline/mcp_settings.json` — Cline (also `.cline/mcp.json`; skips disabled servers)
- `*windsurf*/mcp_config.json` — Windsurf/Codeium (also `.windsurf/mcp.json`)
- `.continue/mcpServers/*.yaml|*.json` — Continue.dev (also `.continue/config.yaml`)
- `*/zed/settings.json` — Zed editor (`context_servers` key; supports JSONC comments)
- Generic JSON with `mcpServers` field

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success — no findings above threshold |
| 1 | Operational error — bad input, parse failure, misconfiguration |
| 2 | Policy violation — findings/drift above threshold |

All commands (`scan`, `diff`, `baseline diff`) follow this convention. Constants are defined in `exit_codes.rs`.

### Output Formats

Text, JSON, Markdown, and SARIF 2.1.0 (for GitHub Code Scanning). Formatters live in `mcplint_report`.

### GitHub Action

The composite action lives in `.github/action/` with four files:
- `action.yml` — inputs, outputs, step orchestration (cache → install → run → upload SARIF → PR comment)
- `install.sh` — downloads prebuilt binary with version caching
- `run.sh` — unified script handling both `scan` and `diff` modes, writes job summary to `$GITHUB_STEP_SUMMARY`
- `comment.sh` — upserts a PR comment via `gh` API with marker-based dedup

The action supports two modes via the `mode` input:
- `scan` (default) — full security scan with SARIF upload
- `diff` — incremental baseline diff, reports only new/resolved findings

## Test Fixtures

Integration test fixtures are in `tests/fixtures/` organized by adapter type and scenario. CLI integration tests use `assert_cmd` and snapshot tests use `insta`.
