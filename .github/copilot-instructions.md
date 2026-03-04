# Copilot Instructions for mcplint

## What is mcplint?

A static security analyzer for MCP (Model Context Protocol) tool configurations. It lints MCP tool definitions for exploitable security issues, outputs compiler-style diagnostics, and can fail CI builds with evidence. Think **clang-tidy / semgrep for MCP**.

## Build, Test, and Lint

```bash
cargo build                              # Debug build
cargo build --release                    # Release build
cargo test                               # All tests (unit + integration)
cargo test -p mcplint_core               # Tests for a specific crate
cargo test test_name_substring           # Single test by name
cargo clippy --all-targets -- -D warnings  # Lint (CI treats warnings as errors)
cargo fmt --all                          # Format
cargo fmt --all -- --check               # Format check (CI)
cargo insta review                       # Review snapshot changes interactively
cargo insta accept                       # Accept all snapshot changes
cargo install --path crates/mcplint_cli  # Install locally from source
```

All PRs must pass `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt --check`.

## Architecture

Five-crate Rust workspace (`resolver = "2"`, Rust 1.75+, edition 2021) with unidirectional dependency flow:

```
mcplint_cli          Binary entry point (clap CLI)
├── mcplint_core     Data models, adapters, config, rule registry, scan context
├── mcplint_rules    Security rules (MG001–MG006)
├── mcplint_semantic Reserved for future semantic analysis
└── mcplint_report   Output formatters (text, JSON, markdown, SARIF 2.1.0)
```

### Analysis Pipeline

```
Input JSON → Adapter (auto-detects format) → McpConfig (canonical) → ScanContext (adds JSON location mapping) → RuleRegistry (runs all rules) → Findings → Config Policy (.mcplint.toml filters) → Report Formatter
```

### Key Design Patterns

- **Adapters** (`mcplint_core::adapters`): Each format implements the `McpAdapter` trait with `detect()` and `load()`. `auto_load()` tries adapters in sequence. Adapters produce a `LoadResult` containing both the canonical `McpConfig` and a JSON pointer map for evidence attribution.
- **Rules** (`mcplint_rules`): Each rule implements the `Rule` trait (`Send + Sync`) from `mcplint_core::rule`. Rules receive a `ScanContext` and return `Vec<Finding>`. Registered in `default_registry()` as boxed trait objects. Rules map to CWE, OWASP Top 10 2021, and OWASP MCP Top 10 2025 threat IDs.
- **Evidence tracking**: `ScanContext` carries a `LocationMap` mapping JSON pointers (RFC 6901) to line/column positions. Rules reference these pointers so findings point to exact source locations.
- **Config policy**: `.mcplint.toml` can ignore rules, ignore specific findings (by rule+tool or rule+server), and downgrade severity (never escalate). Discovery walks upward from the scan path.
- **Formatters** (`mcplint_report`): `OutputFormat` enum dispatches to format-specific modules (text, json, markdown, sarif).

### CLI Subcommands

`scan`, `export`, `list-rules`, `explain`, `baseline` — each in a separate module under `crates/mcplint_cli/src/commands/`.

## Adding a New Rule

1. Create `crates/mcplint_rules/src/mg00N_your_rule.rs`
2. Define a unit struct and implement the `Rule` trait:
   - `id()`, `description()`, `category()` (from `FindingCategory`), `check()` → `Vec<Finding>`, `explain()`
3. Register in `crates/mcplint_rules/src/lib.rs` → `default_registry()` with `registry.register(Box::new(...))`
4. Add unit tests in the same file; integration tests in `crates/mcplint_cli/tests/`
5. Add test fixtures under `tests/fixtures/` if needed

## Testing Conventions

- Integration test fixtures live in `tests/fixtures/`, organized by adapter type and scenario
- CLI integration tests use `assert_cmd`; snapshot tests use `insta`
- After changing output formats or diagnostic messages, run `cargo insta review` to update snapshots
- The typical test pattern: load fixture → build `ScanContext` → `run_all()` → assert on findings

## Input Formats (Auto-Detected)

- `*.tools.json` — single-server native format
- `*.config.json` — multi-server native format
- `claude_desktop_config.json` — Claude Desktop
- `.cursor/mcp.json` — Cursor IDE
- Generic JSON with `mcpServers` field
