# Contributing to mcplint

Thank you for your interest in contributing! This guide will help you get started.

Please review and follow the [Code of Conduct](CODE_OF_CONDUCT.md) in all project interactions.

## Prerequisites

- **Rust 1.75+** — install via [rustup](https://rustup.rs)
- **Git**

## Getting Started

```bash
git clone https://github.com/mcplint/mcplint.git
cd mcplint
cargo build
cargo test
```

## Development Workflow

```bash
# Build
cargo build

# Run all tests (unit + integration)
cargo test

# Run tests for a specific crate
cargo test -p mcplint_core

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt --all

# Update snapshots after intentional output changes
cargo insta review
```

All PRs must pass `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt --check`.

## Release Workflow

Use the GitHub Actions workflow `.github/workflows/release-cut.yml`:

1. Run **Release Cut** with:
   - `mode=prepare`
   - `version=<x.y.z>`
2. Review and merge the generated release PR.
3. Run **Release Cut** again with:
   - `mode=tag`
   - `version=<x.y.z>`

Pushing `v<x.y.z>` triggers `.github/workflows/release.yml` to build artifacts and publish release outputs.

## Architecture

Six-crate workspace with unidirectional dependencies:

```
mcplint_cli            Binary entry point (clap CLI)
├── mcplint_core       Data models, adapters, config, rule registry, fix engine
├── mcplint_rules      Security rules (MG001–MG009)
├── mcplint_report     Output formatters (text, JSON, markdown, SARIF)
└── mcplint_mcp_server MCP server mode + live server scanner
```

### Analysis Pipeline

```
Input JSON (or live MCP server) → Adapter (auto-detects format) → McpConfig → ScanContext → RuleRegistry → Findings → Config Policy → Formatter
```

## Adding a New Rule

1. Create `crates/mcplint_rules/src/mg00N_your_rule.rs`
2. Implement the `Rule` trait from `mcplint_core::rule`:
   ```rust
   impl Rule for Mg00NYourRule {
       fn id(&self) -> &'static str { "MG00N" }
       fn name(&self) -> &'static str { "your-rule-name" }
       fn description(&self) -> &'static str { "..." }
       fn category(&self) -> FindingCategory { ... }
       fn cwe_ids(&self) -> &'static [u32] { &[] }
       fn owasp_ids(&self) -> &'static [&'static str] { &[] }
       fn owasp_mcp_ids(&self) -> &'static [&'static str] { &[] }
       fn run(&self, ctx: &ScanContext) -> Vec<Finding> { ... }
       fn explain(&self) -> &'static str { "..." }
   }
   ```
3. Register it in `crates/mcplint_rules/src/lib.rs` → `default_registry()`
4. Add unit tests in the same file and integration tests in `crates/mcplint_cli/tests/`
5. Add a test fixture under `tests/fixtures/` if needed

## Submitting a Pull Request

1. Fork the repo and create a feature branch from `main`
2. Make your changes with tests
3. Run `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
4. Open a PR against `main` with a clear description of the change

## Code Style

- Follow `cargo fmt` defaults
- No warnings from `cargo clippy`
- Comment only when intent isn't obvious from the code
- Prefer small, focused PRs

## Reporting Issues

Use [GitHub Issues](https://github.com/mcplint/mcplint/issues). Include:
- mcplint version (`mcplint --version`)
- Input file (or minimal reproduction)
- Expected vs actual output

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
