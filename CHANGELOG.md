# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] — 2026-03-05

### Added
- Crate-specific READMEs for mcplint-core, mcplint-rules, mcplint-report, mcplint-mcp-server, and mcplint-cli
- Published mcplint-mcp-server to crates.io

### Changed
- Each crate now uses its own README on crates.io instead of the root README

## [0.1.1] — 2026-03-04

### Added
- **MCP server mode** (`mcplint mcp serve`) — exposes scanning as MCP tools for AI agents via stdio transport
- **Live server scanning** (`mcplint scan --server`) — connect to running MCP servers (stdio/HTTP) and scan discovered tools
- Three new security rules: MG007 (overly broad tool scopes), MG008 (transport security), MG009 (environment variable leakage)
- CWE and OWASP mapping metadata on all rules (visible in `list-rules`, `explain`, SARIF output)
- `--stdin` support for scanning piped input (`cat config.json | mcplint scan --stdin`)
- Pre-commit hook support via `.pre-commit-hooks.yaml`
- Declarative custom rule system via `.mcplint.toml`
- npm wrapper package (`@mcplint/cli`) for `npx` usage
- Homebrew tap (`brew tap mcplint/tap && brew install mcplint`)
- `install.sh` curl-pipe-bash installer
- crates.io publishing in release pipeline
- aarch64-unknown-linux-gnu (ARM64 Linux) prebuilt binaries
- Continue.dev and Zed editor adapters
- `baseline diff` command for CI drift detection

### Changed
- Rule trait extended with `cwe_ids()`, `owasp_ids()`, `rationale()`, `references()` methods
- SARIF output now includes CWE and OWASP tags in rule metadata
- Exit codes standardized: 0 (clean), 1 (operational error), 2 (findings/policy violation)

## [0.1.0] — 2026-02-14

### Added
- Six security rules: MG001 (unbounded strings), MG002 (over-permissioning), MG003 (escalation chains), MG004 (filesystem scope), MG005 (weak auth), MG006 (metadata leakage)
- Auto-detection of MCP config formats: Claude Desktop, Cursor, native, generic JSON
- Output formats: text, JSON, markdown, SARIF 2.1.0
- CLI subcommands: `scan`, `export`, `list-rules`, `explain`, `baseline create`, `baseline diff`
- Baseline drift detection with SHA-256 fingerprinting
- Policy configuration via `.mcplint.toml` (ignore rules, downgrade severity)
- GitHub Actions workflow for CI scanning with SARIF upload
- Multi-platform release builds (Linux, macOS, Windows)
- Precise JSON evidence tracking with line/column source locations

[Unreleased]: https://github.com/mcplint/mcplint/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/mcplint/mcplint/releases/tag/v0.1.2
[0.1.1]: https://github.com/mcplint/mcplint/releases/tag/v0.1.1
[0.1.0]: https://github.com/mcplint/mcplint/compare/v0.1.0...v0.1.1
