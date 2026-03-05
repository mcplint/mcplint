# mcplint-core

Core data models and infrastructure for [mcplint](https://github.com/mcplint/mcplint), a static security analyzer for MCP (Model Context Protocol) configurations.

## Overview

This crate provides the foundational types used across the mcplint workspace:

- **MCP schema models** — `McpConfig`, `McpServer`, `ToolDefinition` for representing MCP configurations
- **Format adapters** — Loaders for Claude Desktop, Cursor, and generic MCP config formats
- **Finding types** — `Finding`, `Severity`, `Evidence` emitted by security rules
- **Rule trait** — `Rule` trait and `RuleRegistry` for registering and executing rules
- **Scan context** — `ScanContext` for carrying config and JSON location mapping
- **Policy config** — `GuardConfig` loaded from `.mcplint.toml`
- **Baseline** — Snapshot support for drift detection
- **JSON locator** — JSON pointer to line/column mapping for precise error locations

## License

Apache-2.0
