# Realistic MCP Configuration Fixtures

Synthetic but realistic MCP configuration files for testing mcplint against
real-world patterns.

## Purpose

These fixtures exercise mcplint's adapters, rules, and report formatters on
configurations that mirror what actual users have — multiple servers, mixed auth
patterns, docker-based setups, and common misconfigurations.

## What's Inside

| Fixture | Servers | Intent |
|---------|---------|--------|
| `claude/developer_typical.json` | 4 | Typical developer setup: filesystem, github, sqlite, fetch |
| `claude/large_org_heavy.json` | 10 | Large org: multiple databases, slack, terraform, puppeteer |
| `claude/insecure_common.json` | 5 | Intentionally insecure: hardcoded secrets, unscoped filesystem, no auth |
| `claude/docker_setup.json` | 4 | Docker-launched MCP servers with volume mounts |
| `cursor/typical.json` | 5 | Cursor IDE format with common servers |

## Security

- **All fixtures are synthetic.** No real infrastructure is referenced.
- **No real credentials.** Secrets use `REDACTED` or `${ENV_VAR}` placeholders.
- **Domains are safe.** Only `localhost`, `127.0.0.1`, and `example.com` are used.
- **Automated guard.** `fixture_secret_guard.rs` runs on every `cargo test` and
  fails if any fixture file contains patterns matching real API keys or tokens.

## Based On

Configs are inspired by publicly documented MCP server patterns from:

- `@modelcontextprotocol/server-filesystem`
- `@modelcontextprotocol/server-github`
- `@modelcontextprotocol/server-postgres`
- `@modelcontextprotocol/server-sqlite`
- `@modelcontextprotocol/server-fetch`
- `@modelcontextprotocol/server-puppeteer`
- `@modelcontextprotocol/server-shell`
- `@modelcontextprotocol/server-slack`
- `@hashicorp/terraform-mcp-server`
