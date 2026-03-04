# mcplint Real-World Examples

> ⚠️ **These configurations are intentionally insecure.** They exist to
> demonstrate what `mcplint` catches. **Do not copy these patterns into
> real projects.** All secrets are obviously fake placeholders.

Six realistic MCP configurations you might write when building AI-powered
applications. Each one contains **intentional security issues** that
`mcplint` will catch.

## Scenarios

| # | File | Scenario | Findings |
|---|------|----------|----------|
| 1 | `01-startup-ai-assistant/claude_desktop_config.json` | Solo founder wires up Claude Desktop for coding + DB + deploy | 6 critical, 13 high, 10 medium |
| 2 | `02-data-pipeline-agent/mcp.config.json` | Multi-agent ETL pipeline: ingest → transform → load → notify | 6 critical, 13 high, 6 medium |
| 3 | `03-customer-support-bot/.cursor/mcp.json` | Cursor-based support bot with CRM, email, and knowledge base | 3 critical, 7 high, 1 medium |
| 4 | `04-devops-chatops/.vscode/mcp.json` | VS Code ChatOps: k8s, terraform, CI/CD, incident response | 8 critical, 16 high, 10 medium |
| 5 | `05-research-agent/research.tools.json` | Autonomous research agent: web scraping, summarization, storage | 1 critical, 7 high, 8 medium |
| 6 | `06-multi-tenant-saas/platform.config.json` | SaaS platform with per-tenant DBs, billing, and admin tools | 10 critical, 14 high, 17 medium |

## Usage

```sh
# Scan a single scenario
mcplint scan examples/01-startup-ai-assistant/claude_desktop_config.json

# See markdown report
mcplint scan examples/06-multi-tenant-saas/platform.config.json --format markdown

# Fail on high-severity findings (CI mode)
mcplint scan examples/04-devops-chatops/.vscode/mcp.json --fail-on high

# Explain a specific rule
mcplint explain MG003
```
