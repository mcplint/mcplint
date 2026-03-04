# Real-World MCP + Agent Examples

> ⚠️ **These examples are intentionally insecure.** They demonstrate
> realistic agent code with security issues that `mcplint` catches.
> The Python agent code is **illustrative, not runnable** — it shows
> real patterns but requires actual MCP servers to execute.
> All secrets are obviously fake placeholders.

Each example includes:

- **Agent code** (Python) — the orchestration logic using the `mcp` and `anthropic` SDKs
- **MCP config** — what the agent connects to (what `mcplint` scans)
- **Inline `← BUG:` comments** — pointing out the security issues in the agent code

## Examples

| # | Directory | What it does |
|---|-----------|-------------|
| 1 | `01-code-review-agent/` | Multi-agent code reviewer: fetches PRs from GitHub, reads files, runs tests, posts review comments |
| 2 | `02-data-analyst-agent/` | Queries production DBs, generates SQL reports, writes CSVs, emails stakeholders |
| 3 | `03-incident-responder/` | PagerDuty → log search → k8s remediation → Slack status updates |
| 4 | `04-rag-customer-support/` | RAG pipeline: vector search knowledge base, look up customer in CRM, draft + send email reply |

## Scanning with mcplint

```sh
# From the repo root:
mcplint scan examples/real-world-agents/01-code-review-agent/mcp_servers.json
mcplint scan examples/real-world-agents/02-data-analyst-agent/claude_desktop_config.json
mcplint scan examples/real-world-agents/03-incident-responder/.cursor/mcp.json
mcplint scan examples/real-world-agents/04-rag-customer-support/mcp_config.json
```
