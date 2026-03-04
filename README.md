# mcplint

[![CI](https://github.com/mcplint/mcplint/actions/workflows/ci.yml/badge.svg)](https://github.com/mcplint/mcplint/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Static security analyzer for [MCP (Model Context Protocol)](https://modelcontextprotocol.io) configurations.

Finds exploitable security issues in MCP tool definitions, explains why they're dangerous, and fails CI builds with evidence. Think **clang-tidy / semgrep for MCP**.

## Quickstart

```sh
# Install from source
cargo install --git https://github.com/mcplint/mcplint --locked

# Scan your Claude Desktop config
mcplint scan ~/.config/Claude/claude_desktop_config.json --fail-on high --format markdown
```

## Install

**Quick install** (Linux / macOS):

```sh
curl -fsSL https://raw.githubusercontent.com/mcplint/mcplint/main/install.sh | bash
```

Set `MCPLINT_VERSION=v0.1.0` to pin a version, or `MCPLINT_INSTALL_DIR` to change the install location (default: `~/.local/bin`).

**Homebrew** (macOS / Linux):

```sh
brew tap mcplint/tap
brew install mcplint
```

**npm** (Node.js 16+):

```sh
npx @mcplint/cli scan .
# or install globally
npm install -g @mcplint/cli
```

**Cargo** (requires Rust 1.75+):

```sh
cargo install mcplint
```

**From source:**

```sh
git clone https://github.com/mcplint/mcplint && cd mcplint
cargo install --path crates/mcplint_cli
```

**Prebuilt binaries** — download from [GitHub Releases](https://github.com/mcplint/mcplint/releases):

| Platform | Target |
|----------|--------|
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS x86_64 | `x86_64-apple-darwin` |
| macOS ARM64 | `aarch64-apple-darwin` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |

> 💡 **Windows is fully supported** — prebuilt binaries, all rules, and all output formats work on Windows. Use `mcplint.exe` after extracting.

```sh
# Example: Linux x86_64
curl -LO https://github.com/mcplint/mcplint/releases/latest/download/mcplint-x86_64-unknown-linux-gnu.tar.gz
tar xzf mcplint-*.tar.gz
./mcplint --version
```

Scan a directory containing MCP configs (auto-detects Claude Desktop, Cursor, or generic MCP inputs):

```sh
mcplint scan /path/to/project --fail-on high
```

Export to canonical format first (useful for CI or reproducibility), then scan:

```sh
mcplint export ~/.config/Claude/claude_desktop_config.json --out ./mcplint-export
mcplint scan ./mcplint-export --fail-on high
```

`export` writes `mcp.config.json` and per-server `*.tools.json` files into the output directory.

## Usage

```sh
# Scan any MCP config (auto-detects format)
mcplint scan mcp.tools.json
mcplint scan claude_desktop_config.json
mcplint scan /path/to/project          # detects .cursor/mcp.json

# Output as JSON (for CI) or Markdown (for PRs)
mcplint scan mcp.tools.json --format json
mcplint scan mcp.tools.json --format markdown

# SARIF output (for GitHub Code Scanning)
mcplint scan mcp.tools.json --format sarif > results.sarif

# Fail CI if high or critical issues found
mcplint scan mcp.tools.json --fail-on high

# Export any config to canonical mcplint format
mcplint export claude_desktop_config.json --out ./exported

# List all rules
mcplint list-rules

# Explain a specific rule
mcplint explain MG001

# Scan from stdin (pipe or pre-commit)
cat mcp.tools.json | mcplint scan --stdin

# Scan multiple files at once
mcplint scan file1.json file2.json file3.json

# Scan a live MCP server (stdio transport)
mcplint scan --server "stdio:npx:@modelcontextprotocol/server-filesystem:/tmp"

# Scan a live MCP server (HTTP transport)
mcplint scan --server "https://my-mcp-server.com/mcp"

# Scan a live server with JSON output
mcplint scan --server "stdio:python3:my_server.py" --format json
```

### Pre-commit Hook

mcplint can run as a [pre-commit](https://pre-commit.com/) hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/anthropics/mcplint
    rev: v0.1.0
    hooks:
      - id: mcplint
```

### MCP Server Mode

mcplint can run as an MCP server, allowing AI agents (Claude, Cursor, etc.) to invoke security scanning directly:

```sh
# Start the MCP server on stdio
mcplint mcp serve
```

Add to your MCP client configuration (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "mcplint": {
      "command": "mcplint",
      "args": ["mcp", "serve"]
    }
  }
}
```

This exposes three tools to AI agents:
- **`mcplint_scan`** — Scan an MCP config file or raw JSON for security issues
- **`mcplint_list_rules`** — List all available security rules with CWE/OWASP mappings
- **`mcplint_explain`** — Get detailed remediation guidance for a specific rule

## Exit Codes

mcplint uses CI-standard exit codes for predictable automation:

| Code | Meaning | Example |
|------|---------|---------|
| 0 | Success — no findings above threshold | Clean scan, or findings below `--fail-on` level |
| 1 | Operational error — bad input or misconfiguration | File not found, invalid JSON, unknown rule |
| 2 | Policy violation — findings above threshold | Findings at/above `--fail-on` severity detected |

### CI usage

```bash
mcplint scan ./configs --fail-on high
status=$?

if [ $status -eq 0 ]; then
  echo "Clean — no high/critical findings"
elif [ $status -eq 2 ]; then
  echo "Findings detected — review required"
elif [ $status -eq 1 ]; then
  echo "Scan error — check configuration"
fi
```

The same exit codes apply to `mcplint diff` (exit 2 on new findings above `--fail-on-new` threshold) and `mcplint baseline diff --fail-on-drift` (exit 2 on risky drift).

## Incremental CI with diff

For teams adopting mcplint on existing projects, `mcplint diff` enables incremental rollout: baseline your current findings, then only fail CI when **new** issues appear.

### Step 1: Create a baseline

```bash
mcplint scan ./mcp-configs/ --save-baseline .mcplint-baseline.json
git add .mcplint-baseline.json
git commit -m "Add mcplint findings baseline"
```

### Step 2: Use diff in CI

```bash
mcplint diff ./mcp-configs/ --baseline .mcplint-baseline.json --fail-on-new high
```

Exit code 0 = no new high/critical findings. Safe to merge.

### Step 3: Update the baseline as you fix issues

```bash
mcplint scan ./mcp-configs/ --save-baseline .mcplint-baseline.json
git add .mcplint-baseline.json
git commit -m "Update mcplint baseline after fixing MG005"
```

### Options

- `--fail-on-new critical` — only fail on new critical findings
- `--fail-on-new none` — report-only mode, never fail (not yet supported, defaults to `low`)
- `--format json` — machine-readable diff output
- `--format markdown` — for PR comments

### GitHub Actions example

```yaml
- name: mcplint diff
  run: mcplint diff ./configs --baseline .mcplint-baseline.json --fail-on-new high
```

> **Note:** `mcplint diff` compares *security findings*. The existing `mcplint baseline` command compares *server/tool configurations* for drift detection. Both are useful and complementary.

### When to use `diff` vs `baseline`

| Feature | `mcplint diff` | `mcplint baseline diff` |
|---------|---------------|------------------------|
| **Compares** | Security findings (rule violations) | Server/tool configurations (capabilities) |
| **Use case** | Incremental CI adoption — suppress existing issues, catch new ones | Rug-pull detection — catch tool additions, capability changes |
| **Tracks** | Finding fingerprints (rule ID + location) | Tool names, capabilities, transport types |
| **CI pattern** | `--fail-on-new high` | `--fail-on-drift` |

**Use both together** for defense-in-depth: `diff` catches new code issues, `baseline` catches supply-chain drift.

## Rules

| ID | Category | CWE | OWASP | [OWASP MCP](https://owasp.org/www-project-mcp-top-10/) | Description |
|----|----------|-----|-------|----------|-------------|
| MG001 | Static | CWE-77, CWE-89, CWE-78 | A03:2021 | MCP05, MCP06 | Unbounded string to dangerous sink (exec, SQL, fs, HTTP) |
| MG002 | Semantic | CWE-285 | A01:2021 | MCP02 | Tool description understates actual capabilities |
| MG003 | Compositional | CWE-269, CWE-284 | A01:2021 | MCP02, MCP03 | Source → amplifier → sink escalation chains |
| MG004 | Static | CWE-22, CWE-73 | A01:2021 | MCP05, MCP10 | Filesystem access without path confinement |
| MG005 | Static | CWE-306, CWE-287 | A07:2021 | MCP01, MCP07 | Missing or weak authentication |
| MG006 | Static | CWE-200, CWE-538 | A01:2021 | MCP01, MCP10 | Internal metadata leaked in descriptions |
| MG007 | Static | CWE-20 | A03:2021 | MCP02, MCP05 | Overly broad tool scopes (unconstrained parameters) |
| MG008 | Static | CWE-319 | A02:2021 | MCP01, MCP07 | Insecure transport (HTTP/WS instead of HTTPS/WSS) |
| MG009 | Static | CWE-798, CWE-522 | A07:2021 | MCP01, MCP09 | Environment variable leakage (secrets in env) |

All rules map to [CWE](https://cwe.mitre.org/), [OWASP Top 10 2021](https://owasp.org/Top10/), and [OWASP MCP Top 10 2025](https://owasp.org/www-project-mcp-top-10/) threat IDs. Run `mcplint explain <RULE_ID>` for full details.

## Auto-Fix

mcplint can automatically remediate certain findings with `--fix`:

```bash
# Preview what would change (no file modification)
mcplint scan config.json --fix-dry-run

# Apply fixes and re-scan
mcplint scan config.json --fix
```

| Rule  | Auto-Fix | What it does |
|-------|----------|-------------|
| MG001 | ✅ | Adds `maxLength: 1000` to unbounded string parameters |
| MG002 | ❌ | Requires manual description update |
| MG003 | ❌ | Requires architectural changes |
| MG004 | ✅ | Adds `allowedDirectories: ["."]` to filesystem parameters |
| MG005 | ✅ | Adds `auth: { type: "bearer", token: "REPLACE_ME" }` placeholder |
| MG006 | ✅ | Replaces leaked metadata (IPs, paths, connection strings) with `[REDACTED]` |
| MG007 | ❌ | Requires manual schema constraints |
| MG008 | ❌ | Requires infrastructure changes (TLS) |
| MG009 | ❌ | Requires manual secret management |

> ⚠️ **MG005 fix inserts a `REPLACE_ME` placeholder.** Search your config for `REPLACE_ME` and substitute actual credentials.

> 💡 **Recommendation:** Always run `--fix-dry-run` first to review changes before applying.

Notes:
- `--fix` and `--fix-dry-run` are mutually exclusive.
- `--fix` only works on single files, not directories.
- After `--fix`, mcplint re-scans and reports remaining (unfixable) findings.

## Input Formats

Auto-detected — pass any of these to `mcplint scan`:

| Format | Detected by |
|--------|-------------|
| `mcp.tools.json` | Filename contains "tools" |
| `mcp.config.json` | Native multi-server config |
| `claude_desktop_config.json` | Claude Desktop MCP config |
| `.cursor/mcp.json` | Cursor MCP config (file or parent directory) |
| `.vscode/mcp.json` | VS Code MCP config (project-level or settings.json with `"mcp"` wrapper) |
| `.cline/mcp_settings.json` | Cline MCP config (also `.cline/mcp.json`); skips `disabled` servers |
| `*windsurf*/mcp_config.json` | Windsurf/Codeium MCP config (also `.windsurf/mcp.json`) |
| `.continue/mcpServers/*.yaml\|*.json` | Continue.dev MCP config (also `.continue/config.yaml`) |
| `*/zed/settings.json` | Zed editor MCP config (`context_servers` key; supports JSONC comments) |
| `*.json` with `mcpServers` | Generic heuristic |

See [docs/export-format.md](docs/export-format.md) for the full schema reference, validation rules, and adapter examples.

**Minimal example** (`mcp.tools.json`):

```json
{
  "server_name": "my-server",
  "tools": [
    {
      "name": "run_query",
      "description": "Execute a SQL query",
      "parameters": [
        { "name": "query", "type": "string", "required": true }
      ]
    }
  ],
  "auth": { "type": "none" }
}
```

## Configuration

Create a `.mcplint.toml` in your project root (or any parent directory of
the scan target) to customize behavior without repeating CLI flags.

```toml
fail_on = "high"
default_format = "sarif"

[ignore]
rules = ["MG006"]
findings = [
  { rule = "MG001", tool = "run_sql", reason = "wrapped with allowlisted queries" },
  { rule = "MG004", server = "filesystem", reason = "sandboxed container path only" },
]

[severity_overrides]
MG002 = "low"
```

**Discovery:** `mcplint scan` searches upward from the scan target for
`.mcplint.toml`. Use `--config <path>` to specify an explicit config or
`--no-config` to disable discovery entirely. CLI flags (`--format`, `--fail-on`)
always override config values.

**Severity overrides** can only downgrade findings (never escalate) to prevent
accidental suppression of new critical issues.

## GitHub Action

### Quick start — 3 lines

```yaml
- uses: actions/checkout@v4
- uses: mcplint/mcplint-action@v1
  with:
    path: .
```

This scans all MCP configs, uploads SARIF to Code Scanning, and fails on high/critical findings.

### Full scan with all options

```yaml
jobs:
  mcplint:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # for SARIF upload
      contents: read
      pull-requests: write     # for PR comments
    steps:
      - uses: actions/checkout@v4
      - uses: mcplint/mcplint-action@v1
        id: mcplint
        with:
          path: './configs'
          format: sarif
          fail-on: high
          config: .mcplint.toml
          upload-sarif: 'true'
          comment-on-pr: 'true'
      - run: echo "Found ${{ steps.mcplint.outputs.findings-count }} findings"
```

### Incremental rollout with baseline diff

For existing projects, use diff mode to only fail on **new** findings:

```yaml
jobs:
  mcplint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: mcplint/mcplint-action@v1
        with:
          mode: diff
          path: './configs'
          baseline: .mcplint-baseline.json
          fail-on-new: high
          comment-on-pr: 'true'
          upload-sarif: 'false'
```

Create the baseline and commit it:

```bash
mcplint scan ./configs --save-baseline .mcplint-baseline.json
git add .mcplint-baseline.json && git commit -m "Add mcplint baseline"
```

### Conditional steps based on results

```yaml
- uses: mcplint/mcplint-action@v1
  id: mcplint
  with:
    fail-on: high
  continue-on-error: true

- if: steps.mcplint.outputs.exit-code == '2'
  run: echo "Security findings detected — blocking merge"

- if: steps.mcplint.outputs.exit-code == '0'
  run: echo "All clear"
```

### Action outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings |
| `critical-count` | Critical severity count |
| `high-count` | High severity count |
| `new-findings-count` | New findings (diff mode) |
| `resolved-findings-count` | Resolved findings (diff mode) |
| `exit-code` | 0=clean, 1=error, 2=violations |
| `sarif-file` | Path to SARIF file |
| `baseline-file` | Path to saved baseline |

See [`.github/action/action.yml`](.github/action/action.yml) for the full
input/output reference.

### Manual CI setup (without the Action)

If you prefer manual setup, mcplint produces [SARIF](https://sarifweb.azurewebsites.net/)
output compatible with [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning):

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: dtolnay/rust-toolchain@stable
  - run: cargo install mcplint
  - run: mcplint scan . --format sarif > results.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: results.sarif
      category: mcplint
  - run: mcplint scan . --fail-on high
```

## Baseline & Drift Detection

mcplint can create a deterministic fingerprint of your MCP configuration and detect
capability drift ("rug-pull" detection) between runs.

**Create a baseline:**

```sh
mcplint baseline create claude_desktop_config.json --out mcplint-baseline.json
```

**Compare current config against a saved baseline:**

```sh
mcplint baseline diff claude_desktop_config.json --baseline mcplint-baseline.json
```

**Fail CI if risky drift is detected** (new dangerous tools, capability expansion,
transport changes from local to remote):

```sh
mcplint baseline diff claude_desktop_config.json \
  --baseline mcplint-baseline.json \
  --fail-on-drift
```

Output formats: `--format text` (default), `--format json`, `--format markdown`.

### What counts as "risky drift"?

- A new server or tool with `exec`, `fs_write`, `net`, or `db` capabilities
- An existing tool gaining any of those capability flags
- Transport change from `stdio` (local) to `http`/`sse` (remote)

## Advanced Examples

### Multi-config CI pipeline with SARIF

Scan all MCP configs across your project and upload results to GitHub Code Scanning:

```bash
# Scan all configs, output SARIF for GitHub
mcplint scan \
  ~/.config/Claude/claude_desktop_config.json \
  .cursor/mcp.json \
  .vscode/mcp.json \
  --format sarif --fail-on high > mcplint.sarif

# In GitHub Actions, upload to Code Scanning:
# - uses: github/codeql-action/upload-sarif@v3
#   with:
#     sarif_file: mcplint.sarif
```

### Custom policy with severity overrides

Create `.mcplint.toml` to tailor mcplint to your risk tolerance:

```toml
# Ignore MG005 (auth) for local-only stdio servers
[[ignore]]
rule = "MG005"
server = "local-dev-*"

# Downgrade MG007 (broad scopes) from high to medium in dev
[[severity_override]]
rule = "MG007"
severity = "medium"
```

### Live MCP server scanning

Connect to a running MCP server and scan its live tool definitions:

```bash
# Scan a server via SSE
mcplint scan --server http://localhost:8080/sse

# Scan and output JSON
mcplint scan --server http://localhost:3000/sse --format json
```

### Pre-commit hook

Add mcplint to your Git pre-commit workflow:

```bash
# .pre-commit-config.yaml (using stdin for changed files)
repos:
  - repo: local
    hooks:
      - id: mcplint
        name: mcplint
        entry: mcplint scan --fail-on high
        language: system
        files: '(mcp\.json|claude_desktop_config\.json|mcp_settings\.json)$'
```

### Drift detection in CI

Detect tool capability changes between deployments:

```bash
# Save baseline after deploying
mcplint baseline create ./mcp-configs/ --out .mcplint-baseline.json

# In CI, detect drift
mcplint baseline diff ./mcp-configs/ \
  --baseline .mcplint-baseline.json \
  --fail-on-drift \
  --format markdown
```

## Migration from mcp-guard

This project was previously named `mcp-guard` and has been renamed to `mcplint`.

- **Binary:** `mcp-guard` → `mcplint`
- **Config file:** `.mcp-guard.toml` → `.mcplint.toml`
- **Crates:** `mcp_guard_*` → `mcplint_*`

**Backward compatibility:** `.mcp-guard.toml` is still recognized during config
discovery with a deprecation warning. If both `.mcplint.toml` and `.mcp-guard.toml`
exist, `.mcplint.toml` takes precedence.

## License

Apache-2.0
