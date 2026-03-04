# mcplint Export Format

mcplint operates on two canonical JSON formats. You can author these by hand or generate them from your MCP setup.

## `mcp.tools.json` — Single Server

Describes tools for one MCP server.

### Schema

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `server_name` | string | no | `"default"` | Identifier for the server |
| `tools` | [Tool](#tool)[] | **yes** | — | List of tool definitions |
| `auth` | [Auth](#auth) | no | `{"type":"none"}` | Authentication configuration |

### Tool

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **yes** | — | Tool identifier |
| `description` | string | no | `""` | What the tool does |
| `parameters` | [Parameter](#parameter)[] | no | `[]` | Input parameters |
| `tags` | string[] | no | `[]` | Categorization tags |

### Parameter

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **yes** | — | Parameter identifier |
| `type` | string | **yes** | — | Data type (e.g. `"string"`, `"integer"`, `"boolean"`) |
| `description` | string | no | `""` | What the parameter represents |
| `required` | boolean | no | `false` | Whether the parameter is required |
| `constraints` | object | no | `{}` | Validation constraints (see below) |

**Supported constraints:**

| Key | Type | Effect |
|-----|------|--------|
| `enum` | array | Restrict to listed values |
| `pattern` | string | Regex the value must match |
| `maxLength` | integer | Maximum string length |
| `format` | string | Semantic format (e.g. `"uri"`, `"email"`) |
| `allowedDirectories` | string[] | Restrict filesystem paths to these directories |
| `basePath` | string | Root directory for path confinement |

Adding any of these reduces the attack surface detected by MG001 and MG004.

---

## `mcp.config.json` — Multi-Server

Describes one or more MCP servers.

### Schema

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `servers` | [Server](#server)[] | no | `[]` | List of server definitions |

### Server

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **yes** | — | Server identifier |
| `description` | string | no | `""` | What the server provides |
| `tools` | [Tool](#tool)[] | no | `[]` | Tools exposed by this server |
| `auth` | [Auth](#auth) | no | `{"type":"none"}` | Authentication configuration |
| `transport` | string | no | `"stdio"` | Transport type: `"stdio"`, `"http"`, `"sse"`, `"websocket"` |
| `url` | string | no | — | Server URL (for network transports) |
| `command` | string | no | — | Command to launch the server (for stdio) |
| `args` | string[] | no | `[]` | Arguments for the launch command |
| `env` | object | no | `{}` | Environment variables (string→string map) |

### Auth

Tagged union — the `type` field selects the variant.

| Type | Additional Fields | Description |
|------|-------------------|-------------|
| `"none"` | — | No authentication (triggers MG005) |
| `"api_key"` | `header`: string (optional) | API key auth; omitting `header` triggers MG005 |
| `"bearer"` | `token_source`: string (optional) | Bearer token auth |
| `"oauth"` | `scopes`: string[] (optional) | OAuth with scope list |
| `"custom"` | `description`: string (optional) | Custom auth scheme |

---

## Validation Rules

- `tools[].name` must be non-empty.
- `tools[].parameters[].type` must be non-empty.
- `servers[].name` must be non-empty.
- Files with `tools` in the filename are parsed as `mcp.tools.json`; all others as `mcp.config.json`.
- Unknown fields are silently ignored (forward-compatible).
- Secrets in `env` values that don't start with `$`, `${`, or contain `env:`/`vault:` are flagged by MG005 if the key name suggests a secret.

---

## Examples

### Safe configuration

```json
{
  "server_name": "weather-api",
  "tools": [
    {
      "name": "get_weather",
      "description": "Returns current weather for a city",
      "parameters": [
        {
          "name": "city",
          "type": "string",
          "description": "City name",
          "required": true,
          "constraints": {
            "maxLength": 100,
            "pattern": "^[a-zA-Z\\s-]+$"
          }
        }
      ]
    }
  ],
  "auth": {
    "type": "oauth",
    "scopes": ["read"]
  }
}
```

mcplint produces **zero findings** for this configuration because:
- String parameters are constrained (`maxLength`, `pattern`)
- Authentication is configured (`oauth`)
- No dangerous sinks, no leaked metadata

### Unsafe configuration

```json
{
  "servers": [
    {
      "name": "internal-tools",
      "description": "Server connected to postgres://admin:pw@10.0.0.5:5432/prod",
      "tools": [
        {
          "name": "run_query",
          "description": "Execute a SQL query",
          "parameters": [
            {
              "name": "query",
              "type": "string",
              "description": "SQL to execute",
              "required": true
            }
          ]
        },
        {
          "name": "write_file",
          "description": "Read file contents",
          "parameters": [
            {
              "name": "path",
              "type": "string",
              "description": "File path",
              "required": true
            }
          ]
        }
      ],
      "auth": { "type": "none" },
      "transport": "http",
      "url": "http://localhost:9090",
      "env": {
        "DB_SECRET": "hunter2"
      }
    }
  ]
}
```

mcplint flags this with:
- **MG001** — `query` is an unbounded string flowing to a SQL sink
- **MG002** — `write_file` description says "Read" but name implies write
- **MG004** — `path` is unconfined filesystem access in a write tool
- **MG005** — No auth on an HTTP server + hardcoded `DB_SECRET`
- **MG006** — Connection string and internal IP leaked in description

---

## Generating Exports from Real MCP Setups

mcplint auto-detects configuration formats from Claude Desktop, Cursor, and other MCP setups. Use the `export` command to convert any detected format into canonical `mcp.config.json` and per-server `*.tools.json` files.

### Claude Desktop

```sh
# Scan directly (auto-detects format)
mcplint scan ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Export to canonical format
mcplint export ~/Library/Application\ Support/Claude/claude_desktop_config.json --out ./exported
```

### Cursor

```sh
# Scan a project directory (detects .cursor/mcp.json)
mcplint scan /path/to/project

# Export from Cursor config
mcplint export /path/to/project --out ./exported
```

### Any MCP Config

```sh
# Auto-detect: works with mcp.tools.json, mcp.config.json,
# claude_desktop_config.json, .cursor/mcp.json, or any
# JSON file containing "mcpServers"
mcplint scan <path>

# Export writes:
#   mcp.config.json       — full multi-server config
#   <server>.tools.json   — per-server tool definitions
mcplint export <path> --out ./exported
```

The adapter auto-detects the format. If tools cannot be inferred (e.g., custom MCP servers), the exported config will have empty tool lists — you can fill them in manually.
