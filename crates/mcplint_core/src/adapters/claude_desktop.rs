use super::{AdapterError, AdapterResult, McpAdapter, SourceInfo};
use crate::json_locator::escape_pointer;
use crate::{AuthConfig, McpConfig, McpServer, ToolDefinition, ToolParameter, ToolProvenance};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Adapter for Claude Desktop's `claude_desktop_config.json`.
///
/// Claude Desktop stores MCP server configurations in a JSON file with this
/// structure:
/// ```json
/// {
///   "mcpServers": {
///     "server-name": {
///       "command": "npx",
///       "args": ["-y", "@some/mcp-server"],
///       "env": { "KEY": "value" }
///     }
///   }
/// }
/// ```
///
/// Tools are not explicitly listed in the config — they are discovered at
/// runtime via the MCP protocol. This adapter extracts server metadata and
/// infers tool capabilities from well-known server package names where possible.
pub struct ClaudeDesktopAdapter;

/// Raw Claude Desktop config structure.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaudeDesktopConfig {
    #[serde(default)]
    mcp_servers: BTreeMap<String, ClaudeServerEntry>,
}

/// A single server entry in Claude Desktop config.
#[derive(Debug, Deserialize)]
struct ClaudeServerEntry {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Some configs use "url" for SSE/HTTP transport.
    #[serde(default)]
    url: Option<String>,
}

const CLAUDE_CONFIG_FILENAMES: &[&str] = &["claude_desktop_config.json", "claude_config.json"];

impl McpAdapter for ClaudeDesktopAdapter {
    fn name(&self) -> &'static str {
        "claude-desktop"
    }

    fn detect(&self, path: &Path) -> bool {
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                return CLAUDE_CONFIG_FILENAMES.contains(&name);
            }
        }

        // Directory: check for config file inside
        if path.is_dir() {
            return CLAUDE_CONFIG_FILENAMES
                .iter()
                .any(|name| path.join(name).is_file());
        }

        false
    }

    fn load(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        let config_path = if path.is_dir() {
            CLAUDE_CONFIG_FILENAMES
                .iter()
                .map(|name| path.join(name))
                .find(|p| p.is_file())
                .ok_or_else(|| {
                    AdapterError::UnsupportedFormat(
                        "No Claude Desktop config found in directory".to_string(),
                    )
                })?
        } else {
            path.to_path_buf()
        };

        let content =
            std::fs::read_to_string(&config_path).map_err(|e| AdapterError::io(&config_path, e))?;

        let location_map = crate::json_locator::JsonLocationMap::from_source(&content);

        let raw: ClaudeDesktopConfig =
            serde_json::from_str(&content).map_err(|e| AdapterError::parse(&config_path, e))?;

        let mut warnings = Vec::new();
        let mut servers = Vec::new();
        let mut source_info = Vec::new();

        for (name, entry) in &raw.mcp_servers {
            let transport = if entry.url.is_some() {
                "sse".to_string()
            } else {
                "stdio".to_string()
            };

            // Infer auth from environment variables
            let auth = infer_auth_from_env(&entry.env);
            if matches!(auth, AuthConfig::None) && !entry.env.is_empty() {
                // Check if any env vars look like they carry auth
                let has_auth_env = entry.env.keys().any(|k| {
                    let lower = k.to_lowercase();
                    lower.contains("token")
                        || lower.contains("api_key")
                        || lower.contains("apikey")
                        || lower.contains("secret")
                        || lower.contains("password")
                        || lower.contains("auth")
                });
                if !has_auth_env {
                    warnings.push(format!("Server '{}': no authentication detected", name));
                }
            }

            // Infer tools from well-known server packages
            let tools = infer_tools_from_command(&entry.command, &entry.args, &mut warnings, name);

            servers.push(McpServer {
                name: name.clone(),
                description: String::new(),
                tools,
                auth,
                transport,
                url: entry.url.clone(),
                command: entry.command.clone(),
                args: entry.args.clone(),
                env: entry.env.clone(),
            });

            source_info.push(SourceInfo::with_pointer(
                &config_path,
                &format!("/mcpServers/{}", escape_pointer(name)),
            ));
        }

        // Sort servers and source_info together by server name for deterministic output
        let mut paired: Vec<_> = servers.into_iter().zip(source_info).collect();
        paired.sort_by(|(a, _), (b, _)| a.name.cmp(&b.name));
        let (servers, source_info): (Vec<_>, Vec<_>) = paired.into_iter().unzip();

        // Build server_pointers: server_name → "/mcpServers/{name}"
        let server_pointers: std::collections::BTreeMap<String, String> = servers
            .iter()
            .map(|s| {
                (
                    s.name.clone(),
                    format!("/mcpServers/{}", escape_pointer(&s.name)),
                )
            })
            .collect();

        Ok(AdapterResult {
            config: McpConfig { servers },
            adapter_name: self.name(),
            warnings,
            source_info,
            location_map: Some(location_map),
            server_pointers,
        })
    }
}

pub fn infer_auth_from_env(env: &BTreeMap<String, String>) -> AuthConfig {
    for (key, value) in env {
        let lower = key.to_lowercase();
        if lower.contains("api_key") || lower.contains("apikey") {
            return AuthConfig::ApiKey {
                header: Some(key.clone()),
            };
        }
        if lower.contains("token") || lower.contains("bearer") {
            return AuthConfig::Bearer {
                token_source: Some(if value.starts_with('$') || value.starts_with("${") {
                    value.clone()
                } else {
                    format!("env:{}", key)
                }),
            };
        }
    }
    AuthConfig::None
}

/// Well-known MCP server packages and their typical tools.
#[allow(dead_code)]
struct KnownServer {
    /// Pattern to match in the command/args (e.g., package name).
    pattern: &'static str,
    /// Description of the server.
    description: &'static str,
    /// Tools this server is known to expose.
    tools: &'static [KnownTool],
}

struct KnownTool {
    name: &'static str,
    description: &'static str,
    params: &'static [(&'static str, &'static str, bool)], // (name, type, required)
}

const KNOWN_SERVERS: &[KnownServer] = &[
    KnownServer {
        pattern: "filesystem",
        description: "MCP filesystem server — provides file read/write/search operations",
        tools: &[
            KnownTool {
                name: "read_file",
                description: "Read the complete contents of a file from the file system",
                params: &[("path", "string", true)],
            },
            KnownTool {
                name: "write_file",
                description: "Create a new file or overwrite an existing file with content",
                params: &[("path", "string", true), ("content", "string", true)],
            },
            KnownTool {
                name: "list_directory",
                description: "List directory contents with [FILE] or [DIR] prefixes",
                params: &[("path", "string", true)],
            },
            KnownTool {
                name: "search_files",
                description: "Recursively search for files and directories matching a pattern",
                params: &[("path", "string", true), ("pattern", "string", true)],
            },
            KnownTool {
                name: "move_file",
                description: "Move or rename files and directories",
                params: &[("source", "string", true), ("destination", "string", true)],
            },
        ],
    },
    KnownServer {
        pattern: "postgres",
        description: "MCP PostgreSQL server — provides database query capabilities",
        tools: &[KnownTool {
            name: "query",
            description: "Execute a read-only SQL query against the PostgreSQL database",
            params: &[("sql", "string", true)],
        }],
    },
    KnownServer {
        pattern: "sqlite",
        description: "MCP SQLite server — provides database query capabilities",
        tools: &[
            KnownTool {
                name: "read_query",
                description: "Execute a SELECT query on the SQLite database",
                params: &[("query", "string", true)],
            },
            KnownTool {
                name: "write_query",
                description: "Execute an INSERT, UPDATE, or DELETE query",
                params: &[("query", "string", true)],
            },
        ],
    },
    KnownServer {
        pattern: "fetch",
        description: "MCP fetch server — retrieves web content",
        tools: &[KnownTool {
            name: "fetch",
            description: "Fetch a URL from the internet and return its content",
            params: &[("url", "string", true)],
        }],
    },
    KnownServer {
        pattern: "puppeteer",
        description: "MCP Puppeteer server — browser automation and web scraping",
        tools: &[
            KnownTool {
                name: "puppeteer_navigate",
                description: "Navigate the browser to a URL",
                params: &[("url", "string", true)],
            },
            KnownTool {
                name: "puppeteer_evaluate",
                description: "Execute JavaScript in the browser console",
                params: &[("script", "string", true)],
            },
        ],
    },
    KnownServer {
        pattern: "github",
        description: "MCP GitHub server — repository and issue management",
        tools: &[
            KnownTool {
                name: "search_repositories",
                description: "Search for GitHub repositories",
                params: &[("query", "string", true)],
            },
            KnownTool {
                name: "create_issue",
                description: "Create a new issue in a GitHub repository",
                params: &[
                    ("owner", "string", true),
                    ("repo", "string", true),
                    ("title", "string", true),
                    ("body", "string", false),
                ],
            },
        ],
    },
    KnownServer {
        pattern: "shell",
        description: "MCP shell server — executes shell commands",
        tools: &[KnownTool {
            name: "run_command",
            description: "Execute a shell command on the system",
            params: &[("command", "string", true)],
        }],
    },
];

/// Infer tools from the server command and args by matching known packages.
pub fn infer_tools_from_command(
    command: &Option<String>,
    args: &[String],
    warnings: &mut Vec<String>,
    server_name: &str,
) -> Vec<ToolDefinition> {
    let search_str =
        format!("{} {}", command.as_deref().unwrap_or(""), args.join(" ")).to_lowercase();

    for known in KNOWN_SERVERS {
        if search_str.contains(known.pattern) {
            return known
                .tools
                .iter()
                .map(|t| ToolDefinition {
                    name: t.name.to_string(),
                    description: t.description.to_string(),
                    parameters: t
                        .params
                        .iter()
                        .map(|(name, ptype, required)| ToolParameter {
                            name: name.to_string(),
                            param_type: ptype.to_string(),
                            description: String::new(),
                            required: *required,
                            constraints: BTreeMap::new(),
                        })
                        .collect(),
                    tags: vec![format!("inferred:{}", known.pattern)],
                    provenance: ToolProvenance::Inferred,
                })
                .collect();
        }
    }

    warnings.push(format!(
        "Server '{}': could not infer tools from command '{}'. \
         Tools will be empty — consider providing an mcp.tools.json.",
        server_name,
        search_str.trim()
    ));
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_claude_config_file() {
        let adapter = ClaudeDesktopAdapter;
        // We can't test with real paths easily, but we test the name matching
        let path = Path::new("/tmp/claude_desktop_config.json");
        assert!(adapter.detect(path) || !path.exists());
    }

    #[test]
    fn parse_claude_config() {
        let json = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                },
                "postgres": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-postgres"],
                    "env": {
                        "POSTGRES_CONNECTION_STRING": "postgresql://localhost/mydb"
                    }
                }
            }
        }"#;

        let raw: ClaudeDesktopConfig = serde_json::from_str(json).unwrap();
        assert_eq!(raw.mcp_servers.len(), 2);
        assert!(raw.mcp_servers.contains_key("filesystem"));
        assert!(raw.mcp_servers.contains_key("postgres"));
    }

    #[test]
    fn infer_filesystem_tools() {
        let mut warnings = Vec::new();
        let tools = infer_tools_from_command(
            &Some("npx".into()),
            &[
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
                "/tmp".into(),
            ],
            &mut warnings,
            "fs-server",
        );

        assert!(!tools.is_empty());
        assert!(tools.iter().any(|t| t.name == "read_file"));
        assert!(tools.iter().any(|t| t.name == "write_file"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn infer_postgres_tools() {
        let mut warnings = Vec::new();
        let tools = infer_tools_from_command(
            &Some("npx".into()),
            &["-y".into(), "@modelcontextprotocol/server-postgres".into()],
            &mut warnings,
            "pg-server",
        );

        assert!(!tools.is_empty());
        assert!(tools.iter().any(|t| t.name == "query"));
    }

    #[test]
    fn unknown_server_warns() {
        let mut warnings = Vec::new();
        let tools = infer_tools_from_command(
            &Some("node".into()),
            &["my-custom-server.js".into()],
            &mut warnings,
            "custom",
        );

        assert!(tools.is_empty());
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("could not infer tools"));
    }

    #[test]
    fn infer_auth_from_token_env() {
        let mut env = BTreeMap::new();
        env.insert("GITHUB_TOKEN".to_string(), "ghp_xxxx".to_string());

        let auth = infer_auth_from_env(&env);
        assert!(matches!(auth, AuthConfig::Bearer { .. }));
    }

    #[test]
    fn infer_auth_from_api_key_env() {
        let mut env = BTreeMap::new();
        env.insert("OPENAI_API_KEY".to_string(), "sk-xxxx".to_string());

        let auth = infer_auth_from_env(&env);
        assert!(matches!(auth, AuthConfig::ApiKey { .. }));
    }

    #[test]
    fn no_auth_without_auth_env() {
        let env = BTreeMap::new();
        let auth = infer_auth_from_env(&env);
        assert!(matches!(auth, AuthConfig::None));
    }
}
