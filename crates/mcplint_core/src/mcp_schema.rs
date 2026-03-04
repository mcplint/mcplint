use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Represents an MCP tool parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParameter {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub required: bool,
    /// Optional constraints (e.g., enum values, pattern, maxLength).
    /// Uses BTreeMap for deterministic serialization order.
    #[serde(default)]
    pub constraints: BTreeMap<String, serde_json::Value>,
}

/// Represents an MCP tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub parameters: Vec<ToolParameter>,
    /// Optional tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,
    /// How this tool definition was obtained.
    #[serde(default)]
    pub provenance: ToolProvenance,
}

/// How a tool definition was obtained by an adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolProvenance {
    /// Directly declared in the configuration file.
    #[default]
    Declared,
    /// Inferred from well-known server package names.
    Inferred,
    /// Origin unknown — tool exists but source is unclear.
    Unknown,
}

/// Authentication configuration for an MCP server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    #[default]
    None,
    ApiKey {
        #[serde(default)]
        header: Option<String>,
    },
    Bearer {
        #[serde(default)]
        token_source: Option<String>,
    },
    #[serde(rename = "oauth")]
    OAuth {
        #[serde(default)]
        scopes: Vec<String>,
    },
    Custom {
        #[serde(default)]
        description: String,
    },
}

/// Represents a complete MCP server definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tools: Vec<ToolDefinition>,
    #[serde(default)]
    pub auth: AuthConfig,
    /// Transport type (e.g., "stdio", "http", "sse").
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Optional URL or command for the server.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables passed to the server.
    /// Uses BTreeMap for deterministic serialization order.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

fn default_transport() -> String {
    "stdio".to_string()
}

/// Top-level MCP configuration, possibly containing multiple servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    #[serde(default)]
    pub servers: Vec<McpServer>,
}

/// The mcp.tools.json format: a flat list of tools for a single server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolsFile {
    #[serde(default)]
    pub server_name: Option<String>,
    pub tools: Vec<ToolDefinition>,
    #[serde(default)]
    pub auth: AuthConfig,
}

impl McpConfig {
    /// Load from an mcp.config.json file content.
    pub fn from_config_json(content: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(content)
    }

    /// Load from an mcp.tools.json file content, wrapping in a single-server config.
    pub fn from_tools_json(content: &str) -> Result<Self, serde_json::Error> {
        let tools_file: McpToolsFile = serde_json::from_str(content)?;
        Ok(McpConfig {
            servers: vec![McpServer {
                name: tools_file
                    .server_name
                    .unwrap_or_else(|| "default".to_string()),
                description: String::new(),
                tools: tools_file.tools,
                auth: tools_file.auth,
                transport: default_transport(),
                url: None,
                command: None,
                args: vec![],
                env: BTreeMap::new(),
            }],
        })
    }

    /// Auto-detect format and load.
    pub fn load(content: &str, filename: &str) -> Result<Self, serde_json::Error> {
        if filename.contains("tools") {
            Self::from_tools_json(content)
        } else {
            Self::from_config_json(content)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tools_json() {
        let json = r#"{
            "server_name": "test-server",
            "tools": [
                {
                    "name": "run_query",
                    "description": "Execute a SQL query",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "description": "SQL query to execute",
                            "required": true
                        }
                    ]
                }
            ],
            "auth": { "type": "none" }
        }"#;

        let config = McpConfig::from_tools_json(json).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].name, "test-server");
        assert_eq!(config.servers[0].tools.len(), 1);
        assert_eq!(config.servers[0].tools[0].name, "run_query");
    }

    #[test]
    fn parse_config_json() {
        let json = r#"{
            "servers": [
                {
                    "name": "db-server",
                    "description": "Database access server",
                    "tools": [],
                    "auth": { "type": "api_key", "header": "X-API-Key" },
                    "transport": "http",
                    "url": "http://localhost:8080"
                }
            ]
        }"#;

        let config = McpConfig::from_config_json(json).unwrap();
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].name, "db-server");
        assert!(matches!(config.servers[0].auth, AuthConfig::ApiKey { .. }));
    }
}
