use super::{AdapterError, AdapterResult, McpAdapter, SourceInfo};
use crate::json_locator::escape_pointer;
use crate::{McpConfig, McpServer};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Adapter for Cursor's MCP configuration.
///
/// Cursor stores MCP servers in:
/// - `.cursor/mcp.json` (primary, project-level)
/// - `settings.json` under `mcpServers` key (user-level)
///
/// Both use the same `{ "mcpServers": { ... } }` structure as Claude Desktop.
pub struct CursorAdapter;

/// Files to look for inside `.cursor/` directory.
const CURSOR_MCP_FILENAMES: &[&str] = &["mcp.json"];
/// Cursor settings file that may embed MCP config.
const CURSOR_SETTINGS: &str = "settings.json";
const CURSOR_DIR: &str = ".cursor";

/// Raw Cursor MCP config — same shape as Claude Desktop.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CursorMcpConfig {
    #[serde(default)]
    mcp_servers: BTreeMap<String, CursorServerEntry>,
}

#[derive(Debug, Deserialize)]
struct CursorServerEntry {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    url: Option<String>,
}

impl McpAdapter for CursorAdapter {
    fn name(&self) -> &'static str {
        "cursor"
    }

    fn detect(&self, path: &Path) -> bool {
        if path.is_file() {
            // File inside .cursor/ directory
            if let Some(parent) = path.parent() {
                if parent.file_name().and_then(|n| n.to_str()) == Some(CURSOR_DIR) {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        return CURSOR_MCP_FILENAMES.contains(&name) || name == CURSOR_SETTINGS;
                    }
                }
            }
            // Standalone mcp.json with mcpServers key (could be Cursor project config)
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if CURSOR_MCP_FILENAMES.contains(&name) {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        return content.contains("mcpServers");
                    }
                }
            }
        }

        // Directory: check for .cursor/mcp.json or .cursor/settings.json with mcpServers
        if path.is_dir() {
            let cursor_dir = path.join(CURSOR_DIR);
            if cursor_dir.is_dir() {
                if CURSOR_MCP_FILENAMES
                    .iter()
                    .any(|name| cursor_dir.join(name).is_file())
                {
                    return true;
                }
                // Check settings.json for embedded mcpServers
                let settings_path = cursor_dir.join(CURSOR_SETTINGS);
                if settings_path.is_file() {
                    if let Ok(content) = std::fs::read_to_string(&settings_path) {
                        return content.contains("mcpServers");
                    }
                }
            }
        }

        false
    }

    fn load(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        let config_path = self.resolve_config_path(path)?;

        let content =
            std::fs::read_to_string(&config_path).map_err(|e| AdapterError::io(&config_path, e))?;

        let location_map = crate::json_locator::JsonLocationMap::from_source(&content);

        let raw: CursorMcpConfig =
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

            let auth = super::claude_desktop::infer_auth_from_env(&entry.env);

            let tools = super::claude_desktop::infer_tools_from_command(
                &entry.command,
                &entry.args,
                &mut warnings,
                name,
            );

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

        // Deterministic ordering by server name
        let mut paired: Vec<_> = servers.into_iter().zip(source_info).collect();
        paired.sort_by(|(a, _), (b, _)| a.name.cmp(&b.name));
        let (servers, source_info): (Vec<_>, Vec<_>) = paired.into_iter().unzip();

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

impl CursorAdapter {
    /// Resolve the actual config file path from a file or directory argument.
    fn resolve_config_path(&self, path: &Path) -> Result<std::path::PathBuf, AdapterError> {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }

        if path.is_dir() {
            let cursor_dir = path.join(CURSOR_DIR);

            // Prefer mcp.json over settings.json
            for name in CURSOR_MCP_FILENAMES {
                let candidate = cursor_dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }

            // Fall back to settings.json if it has mcpServers
            let settings_path = cursor_dir.join(CURSOR_SETTINGS);
            if settings_path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&settings_path) {
                    if content.contains("mcpServers") {
                        return Ok(settings_path);
                    }
                }
            }
        }

        Err(AdapterError::UnsupportedFormat(
            "No Cursor MCP config found".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cursor_config() {
        let json = r#"{
            "mcpServers": {
                "my-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "API_KEY": "test-key"
                    }
                }
            }
        }"#;

        let raw: CursorMcpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(raw.mcp_servers.len(), 1);
        assert!(raw.mcp_servers.contains_key("my-server"));
    }

    #[test]
    fn parse_cursor_with_filesystem() {
        let json = r#"{
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home"]
                }
            }
        }"#;

        let raw: CursorMcpConfig = serde_json::from_str(json).unwrap();
        let entry = &raw.mcp_servers["fs"];
        assert_eq!(entry.command, Some("npx".to_string()));
        assert!(entry.args.iter().any(|a| a.contains("filesystem")));
    }

    #[test]
    fn parse_cursor_with_url_transport() {
        let json = r#"{
            "mcpServers": {
                "remote": {
                    "url": "https://api.example.com/mcp",
                    "env": {
                        "AUTH_TOKEN": "bearer-token"
                    }
                }
            }
        }"#;

        let raw: CursorMcpConfig = serde_json::from_str(json).unwrap();
        let entry = &raw.mcp_servers["remote"];
        assert_eq!(entry.url, Some("https://api.example.com/mcp".to_string()));
        assert!(entry.command.is_none());
    }
}
