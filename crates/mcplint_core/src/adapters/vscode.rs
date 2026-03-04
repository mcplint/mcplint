use super::{AdapterError, AdapterResult, McpAdapter, SourceInfo};
use crate::json_locator::escape_pointer;
use crate::McpConfig;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Adapter for VS Code MCP configuration.
///
/// VS Code stores MCP server configurations in:
/// - `.vscode/mcp.json` (project-level)
/// - User `settings.json` with `"mcp"` → `"servers"` key
///
/// Format: servers is an object mapping server names to configs:
/// ```json
/// {
///   "servers": {
///     "my-server": {
///       "type": "stdio",
///       "command": "node",
///       "args": ["server.js"],
///       "env": { "API_KEY": "..." }
///     }
///   }
/// }
/// ```
///
/// May also be wrapped in an `"mcp"` key from settings.json.
pub struct VsCodeAdapter;

const VSCODE_DIR: &str = ".vscode";
const VSCODE_MCP_FILENAME: &str = "mcp.json";

#[derive(Debug, Deserialize)]
struct VsCodeMcpConfig {
    #[serde(default)]
    servers: BTreeMap<String, VsCodeServerEntry>,
}

#[derive(Debug, Deserialize)]
struct VsCodeSettingsWrapper {
    #[serde(default)]
    mcp: Option<VsCodeMcpConfig>,
}

#[derive(Debug, Deserialize)]
struct VsCodeServerEntry {
    #[serde(default, rename = "type")]
    transport_type: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    url: Option<String>,
}

impl McpAdapter for VsCodeAdapter {
    fn name(&self) -> &'static str {
        "vscode"
    }

    fn detect(&self, path: &Path) -> bool {
        if path.is_file() {
            let path_str = path.to_string_lossy();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                // .vscode/mcp.json
                if name == VSCODE_MCP_FILENAME && path_str.contains(VSCODE_DIR) {
                    return true;
                }
            }
        }

        if path.is_dir() {
            let vscode_dir = path.join(VSCODE_DIR);
            if vscode_dir.join(VSCODE_MCP_FILENAME).is_file() {
                return true;
            }
        }

        false
    }

    fn load(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        let config_path = if path.is_dir() {
            path.join(VSCODE_DIR).join(VSCODE_MCP_FILENAME)
        } else {
            path.to_path_buf()
        };

        let content =
            std::fs::read_to_string(&config_path).map_err(|e| AdapterError::io(&config_path, e))?;

        let location_map = crate::json_locator::JsonLocationMap::from_source(&content);

        // Try unwrapping "mcp" wrapper first (settings.json style)
        let mcp_config =
            if let Ok(wrapper) = serde_json::from_str::<VsCodeSettingsWrapper>(&content) {
                if let Some(inner) = wrapper.mcp {
                    inner
                } else {
                    serde_json::from_str::<VsCodeMcpConfig>(&content)
                        .map_err(|e| AdapterError::parse(&config_path, e))?
                }
            } else {
                serde_json::from_str::<VsCodeMcpConfig>(&content)
                    .map_err(|e| AdapterError::parse(&config_path, e))?
            };

        let mut warnings = Vec::new();
        let mut servers = Vec::new();
        let mut source_info = Vec::new();

        // Determine the JSON pointer prefix based on whether "mcp" wrapper is present
        let has_mcp_wrapper = content.contains("\"mcp\"");
        let pointer_prefix = if has_mcp_wrapper {
            "/mcp/servers"
        } else {
            "/servers"
        };

        for (name, entry) in &mcp_config.servers {
            let transport = entry.transport_type.clone().unwrap_or_else(|| {
                if entry.url.is_some() {
                    "sse".to_string()
                } else {
                    "stdio".to_string()
                }
            });

            let auth = super::claude_desktop::infer_auth_from_env(&entry.env);
            let tools = super::claude_desktop::infer_tools_from_command(
                &entry.command,
                &entry.args,
                &mut warnings,
                name,
            );

            servers.push(crate::McpServer {
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
                &format!("{}/{}", pointer_prefix, escape_pointer(name)),
            ));
        }

        // Deterministic ordering
        let mut paired: Vec<_> = servers.into_iter().zip(source_info).collect();
        paired.sort_by(|(a, _), (b, _)| a.name.cmp(&b.name));
        let (servers, source_info): (Vec<_>, Vec<_>) = paired.into_iter().unzip();

        let server_pointers: BTreeMap<String, String> = servers
            .iter()
            .map(|s| {
                (
                    s.name.clone(),
                    format!("{}/{}", pointer_prefix, escape_pointer(&s.name)),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vscode_servers_object() {
        let json = r#"{
            "servers": {
                "my-server": {
                    "type": "stdio",
                    "command": "node",
                    "args": ["server.js"],
                    "env": { "API_KEY": "test" }
                }
            }
        }"#;

        let raw: VsCodeMcpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(raw.servers.len(), 1);
        assert!(raw.servers.contains_key("my-server"));
    }

    #[test]
    fn parse_vscode_mcp_wrapper() {
        let json = r#"{
            "mcp": {
                "servers": {
                    "wrapped-server": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                    }
                }
            }
        }"#;

        let wrapper: VsCodeSettingsWrapper = serde_json::from_str(json).unwrap();
        let inner = wrapper.mcp.unwrap();
        assert_eq!(inner.servers.len(), 1);
        assert!(inner.servers.contains_key("wrapped-server"));
    }

    #[test]
    fn detect_vscode_path() {
        let adapter = VsCodeAdapter;
        // Test path-based detection
        let dir = tempfile::TempDir::new().unwrap();
        let vscode_dir = dir.path().join(".vscode");
        std::fs::create_dir_all(&vscode_dir).unwrap();
        let mcp_file = vscode_dir.join("mcp.json");
        std::fs::write(&mcp_file, r#"{"servers":{}}"#).unwrap();

        assert!(adapter.detect(&mcp_file));
        assert!(adapter.detect(dir.path()));
    }
}
