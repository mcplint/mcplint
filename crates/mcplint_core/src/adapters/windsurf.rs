use super::{AdapterError, AdapterResult, McpAdapter, SourceInfo};
use crate::json_locator::escape_pointer;
use crate::McpConfig;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Adapter for Windsurf (Codeium) MCP configuration.
///
/// Windsurf stores MCP config at:
/// - `~/.codeium/windsurf/mcp_config.json`
/// - `.windsurf/mcp.json`
///
/// Format uses `mcpServers` object map (same as Claude Desktop).
pub struct WindsurfAdapter;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WindsurfMcpConfig {
    #[serde(default)]
    mcp_servers: BTreeMap<String, WindsurfServerEntry>,
}

#[derive(Debug, Deserialize)]
struct WindsurfServerEntry {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    url: Option<String>,
}

impl McpAdapter for WindsurfAdapter {
    fn name(&self) -> &'static str {
        "windsurf"
    }

    fn detect(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();

        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let name_lower = name.to_lowercase();
                if (name_lower == "mcp_config.json" || name_lower == "mcp.json")
                    && (path_str.contains("windsurf") || path_str.contains("codeium"))
                {
                    return true;
                }
            }
        }

        if path.is_dir() {
            // Check .windsurf/mcp.json
            let windsurf_dir = path.join(".windsurf");
            if windsurf_dir.join("mcp.json").is_file() {
                return true;
            }
        }

        false
    }

    fn load(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        let config_path = if path.is_dir() {
            let windsurf_mcp = path.join(".windsurf").join("mcp.json");
            if windsurf_mcp.is_file() {
                windsurf_mcp
            } else {
                return Err(AdapterError::UnsupportedFormat(
                    "No Windsurf MCP config found".to_string(),
                ));
            }
        } else {
            path.to_path_buf()
        };

        let content =
            std::fs::read_to_string(&config_path).map_err(|e| AdapterError::io(&config_path, e))?;

        let location_map = crate::json_locator::JsonLocationMap::from_source(&content);

        let raw: WindsurfMcpConfig =
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
                &format!("/mcpServers/{}", escape_pointer(name)),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_windsurf_config() {
        let json = r#"{
            "mcpServers": {
                "my-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {}
                }
            }
        }"#;

        let raw: WindsurfMcpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(raw.mcp_servers.len(), 1);
        assert!(raw.mcp_servers.contains_key("my-server"));
    }

    #[test]
    fn detect_windsurf_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let windsurf_dir = dir.path().join(".windsurf");
        std::fs::create_dir_all(&windsurf_dir).unwrap();
        let mcp_file = windsurf_dir.join("mcp.json");
        std::fs::write(&mcp_file, r#"{"mcpServers":{}}"#).unwrap();

        let adapter = WindsurfAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn detect_codeium_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let codeium_dir = dir.path().join(".codeium").join("windsurf");
        std::fs::create_dir_all(&codeium_dir).unwrap();
        let mcp_file = codeium_dir.join("mcp_config.json");
        std::fs::write(&mcp_file, r#"{"mcpServers":{}}"#).unwrap();

        let adapter = WindsurfAdapter;
        assert!(adapter.detect(&mcp_file));
    }
}
