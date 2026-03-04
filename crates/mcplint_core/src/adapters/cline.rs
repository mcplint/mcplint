use super::{AdapterError, AdapterResult, McpAdapter, SourceInfo};
use crate::json_locator::escape_pointer;
use crate::McpConfig;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Adapter for Cline MCP configuration.
///
/// Cline stores MCP config at:
/// - `.cline/mcp_settings.json`
/// - `.cline/mcp.json` (newer versions)
///
/// Format uses `mcpServers` object map (same as Claude Desktop) with additional
/// `disabled` and `alwaysAllow` fields per server.
pub struct ClineAdapter;

const CLINE_DIR: &str = ".cline";
const CLINE_FILENAMES: &[&str] = &["mcp_settings.json", "mcp.json"];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClineMcpConfig {
    #[serde(default)]
    mcp_servers: BTreeMap<String, ClineServerEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClineServerEntry {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    always_allow: Vec<String>,
}

impl McpAdapter for ClineAdapter {
    fn name(&self) -> &'static str {
        "cline"
    }

    fn detect(&self, path: &Path) -> bool {
        if path.is_file() {
            let path_str = path.to_string_lossy();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if CLINE_FILENAMES.contains(&name) && path_str.contains(CLINE_DIR) {
                    return true;
                }
            }
        }

        if path.is_dir() {
            let cline_dir = path.join(CLINE_DIR);
            if cline_dir.is_dir() {
                return CLINE_FILENAMES
                    .iter()
                    .any(|name| cline_dir.join(name).is_file());
            }
        }

        false
    }

    fn load(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        let config_path = if path.is_dir() {
            let cline_dir = path.join(CLINE_DIR);
            CLINE_FILENAMES
                .iter()
                .map(|name| cline_dir.join(name))
                .find(|p| p.is_file())
                .ok_or_else(|| {
                    AdapterError::UnsupportedFormat("No Cline MCP config found".to_string())
                })?
        } else {
            path.to_path_buf()
        };

        let content =
            std::fs::read_to_string(&config_path).map_err(|e| AdapterError::io(&config_path, e))?;

        let location_map = crate::json_locator::JsonLocationMap::from_source(&content);

        let raw: ClineMcpConfig =
            serde_json::from_str(&content).map_err(|e| AdapterError::parse(&config_path, e))?;

        let mut warnings = Vec::new();
        let mut servers = Vec::new();
        let mut source_info = Vec::new();

        for (name, entry) in &raw.mcp_servers {
            // Skip disabled servers
            if entry.disabled {
                warnings.push(format!("Server '{}': disabled, skipping", name));
                continue;
            }

            // Warn about alwaysAllow
            if !entry.always_allow.is_empty() {
                warnings.push(format!(
                    "Server '{}' has alwaysAllow for {} tools — auto-approved tools bypass user confirmation",
                    name,
                    entry.always_allow.len()
                ));
            }

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
    fn parse_cline_config() {
        let json = r#"{
            "mcpServers": {
                "my-server": {
                    "command": "npx",
                    "args": ["-y", "@some/mcp-server"],
                    "env": { "KEY": "value" },
                    "disabled": false,
                    "alwaysAllow": ["tool1", "tool2"]
                }
            }
        }"#;

        let raw: ClineMcpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(raw.mcp_servers.len(), 1);
        let entry = &raw.mcp_servers["my-server"];
        assert!(!entry.disabled);
        assert_eq!(entry.always_allow.len(), 2);
    }

    #[test]
    fn disabled_server_skipped() {
        let json = r#"{
            "mcpServers": {
                "active": {
                    "command": "node",
                    "args": ["server.js"]
                },
                "inactive": {
                    "command": "node",
                    "args": ["other.js"],
                    "disabled": true
                }
            }
        }"#;

        let raw: ClineMcpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(raw.mcp_servers.len(), 2);
        assert!(raw.mcp_servers["inactive"].disabled);
    }

    #[test]
    fn detect_cline_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let cline_dir = dir.path().join(".cline");
        std::fs::create_dir_all(&cline_dir).unwrap();
        let settings_file = cline_dir.join("mcp_settings.json");
        std::fs::write(&settings_file, r#"{"mcpServers":{}}"#).unwrap();

        let adapter = ClineAdapter;
        assert!(adapter.detect(&settings_file));
        assert!(adapter.detect(dir.path()));
    }
}
