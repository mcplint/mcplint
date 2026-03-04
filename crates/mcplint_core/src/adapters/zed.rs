use super::{AdapterError, AdapterResult, McpAdapter, SourceInfo};
use crate::adapters::claude_desktop::{infer_auth_from_env, infer_tools_from_command};
use crate::json_locator::escape_pointer;
use crate::{McpConfig, McpServer};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Adapter for Zed editor MCP configuration.
///
/// Zed stores MCP config in `settings.json` with a `context_servers` key:
/// ```json
/// {
///   "context_servers": {
///     "server-name": {
///       "command": { "path": "node", "args": [...], "env": {} }
///     }
///   }
/// }
/// ```
///
/// Zed settings files may contain JSONC (JSON with comments).
pub struct ZedAdapter;

#[derive(Debug, Deserialize)]
struct ZedSettings {
    #[serde(default)]
    context_servers: BTreeMap<String, ZedServerEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ZedServerEntry {
    /// Nested command format: { "command": { "path": "...", "args": [...] } }
    Nested {
        #[serde(default)]
        #[allow(dead_code)]
        settings: Option<serde_json::Value>,
        command: ZedCommandConfig,
    },
    /// Flat format: { "source": "...", "command": "...", "args": [...] }
    Flat {
        #[serde(default)]
        #[allow(dead_code)]
        source: Option<String>,
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
}

#[derive(Debug, Deserialize)]
struct ZedCommandConfig {
    path: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

const ZED_DIRS: &[&str] = &[".config/zed", ".zed"];

impl McpAdapter for ZedAdapter {
    fn name(&self) -> &'static str {
        "zed"
    }

    fn detect(&self, path: &Path) -> bool {
        if path.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name != "settings.json" {
                return false;
            }
            // Check if path contains "zed" (case-insensitive)
            let path_str = path.to_string_lossy().to_lowercase();
            if path_str.contains("zed") {
                // Quick content check
                if let Ok(content) = std::fs::read_to_string(path) {
                    return content.contains("context_servers");
                }
            }
            // Also detect any settings.json with context_servers
            if let Ok(content) = std::fs::read_to_string(path) {
                return content.contains("context_servers");
            }
            return false;
        }

        if path.is_dir() {
            for zed_dir in ZED_DIRS {
                let settings = path.join(zed_dir).join("settings.json");
                if settings.is_file() {
                    if let Ok(content) = std::fs::read_to_string(&settings) {
                        if content.contains("context_servers") {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn load(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        let config_path = if path.is_dir() {
            ZED_DIRS
                .iter()
                .map(|d| path.join(d).join("settings.json"))
                .find(|p| p.is_file())
                .ok_or_else(|| {
                    AdapterError::UnsupportedFormat(
                        "No Zed settings.json found in directory".to_string(),
                    )
                })?
        } else {
            path.to_path_buf()
        };

        let raw_content =
            std::fs::read_to_string(&config_path).map_err(|e| AdapterError::io(&config_path, e))?;

        // Strip JSONC comments before parsing
        let content = strip_json_comments(&raw_content);

        let location_map = crate::json_locator::JsonLocationMap::from_source(&content);

        let settings: ZedSettings =
            serde_json::from_str(&content).map_err(|e| AdapterError::parse(&config_path, e))?;

        if settings.context_servers.is_empty() {
            return Err(AdapterError::UnsupportedFormat(
                "No context_servers found in Zed settings".to_string(),
            ));
        }

        let mut warnings = Vec::new();
        let mut servers = Vec::new();
        let mut source_info = Vec::new();

        for (name, entry) in &settings.context_servers {
            let (command, args, env, url) = match entry {
                ZedServerEntry::Nested { command: cmd, .. } => (
                    Some(cmd.path.clone()),
                    cmd.args.clone(),
                    cmd.env.clone(),
                    None,
                ),
                ZedServerEntry::Flat {
                    command, args, env, ..
                } => (Some(command.clone()), args.clone(), env.clone(), None),
            };

            let auth = infer_auth_from_env(&env);
            let tools = infer_tools_from_command(&command, &args, &mut warnings, name);

            servers.push(McpServer {
                name: name.clone(),
                description: String::new(),
                tools,
                auth,
                transport: "stdio".to_string(),
                url,
                command,
                args,
                env,
            });

            source_info.push(SourceInfo::with_pointer(
                &config_path,
                &format!("/context_servers/{}", escape_pointer(name)),
            ));
        }

        // Sort by name
        let mut paired: Vec<_> = servers.into_iter().zip(source_info).collect();
        paired.sort_by(|(a, _), (b, _)| a.name.cmp(&b.name));
        let (servers, source_info): (Vec<_>, Vec<_>) = paired.into_iter().unzip();

        let server_pointers: BTreeMap<String, String> = servers
            .iter()
            .map(|s| {
                (
                    s.name.clone(),
                    format!("/context_servers/{}", escape_pointer(&s.name)),
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

/// Strip JSON comments (// line comments and /* block comments */) while
/// preserving string contents unchanged.
pub fn strip_json_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // String literal — copy verbatim
        if chars[i] == '"' {
            out.push('"');
            i += 1;
            while i < len {
                if chars[i] == '\\' && i + 1 < len {
                    out.push(chars[i]);
                    out.push(chars[i + 1]);
                    i += 2;
                } else if chars[i] == '"' {
                    out.push('"');
                    i += 1;
                    break;
                } else {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            continue;
        }

        // Line comment
        if chars[i] == '/' && i + 1 < len && chars[i + 1] == '/' {
            // Skip until end of line
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        // Block comment
        if chars[i] == '/' && i + 1 < len && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < len {
                if chars[i] == '*' && chars[i + 1] == '/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            // Handle case where block comment reaches end of input
            if i >= len {
                break;
            }
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nested_command() {
        let json = r#"{
            "context_servers": {
                "filesystem": {
                    "command": {
                        "path": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                        "env": {}
                    }
                }
            }
        }"#;
        let settings: ZedSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.context_servers.len(), 1);
        match &settings.context_servers["filesystem"] {
            ZedServerEntry::Nested { command, .. } => {
                assert_eq!(command.path, "npx");
                assert_eq!(command.args.len(), 3);
            }
            _ => panic!("Expected Nested variant"),
        }
    }

    #[test]
    fn parse_flat_command() {
        let json = r#"{
            "context_servers": {
                "github": {
                    "source": "custom",
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "ghp_xxx"}
                }
            }
        }"#;
        let settings: ZedSettings = serde_json::from_str(json).unwrap();
        match &settings.context_servers["github"] {
            ZedServerEntry::Flat {
                command, args, env, ..
            } => {
                assert_eq!(command, "npx");
                assert_eq!(args.len(), 2);
                assert!(env.contains_key("GITHUB_TOKEN"));
            }
            _ => panic!("Expected Flat variant"),
        }
    }

    #[test]
    fn parse_mixed_formats() {
        let json = r#"{
            "context_servers": {
                "fs": {
                    "command": {
                        "path": "npx",
                        "args": ["-y", "server-filesystem"],
                        "env": {}
                    }
                },
                "gh": {
                    "source": "custom",
                    "command": "npx",
                    "args": ["-y", "server-github"],
                    "env": {}
                }
            }
        }"#;
        let settings: ZedSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.context_servers.len(), 2);
    }

    #[test]
    fn detect_zed_settings() {
        let dir = tempfile::tempdir().unwrap();
        let zed_dir = dir.path().join(".config/zed");
        std::fs::create_dir_all(&zed_dir).unwrap();
        std::fs::write(
            zed_dir.join("settings.json"),
            r#"{"context_servers": {"fs": {"command": {"path": "npx", "args": []}}}}"#,
        )
        .unwrap();

        let adapter = ZedAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn detect_rejects_settings_without_mcp() {
        let dir = tempfile::tempdir().unwrap();
        let zed_dir = dir.path().join(".config/zed");
        std::fs::create_dir_all(&zed_dir).unwrap();
        std::fs::write(zed_dir.join("settings.json"), r#"{"theme": "One Dark"}"#).unwrap();

        let adapter = ZedAdapter;
        assert!(!adapter.detect(dir.path()));
    }

    #[test]
    fn strip_comments_line() {
        let input = r#"{
  // this is a comment
  "key": "value"
}"#;
        let stripped = strip_json_comments(input);
        assert!(!stripped.contains("// this is"));
        let parsed: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(parsed["key"], "value");
    }

    #[test]
    fn strip_comments_block() {
        let input = r#"{
  /* block comment */
  "key": "value"
}"#;
        let stripped = strip_json_comments(input);
        assert!(!stripped.contains("block comment"));
        let parsed: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(parsed["key"], "value");
    }

    #[test]
    fn strip_comments_preserves_strings() {
        let input = r#"{"url": "http://example.com // not a comment"}"#;
        let stripped = strip_json_comments(input);
        let parsed: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(parsed["url"], "http://example.com // not a comment");
    }

    #[test]
    fn load_settings_with_comments() {
        let dir = tempfile::tempdir().unwrap();
        let zed_dir = dir.path().join(".config/zed");
        std::fs::create_dir_all(&zed_dir).unwrap();
        let jsonc = r#"{
  // Editor settings
  "theme": "One Dark",
  /* MCP servers */
  "context_servers": {
    // Filesystem
    "filesystem": {
      "command": {
        "path": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        "env": {}
      }
    }
  }
}"#;
        std::fs::write(zed_dir.join("settings.json"), jsonc).unwrap();

        let adapter = ZedAdapter;
        let result = adapter.load(dir.path()).unwrap();
        assert_eq!(result.config.servers.len(), 1);
        assert_eq!(result.config.servers[0].name, "filesystem");
    }

    #[test]
    fn zed_pointers_use_context_servers() {
        let dir = tempfile::tempdir().unwrap();
        let zed_dir = dir.path().join(".config/zed");
        std::fs::create_dir_all(&zed_dir).unwrap();
        std::fs::write(
            zed_dir.join("settings.json"),
            r#"{"context_servers": {"fs": {"command": {"path": "npx", "args": [], "env": {}}}}}"#,
        )
        .unwrap();

        let adapter = ZedAdapter;
        let result = adapter.load(dir.path()).unwrap();
        assert_eq!(
            result.server_pointers.get("fs").unwrap(),
            "/context_servers/fs"
        );
    }
}
