use super::{AdapterError, AdapterResult, McpAdapter, SourceInfo};
use crate::adapters::claude_desktop::{infer_auth_from_env, infer_tools_from_command};
use crate::{McpConfig, McpServer};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Adapter for Continue.dev MCP configuration.
///
/// Continue.dev stores MCP config in two ways:
/// - Directory: `.continue/mcpServers/` with individual YAML or JSON files per server
/// - Inline: `.continue/config.yaml` with an `mcpServers` array
///
/// YAML configs use an array of server objects (not object map).
/// JSON configs inside `mcpServers/` use the Claude Desktop object map format.
pub struct ContinueDevAdapter;

const CONTINUE_DIR: &str = ".continue";
const MCP_SERVERS_DIR: &str = "mcpServers";

/// YAML server entry (array-style with explicit name field).
#[derive(Debug, Deserialize)]
struct ContinueYamlServerEntry {
    name: String,
    #[serde(default, rename = "type")]
    transport_type: Option<String>,
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    url: Option<String>,
}

/// YAML file wrapper (mcpServers as array).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContinueYamlFile {
    #[serde(default)]
    mcp_servers: Vec<ContinueYamlServerEntry>,
}

/// JSON file wrapper (mcpServers as object map, same as Claude Desktop).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContinueJsonFile {
    #[serde(default)]
    mcp_servers: BTreeMap<String, ContinueJsonServerEntry>,
}

#[derive(Debug, Deserialize)]
struct ContinueJsonServerEntry {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    url: Option<String>,
}

/// config.yaml top-level (only cares about mcpServers key).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContinueConfig {
    #[serde(default)]
    mcp_servers: Vec<ContinueYamlServerEntry>,
}

impl McpAdapter for ContinueDevAdapter {
    fn name(&self) -> &'static str {
        "continue"
    }

    fn detect(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        if path.is_file() {
            // File inside .continue/mcpServers/ directory
            if path_str.contains(CONTINUE_DIR) {
                if let Some(parent) = path.parent() {
                    let parent_name = parent.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if parent_name == MCP_SERVERS_DIR {
                        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                            return matches!(ext, "json" | "yaml" | "yml");
                        }
                    }
                }
                // config.yaml or config.json inside .continue/
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    return name == "config.yaml" || name == "config.json";
                }
            }
            return false;
        }

        if path.is_dir() {
            // Check for .continue/mcpServers/ directory with config files
            let mcp_dir = path.join(CONTINUE_DIR).join(MCP_SERVERS_DIR);
            if mcp_dir.is_dir() && has_config_files(&mcp_dir) {
                return true;
            }
            // Check for .continue/config.yaml with mcpServers
            let config_yaml = path.join(CONTINUE_DIR).join("config.yaml");
            if config_yaml.is_file() {
                if let Ok(content) = std::fs::read_to_string(&config_yaml) {
                    return content.contains("mcpServers");
                }
            }
        }

        false
    }

    fn load(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        if path.is_dir() {
            return self.load_directory(path);
        }

        // Single file
        let path_str = path.to_string_lossy();
        if let Some(parent) = path.parent() {
            let parent_name = parent.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if parent_name == MCP_SERVERS_DIR {
                return self.load_single_file(path);
            }
        }

        // config.yaml or config.json
        if path_str.contains(CONTINUE_DIR) {
            return self.load_config_file(path);
        }

        Err(AdapterError::UnsupportedFormat(
            "Not a Continue.dev configuration".to_string(),
        ))
    }
}

impl ContinueDevAdapter {
    fn load_directory(&self, dir: &Path) -> Result<AdapterResult, AdapterError> {
        let mcp_dir = dir.join(CONTINUE_DIR).join(MCP_SERVERS_DIR);
        let config_yaml = dir.join(CONTINUE_DIR).join("config.yaml");

        let mut all_servers: Vec<McpServer> = Vec::new();
        let mut all_source_info: Vec<SourceInfo> = Vec::new();
        let mut warnings = Vec::new();
        let mut seen_names: BTreeMap<String, String> = BTreeMap::new(); // name → file

        // Load from mcpServers/ directory first
        if mcp_dir.is_dir() {
            let mut files: Vec<_> = std::fs::read_dir(&mcp_dir)
                .map_err(|e| AdapterError::io(&mcp_dir, e))?
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| matches!(ext, "json" | "yaml" | "yml"))
                        .unwrap_or(false)
                })
                .collect();
            files.sort_by_key(|e| e.file_name());

            for entry in &files {
                let file_path = entry.path();
                match self.load_single_file(&file_path) {
                    Ok(result) => {
                        for (server, si) in
                            result.config.servers.into_iter().zip(result.source_info)
                        {
                            if let Some(prev_file) = seen_names.get(&server.name) {
                                warnings.push(format!(
                                    "Server '{}' redefined in '{}' (previously in '{}')",
                                    server.name,
                                    file_path.display(),
                                    prev_file,
                                ));
                                // Remove the old one
                                if let Some(pos) =
                                    all_servers.iter().position(|s| s.name == server.name)
                                {
                                    all_servers.remove(pos);
                                    all_source_info.remove(pos);
                                }
                            }
                            seen_names.insert(server.name.clone(), file_path.display().to_string());
                            all_servers.push(server);
                            all_source_info.push(si);
                        }
                        warnings.extend(result.warnings);
                    }
                    Err(e) => {
                        warnings.push(format!("Failed to load {}: {}", file_path.display(), e));
                    }
                }
            }
        }

        // Load from config.yaml if exists and no servers found yet
        if all_servers.is_empty() && config_yaml.is_file() {
            match self.load_config_file(&config_yaml) {
                Ok(result) => {
                    all_servers = result.config.servers;
                    all_source_info = result.source_info;
                    warnings.extend(result.warnings);
                }
                Err(e) => {
                    warnings.push(format!("Failed to load config.yaml: {}", e));
                }
            }
        }

        if all_servers.is_empty() {
            return Err(AdapterError::UnsupportedFormat(
                "No Continue.dev MCP servers found".to_string(),
            ));
        }

        let server_pointers: BTreeMap<String, String> = all_servers
            .iter()
            .map(|s| (s.name.clone(), String::new()))
            .collect();

        Ok(AdapterResult {
            config: McpConfig {
                servers: all_servers,
            },
            adapter_name: self.name(),
            warnings,
            source_info: all_source_info,
            location_map: None, // Multi-file; no single location map
            server_pointers,
        })
    }

    fn load_single_file(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        let content = std::fs::read_to_string(path).map_err(|e| AdapterError::io(path, e))?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match ext {
            "yaml" | "yml" => self.parse_yaml_file(&content, path),
            "json" => self.parse_json_file(&content, path),
            _ => Err(AdapterError::UnsupportedFormat(format!(
                "Unsupported file extension: {}",
                ext
            ))),
        }
    }

    fn load_config_file(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        let content = std::fs::read_to_string(path).map_err(|e| AdapterError::io(path, e))?;

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        if ext == "json" {
            // config.json uses same format as JSON in mcpServers/
            return self.parse_json_file(&content, path);
        }

        // YAML config.yaml
        let config: ContinueConfig = serde_yaml::from_str(&content).map_err(|e| {
            AdapterError::UnsupportedFormat(format!(
                "Failed to parse Continue config YAML {}: {}",
                path.display(),
                e
            ))
        })?;

        self.build_from_yaml_entries(config.mcp_servers, path)
    }

    fn parse_yaml_file(&self, content: &str, path: &Path) -> Result<AdapterResult, AdapterError> {
        let file: ContinueYamlFile = serde_yaml::from_str(content).map_err(|e| {
            AdapterError::UnsupportedFormat(format!(
                "Failed to parse Continue YAML {}: {}",
                path.display(),
                e
            ))
        })?;

        self.build_from_yaml_entries(file.mcp_servers, path)
    }

    fn parse_json_file(&self, content: &str, path: &Path) -> Result<AdapterResult, AdapterError> {
        let location_map = crate::json_locator::JsonLocationMap::from_source(content);
        let raw: ContinueJsonFile =
            serde_json::from_str(content).map_err(|e| AdapterError::parse(path, e))?;

        let mut warnings = Vec::new();
        let mut servers = Vec::new();
        let mut source_info = Vec::new();

        for (name, entry) in &raw.mcp_servers {
            let transport = if entry.url.is_some() {
                "sse".to_string()
            } else {
                "stdio".to_string()
            };
            let auth = infer_auth_from_env(&entry.env);
            let tools = infer_tools_from_command(&entry.command, &entry.args, &mut warnings, name);

            // Check for Continue.dev secret templates
            for value in entry.env.values() {
                if value.starts_with("${{") {
                    warnings.push(format!(
                        "Server '{}' uses Continue.dev secret references (${{{{ secrets.* }}}}). \
                         Actual values are injected at runtime.",
                        name
                    ));
                    break;
                }
            }

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
                path,
                &format!("/mcpServers/{}", crate::json_locator::escape_pointer(name)),
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
                    format!(
                        "/mcpServers/{}",
                        crate::json_locator::escape_pointer(&s.name)
                    ),
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

    fn build_from_yaml_entries(
        &self,
        entries: Vec<ContinueYamlServerEntry>,
        path: &Path,
    ) -> Result<AdapterResult, AdapterError> {
        let mut warnings = Vec::new();
        let mut servers = Vec::new();
        let mut source_info = Vec::new();

        for entry in entries {
            let transport = match entry.transport_type.as_deref() {
                Some(t) => t.to_string(),
                None => {
                    if entry.url.is_some() {
                        "sse".to_string()
                    } else {
                        "stdio".to_string()
                    }
                }
            };

            let auth = infer_auth_from_env(&entry.env);
            let tools =
                infer_tools_from_command(&entry.command, &entry.args, &mut warnings, &entry.name);

            // Check for Continue.dev secret templates
            for value in entry.env.values() {
                if value.starts_with("${{") {
                    warnings.push(format!(
                        "Server '{}' uses Continue.dev secret references (${{{{ secrets.* }}}}). \
                         Actual values are injected at runtime.",
                        entry.name
                    ));
                    break;
                }
            }

            servers.push(McpServer {
                name: entry.name.clone(),
                description: String::new(),
                tools,
                auth,
                transport,
                url: entry.url,
                command: entry.command,
                args: entry.args,
                env: entry.env,
            });

            source_info.push(SourceInfo::file(path));
        }

        // Sort by name
        let mut paired: Vec<_> = servers.into_iter().zip(source_info).collect();
        paired.sort_by(|(a, _), (b, _)| a.name.cmp(&b.name));
        let (servers, source_info): (Vec<_>, Vec<_>) = paired.into_iter().unzip();

        let server_pointers: BTreeMap<String, String> = servers
            .iter()
            .map(|s| (s.name.clone(), String::new()))
            .collect();

        Ok(AdapterResult {
            config: McpConfig { servers },
            adapter_name: self.name(),
            warnings,
            source_info,
            location_map: None, // YAML — no JSON location map
            server_pointers,
        })
    }
}

fn has_config_files(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries.filter_map(|e| e.ok()).any(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| matches!(ext, "json" | "yaml" | "yml"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_yaml_config() {
        let yaml = r#"
mcpServers:
  - name: sqlite-server
    type: stdio
    command: npx
    args:
      - mcp-sqlite
      - /tmp/test.db
    env:
      DB_PATH: /tmp/test.db
  - name: github-server
    command: npx
    args:
      - "@modelcontextprotocol/server-github"
"#;
        let config: ContinueConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mcp_servers.len(), 2);
        assert_eq!(config.mcp_servers[0].name, "sqlite-server");
        assert_eq!(
            config.mcp_servers[0].transport_type,
            Some("stdio".to_string())
        );
        assert_eq!(config.mcp_servers[1].name, "github-server");
    }

    #[test]
    fn parse_json_config() {
        let json = r#"{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}}}"#;
        let raw: ContinueJsonFile = serde_json::from_str(json).unwrap();
        assert_eq!(raw.mcp_servers.len(), 1);
        assert!(raw.mcp_servers.contains_key("fs"));
    }

    #[test]
    fn detect_continue_directory() {
        let dir = tempfile::tempdir().unwrap();
        let mcp_dir = dir.path().join(CONTINUE_DIR).join(MCP_SERVERS_DIR);
        std::fs::create_dir_all(&mcp_dir).unwrap();
        std::fs::write(mcp_dir.join("test.yaml"), "mcpServers: []").unwrap();

        let adapter = ContinueDevAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn detect_continue_config_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let continue_dir = dir.path().join(CONTINUE_DIR);
        std::fs::create_dir_all(&continue_dir).unwrap();
        std::fs::write(
            continue_dir.join("config.yaml"),
            "mcpServers:\n  - name: test\n    command: echo\n",
        )
        .unwrap();

        let adapter = ContinueDevAdapter;
        assert!(adapter.detect(dir.path()));
    }

    #[test]
    fn detect_rejects_non_continue() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("random.json"), "{}").unwrap();

        let adapter = ContinueDevAdapter;
        assert!(!adapter.detect(dir.path()));
    }

    #[test]
    fn load_multi_file_merge() {
        let dir = tempfile::tempdir().unwrap();
        let mcp_dir = dir.path().join(CONTINUE_DIR).join(MCP_SERVERS_DIR);
        std::fs::create_dir_all(&mcp_dir).unwrap();

        std::fs::write(
            mcp_dir.join("a.yaml"),
            "mcpServers:\n  - name: alpha\n    command: echo\n    args: [hello]\n",
        )
        .unwrap();
        std::fs::write(
            mcp_dir.join("b.json"),
            r#"{"mcpServers": {"beta": {"command": "node", "args": ["server.js"]}}}"#,
        )
        .unwrap();

        let adapter = ContinueDevAdapter;
        let result = adapter.load(dir.path()).unwrap();
        assert_eq!(result.config.servers.len(), 2);
        let names: Vec<&str> = result
            .config
            .servers
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
    }

    #[test]
    fn load_multi_file_duplicate_warns() {
        let dir = tempfile::tempdir().unwrap();
        let mcp_dir = dir.path().join(CONTINUE_DIR).join(MCP_SERVERS_DIR);
        std::fs::create_dir_all(&mcp_dir).unwrap();

        std::fs::write(
            mcp_dir.join("a.yaml"),
            "mcpServers:\n  - name: dup-server\n    command: echo\n    args: [first]\n",
        )
        .unwrap();
        std::fs::write(
            mcp_dir.join("b.yaml"),
            "mcpServers:\n  - name: dup-server\n    command: echo\n    args: [second]\n",
        )
        .unwrap();

        let adapter = ContinueDevAdapter;
        let result = adapter.load(dir.path()).unwrap();
        assert_eq!(result.config.servers.len(), 1);
        assert_eq!(result.config.servers[0].args, vec!["second"]);
        assert!(result.warnings.iter().any(|w| w.contains("redefined")));
    }

    #[test]
    fn secrets_template_preserved() {
        let yaml = r#"
mcpServers:
  - name: test-server
    command: npx
    args:
      - some-server
    env:
      API_KEY: ${{ secrets.MY_API_KEY }}
"#;
        let config: ContinueConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            config.mcp_servers[0].env.get("API_KEY").unwrap(),
            "${{ secrets.MY_API_KEY }}"
        );
    }

    #[test]
    fn yaml_has_no_location_map() {
        let dir = tempfile::tempdir().unwrap();
        let continue_dir = dir.path().join(CONTINUE_DIR);
        std::fs::create_dir_all(&continue_dir).unwrap();
        std::fs::write(
            continue_dir.join("config.yaml"),
            "mcpServers:\n  - name: test\n    command: echo\n    args: []\n",
        )
        .unwrap();

        let adapter = ContinueDevAdapter;
        let result = adapter.load(dir.path()).unwrap();
        assert!(result.location_map.is_none());
    }
}
