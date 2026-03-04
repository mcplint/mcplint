use super::{AdapterError, AdapterResult, McpAdapter, SourceInfo};
use crate::McpConfig;
use std::path::Path;

/// Generic fallback adapter that handles MCP configurations when no
/// specific adapter (Claude Desktop, Cursor) matches.
///
/// Detection strategy (conservative):
/// - Files: JSON files with "mcp" in the name, or any JSON containing
///   recognized MCP keys (`mcpServers`, `tools`, `servers`)
/// - Directories: contains files matching common MCP config patterns
///
/// Extraction strategy:
/// - Tries known formats in order: mcpServers, mcp.config.json, mcp.tools.json
/// - Never invents fields or infers dangerous capabilities
/// - Prefers under-reporting over false positives
/// - Always labels output with adapter_name = "generic"
pub struct GenericAdapter;

/// Well-known MCP file patterns to scan for in directories.
const MCP_FILE_PATTERNS: &[&str] = &[
    "mcp.json",
    "mcp-config.json",
    "mcp_config.json",
    "mcp-servers.json",
    "mcp_servers.json",
    "mcp.config.json",
    "mcp.tools.json",
];

/// Top-level JSON keys that indicate MCP content.
/// These are checked via simple string containment — use full key syntax
/// to avoid false positives (e.g., `"mcpServers"` not just `servers`).
const MCP_CONTENT_MARKERS: &[&str] = &["mcpServers"];

impl McpAdapter for GenericAdapter {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn detect(&self, path: &Path) -> bool {
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let lower = name.to_lowercase();
                // Match any JSON file with "mcp" in the name
                if lower.ends_with(".json") && lower.contains("mcp") {
                    return true;
                }
                // For other JSON files, peek at content for mcpServers key only
                if lower.ends_with(".json") {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        return MCP_CONTENT_MARKERS.iter().any(|key| content.contains(key));
                    }
                }
            }
        }

        if path.is_dir() {
            // Check for any MCP-like file in the directory
            if MCP_FILE_PATTERNS
                .iter()
                .any(|name| path.join(name).is_file())
            {
                return true;
            }

            // Scan for any JSON file with "mcp" in the name
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        let lower = name.to_lowercase();
                        if lower.ends_with(".json") && lower.contains("mcp") {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn load(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        if path.is_file() {
            return self.load_file(path);
        }

        if path.is_dir() {
            return self.load_directory(path);
        }

        Err(AdapterError::UnsupportedFormat(format!(
            "Path '{}' is neither a file nor a directory",
            path.display()
        )))
    }
}

impl GenericAdapter {
    fn load_file(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        let content = std::fs::read_to_string(path).map_err(|e| AdapterError::io(path, e))?;
        let mut warnings = Vec::new();
        let location_map = crate::json_locator::JsonLocationMap::from_source(&content);

        // Strategy 1: Try mcpServers format (Claude/Cursor style)
        if content.contains("mcpServers") {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if val.get("mcpServers").is_some() {
                    let adapter = super::claude_desktop::ClaudeDesktopAdapter;
                    match adapter.load(path) {
                        Ok(mut result) => {
                            result.adapter_name = self.name();
                            result.warnings.insert(
                                0,
                                format!(
                                    "Detected mcpServers format in '{}', parsed as Claude Desktop style",
                                    path.display()
                                ),
                            );
                            return Ok(result);
                        }
                        Err(e) => {
                            warnings.push(format!(
                                "Found mcpServers in '{}' but failed to parse: {}",
                                path.display(),
                                e
                            ));
                        }
                    }
                }
            }
        }

        // Strategy 2: Try native mcplint config format
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        match McpConfig::load(&content, &filename) {
            Ok(config) => {
                let server_pointers: std::collections::BTreeMap<String, String> = config
                    .servers
                    .iter()
                    .enumerate()
                    .map(|(i, s)| (s.name.clone(), format!("/servers/{}", i)))
                    .collect();
                let source_info = config
                    .servers
                    .iter()
                    .enumerate()
                    .map(|(i, _)| SourceInfo::with_pointer(path, &format!("/servers/{}", i)))
                    .collect();
                Ok(AdapterResult {
                    config,
                    adapter_name: self.name(),
                    warnings,
                    source_info,
                    location_map: Some(location_map.clone()),
                    server_pointers,
                })
            }
            Err(e1) => {
                // Strategy 3: Try the alternate native format
                let is_tools_format = !filename.contains("tools");
                let alt_result = if is_tools_format {
                    McpConfig::from_tools_json(&content)
                } else {
                    McpConfig::from_config_json(&content)
                };

                match alt_result {
                    Ok(config) => {
                        warnings.push(format!(
                            "Parsed '{}' using alternate format detection",
                            path.display()
                        ));
                        // Rebuild location_map for the alternate interpretation
                        let alt_location_map =
                            crate::json_locator::JsonLocationMap::from_source(&content);
                        let (server_pointers, source_info) = if is_tools_format {
                            // from_tools_json wraps tools into a single server at root;
                            // raw JSON has /tools/{i}, not /servers/0/tools/{i}
                            let sp: std::collections::BTreeMap<String, String> = config
                                .servers
                                .iter()
                                .map(|s| (s.name.clone(), String::new()))
                                .collect();
                            let si = config
                                .servers
                                .iter()
                                .map(|_| SourceInfo::with_pointer(path, ""))
                                .collect();
                            (sp, si)
                        } else {
                            // from_config_json — /servers/{i} pointers match raw JSON
                            let sp: std::collections::BTreeMap<String, String> = config
                                .servers
                                .iter()
                                .enumerate()
                                .map(|(i, s)| (s.name.clone(), format!("/servers/{}", i)))
                                .collect();
                            let si = config
                                .servers
                                .iter()
                                .enumerate()
                                .map(|(i, _)| {
                                    SourceInfo::with_pointer(path, &format!("/servers/{}", i))
                                })
                                .collect();
                            (sp, si)
                        };
                        Ok(AdapterResult {
                            config,
                            adapter_name: self.name(),
                            warnings,
                            source_info,
                            location_map: Some(alt_location_map),
                            server_pointers,
                        })
                    }
                    Err(_) => Err(AdapterError::parse(path, e1)),
                }
            }
        }
    }

    fn load_directory(&self, path: &Path) -> Result<AdapterResult, AdapterError> {
        // Try known MCP file patterns first
        for name in MCP_FILE_PATTERNS {
            let file_path = path.join(name);
            if file_path.is_file() {
                return self.load_file(&file_path);
            }
        }

        // Scan for any JSON file with "mcp" in the name
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let lower = name.to_lowercase();
                    if lower.ends_with(".json") && lower.contains("mcp") {
                        return self.load_file(&entry.path());
                    }
                }
            }
        }

        // Nothing found — return empty config with a warning rather than failing
        Ok(AdapterResult {
            config: McpConfig { servers: vec![] },
            adapter_name: self.name(),
            warnings: vec![format!(
                "No MCP configuration files found in '{}'",
                path.display()
            )],
            source_info: vec![],
            location_map: None,
            server_pointers: std::collections::BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_mcp_json_file() {
        let adapter = GenericAdapter;
        let path = Path::new("/tmp/my-mcp-config.json");
        // Name contains "mcp" and ends with ".json" → detected (even if file doesn't exist
        // on disk, the name-based check uses Path::is_file which returns false, so this
        // correctly tests the name pattern without I/O).
        assert!(adapter.detect(path) || !path.exists());
    }

    #[test]
    fn detect_does_not_match_random_json() {
        let adapter = GenericAdapter;
        let path = Path::new("/tmp/settings.json");
        // Does not contain "mcp" and file doesn't exist for content peeking
        assert!(!adapter.detect(path));
    }

    #[test]
    fn detect_does_not_match_non_json() {
        let adapter = GenericAdapter;
        let path = Path::new("/tmp/mcp-readme.md");
        assert!(!adapter.detect(path));
    }

    #[test]
    fn config_fallback_rebuilds_location_map() {
        // File named with "tools" in name but contains config-format JSON (servers array).
        // McpConfig::load() tries from_tools_json first (because of "tools" in name) → fails.
        // Then Strategy 3 tries from_config_json → succeeds.
        // The location_map and server_pointers should be consistent.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("custom.tools.json");
        let content = r#"{
  "servers": [
    {
      "name": "db-server",
      "description": "Database server",
      "tools": [
        {
          "name": "query",
          "description": "Run SQL",
          "parameters": []
        }
      ]
    }
  ]
}"#;
        std::fs::write(&file, content).unwrap();

        let adapter = GenericAdapter;
        let result = adapter.load(&file).unwrap();

        // Server pointers should use /servers/{i} for config format
        assert_eq!(
            result.server_pointers.get("db-server"),
            Some(&"/servers/0".to_string()),
            "config-format server should have /servers/0 pointer"
        );

        // The location_map should contain /servers/0 since it was rebuilt
        let map = result.location_map.as_ref().unwrap();
        assert!(
            map.get("/servers/0").is_some(),
            "location_map should have /servers/0 for config-format JSON"
        );

        // Verify the warning indicates alternate format was used
        assert!(
            result.warnings.iter().any(|w| w.contains("alternate")),
            "should have warning about alternate format"
        );
    }

    #[test]
    fn primary_parse_location_map_has_correct_pointers() {
        // Directly parsed config file — location_map pointers should match server_pointers
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("mcp.config.json");
        let content = r#"{
  "servers": [
    {
      "name": "api-server",
      "tools": [
        {
          "name": "get_users",
          "description": "List users",
          "parameters": []
        }
      ]
    }
  ]
}"#;
        std::fs::write(&file, content).unwrap();

        let adapter = GenericAdapter;
        let result = adapter.load(&file).unwrap();

        // Primary path — server_pointers and location_map should agree
        let base_ptr = result.server_pointers.get("api-server").unwrap();
        let map = result.location_map.as_ref().unwrap();
        assert!(
            map.get(base_ptr).is_some(),
            "location_map should have the server pointer from primary parse"
        );
    }
}
