pub mod claude_desktop;
pub mod cline;
pub mod continue_dev;
pub mod cursor;
pub mod generic;
pub mod vscode;
pub mod windsurf;
pub mod zed;

use crate::McpConfig;
use std::path::Path;

/// Metadata about where a piece of data was extracted from.
#[derive(Debug, Clone)]
pub struct SourceInfo {
    /// Filesystem path to the source file.
    pub file_path: String,
    /// Optional JSON pointer within the file (e.g., "/mcpServers/filesystem").
    pub json_pointer: Option<String>,
}

impl SourceInfo {
    pub fn file(path: &Path) -> Self {
        Self {
            file_path: path.display().to_string(),
            json_pointer: None,
        }
    }

    pub fn with_pointer(path: &Path, pointer: &str) -> Self {
        Self {
            file_path: path.display().to_string(),
            json_pointer: Some(pointer.to_string()),
        }
    }
}

/// Result of adapter loading, including metadata about the extraction.
#[derive(Debug, Clone)]
pub struct AdapterResult {
    /// The canonical MCP configuration extracted by the adapter.
    pub config: McpConfig,
    /// Which adapter produced this result.
    pub adapter_name: &'static str,
    /// Warnings generated during extraction (e.g., missing fields).
    pub warnings: Vec<String>,
    /// Source provenance per server (parallel to config.servers by index).
    pub source_info: Vec<SourceInfo>,
    /// JSON pointer → source region mapping for precise evidence locations.
    pub location_map: Option<crate::json_locator::JsonLocationMap>,
    /// Maps server name → JSON pointer base in the raw source file.
    pub server_pointers: std::collections::BTreeMap<String, String>,
}

/// Trait for MCP configuration adapters.
///
/// Adapters extract tool/server definitions from various real-world MCP
/// configuration formats and convert them into the canonical `McpConfig`
/// representation used by mcplint's analysis rules.
pub trait McpAdapter {
    /// Human-readable adapter name.
    fn name(&self) -> &'static str;

    /// Returns true if this adapter can handle the given path.
    /// For files, checks filename/content patterns.
    /// For directories, checks for expected files within.
    fn detect(&self, path: &Path) -> bool;

    /// Load and convert the configuration at `path` into canonical form.
    /// Prefers partial extraction over failure — missing fields are recorded
    /// as warnings rather than errors.
    fn load(&self, path: &Path) -> Result<AdapterResult, AdapterError>;
}

/// Errors that can occur during adapter loading.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("JSON parse error in {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
}

impl AdapterError {
    pub fn io(path: &Path, source: std::io::Error) -> Self {
        AdapterError::Io {
            path: path.display().to_string(),
            source,
        }
    }

    pub fn parse(path: &Path, source: serde_json::Error) -> Self {
        AdapterError::Parse {
            path: path.display().to_string(),
            source,
        }
    }
}

/// Auto-detect the appropriate adapter for a given path and load the config.
///
/// Tries adapters in priority order:
/// 1. Claude Desktop (most specific filename)
/// 2. Cursor (specific path pattern)
/// 3. VS Code (specific path pattern)
/// 4. Cline (specific path pattern)
/// 5. Windsurf (specific path pattern)
/// 6. Continue.dev (specific directory pattern)
/// 7. Zed (settings.json with context_servers)
/// 8. Generic heuristic (fallback)
///
/// Returns the first successful match.
pub fn auto_load(path: &Path) -> Result<AdapterResult, AdapterError> {
    let adapters: Vec<Box<dyn McpAdapter>> = vec![
        Box::new(claude_desktop::ClaudeDesktopAdapter),
        Box::new(cursor::CursorAdapter),
        Box::new(vscode::VsCodeAdapter),
        Box::new(cline::ClineAdapter),
        Box::new(windsurf::WindsurfAdapter),
        Box::new(continue_dev::ContinueDevAdapter),
        Box::new(zed::ZedAdapter),
        Box::new(generic::GenericAdapter),
    ];

    // Try specific adapters first
    for adapter in &adapters {
        if adapter.detect(path) {
            return adapter.load(path);
        }
    }

    // Fallback: try native format loading
    load_native(path)
}

/// Auto-detect the appropriate adapter for raw content and load the config.
///
/// Used for --stdin support where no file path is available.
/// Writes content to a temporary file and delegates to `auto_load`.
pub fn auto_load_content(
    content: &str,
    filename_hint: &str,
) -> Result<AdapterResult, AdapterError> {
    // Write to a uniquely-named temp directory so that concurrent callers
    // (e.g. parallel tests) never collide on the same path.
    let tmp_dir = tempfile::tempdir().map_err(|e| AdapterError::Io {
        path: std::env::temp_dir().display().to_string(),
        source: e,
    })?;
    let tmp_path = tmp_dir.path().join(filename_hint);
    std::fs::write(&tmp_path, content).map_err(|e| AdapterError::io(&tmp_path, e))?;

    let result = auto_load(&tmp_path);
    // tmp_dir is dropped here, automatically removing the directory and file.

    // Replace the temp path with "<stdin>" in the result
    result.map(|mut r| {
        r.source_info.iter_mut().for_each(|si| {
            si.file_path = "<stdin>".to_string();
        });
        r
    })
}

/// Load a native mcplint format file (mcp.tools.json / mcp.config.json).
fn load_native(path: &Path) -> Result<AdapterResult, AdapterError> {
    let content = std::fs::read_to_string(path).map_err(|e| AdapterError::io(path, e))?;
    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let is_tools_file = filename.contains("tools");

    let config = McpConfig::load(&content, &filename).map_err(|e| AdapterError::parse(path, e))?;

    let location_map = crate::json_locator::JsonLocationMap::from_source(&content);

    // Build pointers that match the actual JSON structure:
    // - mcp.tools.json: flat file with /tools/0, /tools/1, ...
    //   Server pointer base is "" (root), so tool paths become /tools/{i}
    // - mcp.config.json: /servers/0, /servers/1, ...
    //   Server pointer base is /servers/{i}, tool paths become /servers/{i}/tools/{j}
    let (server_pointers, source_info) = if is_tools_file {
        let mut ptrs = std::collections::BTreeMap::new();
        // Single server; pointer base is root so rules build "/tools/{i}" etc.
        if let Some(server) = config.servers.first() {
            ptrs.insert(server.name.clone(), String::new());
        }
        let si = config
            .servers
            .iter()
            .map(|_| SourceInfo::file(path))
            .collect();
        (ptrs, si)
    } else {
        let ptrs: std::collections::BTreeMap<String, String> = config
            .servers
            .iter()
            .enumerate()
            .map(|(i, s)| (s.name.clone(), format!("/servers/{}", i)))
            .collect();
        let si = config
            .servers
            .iter()
            .enumerate()
            .map(|(i, _)| SourceInfo::with_pointer(path, &format!("/servers/{}", i)))
            .collect();
        (ptrs, si)
    };

    Ok(AdapterResult {
        config,
        adapter_name: "native",
        warnings: vec![],
        source_info,
        location_map: Some(location_map),
        server_pointers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/native")
    }

    #[test]
    fn native_tools_json_pointers_resolve() {
        let path = fixtures_dir().join("sample.tools.json");
        let result = load_native(&path).expect("should load tools.json");

        assert_eq!(result.adapter_name, "native");
        assert_eq!(result.config.servers.len(), 1);
        assert_eq!(result.config.servers[0].name, "db-tools");

        // Server pointer base for tools.json is "" (root)
        let base = result
            .server_pointers
            .get("db-tools")
            .expect("pointer exists");
        assert_eq!(base, "", "tools.json server base should be root");

        // Build tool pointer the same way rules do: base + "/tools/{i}"
        let tool0_ptr = format!("{}/tools/0", base);
        let map = result.location_map.as_ref().unwrap();
        let region = map.get(&tool0_ptr).expect("tool 0 pointer should resolve");
        // run_query object starts on line 4
        assert_eq!(region.start_line, 4);

        let tool1_ptr = format!("{}/tools/1", base);
        let region1 = map.get(&tool1_ptr).expect("tool 1 pointer should resolve");
        assert_eq!(region1.start_line, 16);

        // Parameter pointer
        let param_ptr = format!("{}/tools/0/parameters/0", base);
        let param_region = map.get(&param_ptr).expect("param pointer should resolve");
        assert_eq!(param_region.start_line, 8);
    }

    #[test]
    fn native_config_json_pointers_resolve() {
        let path = fixtures_dir().join("sample.config.json");
        let result = load_native(&path).expect("should load config.json");

        assert_eq!(result.adapter_name, "native");
        assert_eq!(result.config.servers.len(), 2);

        // Server pointer bases for config.json are /servers/{i}
        let base0 = result
            .server_pointers
            .get("file-server")
            .expect("pointer exists");
        assert_eq!(base0, "/servers/0");

        let base1 = result
            .server_pointers
            .get("exec-server")
            .expect("pointer exists");
        assert_eq!(base1, "/servers/1");

        let map = result.location_map.as_ref().unwrap();

        // Verify server-level pointers resolve
        let s0_region = map.get("/servers/0").expect("server 0 should resolve");
        assert_eq!(s0_region.start_line, 3);

        let s1_region = map.get("/servers/1").expect("server 1 should resolve");
        assert_eq!(s1_region.start_line, 21);

        // Verify tool-level pointers resolve
        let tool_ptr = format!("{}/tools/0", base0);
        let tool_region = map.get(&tool_ptr).expect("tool pointer should resolve");
        assert_eq!(tool_region.start_line, 6);

        // Verify parameter pointer
        let param_ptr = format!("{}/tools/0/parameters/0", base1);
        let param_region = map.get(&param_ptr).expect("param pointer should resolve");
        assert_eq!(param_region.start_line, 28);
    }

    #[test]
    fn native_tools_json_source_info_has_no_bad_pointer() {
        let path = fixtures_dir().join("sample.tools.json");
        let result = load_native(&path).expect("should load");

        // Source info should not contain /servers/0 for tools.json
        for si in &result.source_info {
            if let Some(ref ptr) = si.json_pointer {
                assert!(
                    !ptr.contains("/servers/"),
                    "tools.json should not have /servers/ pointer, got: {}",
                    ptr
                );
            }
        }
    }

    #[test]
    fn native_config_json_source_info_has_server_pointers() {
        let path = fixtures_dir().join("sample.config.json");
        let result = load_native(&path).expect("should load");

        assert_eq!(result.source_info.len(), 2);
        assert_eq!(
            result.source_info[0].json_pointer.as_deref(),
            Some("/servers/0")
        );
        assert_eq!(
            result.source_info[1].json_pointer.as_deref(),
            Some("/servers/1")
        );
    }
}
