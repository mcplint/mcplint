use crate::finding::Finding;
use crate::json_locator::JsonLocationMap;
use crate::mcp_schema::McpConfig;
use std::collections::BTreeMap;

/// Context passed to each rule during a scan.
pub struct ScanContext {
    /// The parsed MCP configuration being analyzed.
    pub config: McpConfig,
    /// Source file path (for evidence reporting).
    pub source_path: String,
    /// JSON pointer → source region mapping for precise evidence locations.
    /// Built from the raw JSON source at load time.
    pub location_map: Option<JsonLocationMap>,
    /// Maps server name → JSON pointer base in the raw source file.
    /// For Claude Desktop: "db-server" → "/mcpServers/db-server"
    /// For native format: "db-server" → "/servers/0"
    pub server_pointers: BTreeMap<String, String>,
}

impl ScanContext {
    pub fn new(config: McpConfig, source_path: String) -> Self {
        Self {
            config,
            source_path,
            location_map: None,
            server_pointers: BTreeMap::new(),
        }
    }

    /// Create a ScanContext with a pre-built location map and server pointer mappings.
    pub fn with_location_map(
        config: McpConfig,
        source_path: String,
        location_map: JsonLocationMap,
        server_pointers: BTreeMap<String, String>,
    ) -> Self {
        Self {
            config,
            source_path,
            location_map: Some(location_map),
            server_pointers,
        }
    }

    /// Look up the source region for a JSON pointer.
    /// Returns None if no location map is available or the pointer is not found.
    pub fn region_for(&self, pointer: &str) -> Option<&crate::json_locator::Region> {
        self.location_map.as_ref()?.get(pointer)
    }

    /// Build a JSON pointer for a server-relative path.
    /// E.g., server_pointer("db-server", "command") → "/mcpServers/db-server/command"
    pub fn server_pointer(&self, server_name: &str, suffix: &str) -> Option<String> {
        let base = self.server_pointers.get(server_name)?;
        if suffix.is_empty() {
            Some(base.clone())
        } else {
            Some(format!("{}/{}", base, suffix))
        }
    }
}

/// Aggregated scan results.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub source_path: String,
    pub findings: Vec<Finding>,
}

impl ScanResult {
    pub fn has_findings_at_or_above(&self, severity: crate::finding::Severity) -> bool {
        self.findings.iter().any(|f| f.meets_threshold(severity))
    }
}
