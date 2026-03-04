//! Live MCP server scanner — connects to a running MCP server and produces
//! a canonical `McpConfig` for analysis by the existing rule engine.
//!
//! Supports three transport modes:
//! - **stdio**: `stdio:<command>:<args...>` — spawns a subprocess
//! - **http/https**: `http[s]://...` — connects via Streamable HTTP
//! - **sse**: `sse+http[s]://...` — connects via SSE (legacy)

use mcplint_core::adapters::{AdapterResult, SourceInfo};
use mcplint_core::mcp_schema::{
    McpConfig, McpServer, ToolDefinition, ToolParameter, ToolProvenance,
};
use std::collections::BTreeMap;
use std::path::Path;

/// Errors from live server scanning.
#[derive(Debug)]
pub enum LiveScanError {
    /// Failed to parse the server target string.
    InvalidTarget(String),
    /// Transport/connection error.
    Connection(String),
    /// MCP protocol error (e.g., tools/list failed).
    Protocol(String),
}

impl std::fmt::Display for LiveScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LiveScanError::InvalidTarget(msg) => write!(f, "invalid server target: {}", msg),
            LiveScanError::Connection(msg) => write!(f, "connection error: {}", msg),
            LiveScanError::Protocol(msg) => write!(f, "protocol error: {}", msg),
        }
    }
}

impl std::error::Error for LiveScanError {}

/// Scan a live MCP server and produce an `AdapterResult` compatible with
/// the existing rule engine pipeline.
///
/// Target formats:
/// - `stdio:command:arg1:arg2` — spawn subprocess with stdio transport
/// - `http://host/path` or `https://host/path` — Streamable HTTP transport
pub async fn scan_live_server(target: &str) -> Result<AdapterResult, LiveScanError> {
    let tools = if target.starts_with("stdio:") {
        scan_stdio(target).await?
    } else if target.starts_with("http://") || target.starts_with("https://") {
        scan_http(target).await?
    } else {
        return Err(LiveScanError::InvalidTarget(format!(
            "Unrecognized target format: '{}'. \
             Use 'stdio:<command>:<args...>' or 'http[s]://...'",
            target
        )));
    };

    let server_name = derive_server_name(target);
    let mcp_tools = convert_tools(&tools);

    let server = McpServer {
        name: server_name.clone(),
        description: String::new(),
        tools: mcp_tools,
        transport: if target.starts_with("stdio:") {
            "stdio".to_string()
        } else {
            "http".to_string()
        },
        auth: Default::default(),
        url: if target.starts_with("http") {
            Some(target.to_string())
        } else {
            None
        },
        command: if target.starts_with("stdio:") {
            let parts: Vec<&str> = target.splitn(3, ':').collect();
            parts.get(1).map(|s| s.to_string())
        } else {
            None
        },
        args: if target.starts_with("stdio:") {
            let parts: Vec<&str> = target.splitn(3, ':').collect();
            parts
                .get(2)
                .map(|rest| rest.split(':').map(|s| s.to_string()).collect())
                .unwrap_or_default()
        } else {
            vec![]
        },
        env: BTreeMap::new(),
    };

    let config = McpConfig {
        servers: vec![server],
    };

    Ok(AdapterResult {
        config,
        adapter_name: "live-server",
        warnings: vec![],
        source_info: vec![SourceInfo::file(Path::new(target))],
        location_map: None,
        server_pointers: BTreeMap::new(),
    })
}

/// Connect to a stdio-based MCP server.
async fn scan_stdio(target: &str) -> Result<Vec<rmcp::model::Tool>, LiveScanError> {
    use rmcp::transport::TokioChildProcess;
    use rmcp::ServiceExt;

    // Parse "stdio:command:arg1:arg2:..."
    let parts: Vec<&str> = target.splitn(3, ':').collect();
    if parts.len() < 2 || parts[1].is_empty() {
        return Err(LiveScanError::InvalidTarget(
            "stdio target must be 'stdio:<command>[:<args...>]'".to_string(),
        ));
    }

    let command = parts[1];
    let args: Vec<&str> = if parts.len() > 2 {
        parts[2].split(':').collect()
    } else {
        vec![]
    };

    let mut cmd = tokio::process::Command::new(command);
    for arg in &args {
        cmd.arg(arg);
    }

    let transport = TokioChildProcess::new(cmd)
        .map_err(|e| LiveScanError::Connection(format!("Failed to spawn '{}': {}", command, e)))?;

    let client = ().serve(transport).await.map_err(|e| {
        LiveScanError::Connection(format!("Failed to initialize MCP session: {}", e))
    })?;

    let tools = client
        .peer()
        .list_all_tools()
        .await
        .map_err(|e| LiveScanError::Protocol(format!("Failed to list tools: {}", e)))?;

    // Gracefully shut down
    client.cancel().await.ok();

    Ok(tools)
}

/// Connect to an HTTP/SSE-based MCP server.
async fn scan_http(url: &str) -> Result<Vec<rmcp::model::Tool>, LiveScanError> {
    use rmcp::transport::StreamableHttpClientTransport;
    use rmcp::ServiceExt;

    let transport = StreamableHttpClientTransport::from_uri(url);

    let client = ()
        .serve(transport)
        .await
        .map_err(|e| LiveScanError::Connection(format!("Failed to connect to '{}': {}", url, e)))?;

    let tools = client
        .peer()
        .list_all_tools()
        .await
        .map_err(|e| LiveScanError::Protocol(format!("Failed to list tools: {}", e)))?;

    client.cancel().await.ok();

    Ok(tools)
}

/// Convert rmcp `Tool` structs to mcplint's canonical `ToolDefinition`.
fn convert_tools(tools: &[rmcp::model::Tool]) -> Vec<ToolDefinition> {
    let mut result: Vec<ToolDefinition> = tools
        .iter()
        .map(|t| {
            let params = extract_parameters(&t.input_schema);

            ToolDefinition {
                name: t.name.to_string(),
                description: t.description.as_deref().unwrap_or_default().to_string(),
                parameters: params,
                tags: vec![],
                provenance: ToolProvenance::Declared,
            }
        })
        .collect();

    // Sort for deterministic output
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

/// Extract parameters from a JSON Schema `input_schema` object.
///
/// The MCP tool input_schema is a JSON Schema object with `properties` and
/// optionally `required`. We flatten it into mcplint's `ToolParameter` list.
fn extract_parameters(schema: &serde_json::Map<String, serde_json::Value>) -> Vec<ToolParameter> {
    let properties = match schema.get("properties") {
        Some(serde_json::Value::Object(props)) => props,
        _ => return vec![],
    };

    let required_set: std::collections::HashSet<&str> = schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let mut params: Vec<ToolParameter> = properties
        .iter()
        .map(|(name, prop)| {
            let param_type = prop
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("string")
                .to_string();

            let description = prop
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let mut constraints = BTreeMap::new();

            // Carry forward useful schema constraints
            for key in &[
                "enum",
                "pattern",
                "minLength",
                "maxLength",
                "minimum",
                "maximum",
                "items",
                "format",
            ] {
                if let Some(val) = prop.get(*key) {
                    constraints.insert(key.to_string(), val.clone());
                }
            }

            ToolParameter {
                name: name.clone(),
                param_type,
                description,
                required: required_set.contains(name.as_str()),
                constraints,
            }
        })
        .collect();

    // Sort for deterministic output
    params.sort_by(|a, b| a.name.cmp(&b.name));
    params
}

/// Derive a human-readable server name from the target string.
fn derive_server_name(target: &str) -> String {
    if target.starts_with("stdio:") {
        let parts: Vec<&str> = target.splitn(3, ':').collect();
        let cmd = parts.get(1).unwrap_or(&"unknown");
        // Use the last path component of the command
        let base = cmd.rsplit('/').next().unwrap_or(cmd);
        base.to_string()
    } else {
        // HTTP URL — use host
        target
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("remote-server")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_server_name_stdio() {
        assert_eq!(derive_server_name("stdio:npx:mcp-server"), "npx");
        assert_eq!(
            derive_server_name("stdio:/usr/local/bin/my-server"),
            "my-server"
        );
        assert_eq!(derive_server_name("stdio:python3:server.py"), "python3");
    }

    #[test]
    fn test_derive_server_name_http() {
        assert_eq!(
            derive_server_name("https://api.example.com/mcp/"),
            "api.example.com"
        );
        assert_eq!(
            derive_server_name("http://localhost:8080/mcp"),
            "localhost:8080"
        );
    }

    #[test]
    fn test_extract_parameters_empty() {
        let schema = serde_json::Map::new();
        let params = extract_parameters(&schema);
        assert!(params.is_empty());
    }

    #[test]
    fn test_extract_parameters_with_properties() {
        let schema: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
            r#"{
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "SQL query to execute"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max rows",
                        "maximum": 1000
                    }
                },
                "required": ["query"]
            }"#,
        )
        .unwrap();

        let params = extract_parameters(&schema);
        assert_eq!(params.len(), 2);

        // Sorted: limit, query
        assert_eq!(params[0].name, "limit");
        assert_eq!(params[0].param_type, "integer");
        assert!(!params[0].required);
        assert!(!params[0].constraints.is_empty());

        assert_eq!(params[1].name, "query");
        assert_eq!(params[1].param_type, "string");
        assert!(params[1].required);
    }

    #[test]
    fn test_convert_tools_deterministic() {
        use rmcp::model::Tool;
        use std::borrow::Cow;
        use std::sync::Arc;

        let schema_b: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"type": "object", "properties": {}}"#).unwrap();
        let schema_a = schema_b.clone();

        let tools = vec![
            Tool {
                name: Cow::Borrowed("z_tool"),
                title: None,
                description: Some(Cow::Borrowed("Second tool")),
                input_schema: Arc::new(schema_b),
                output_schema: None,
                annotations: None,
                execution: None,
                icons: None,
                meta: None,
            },
            Tool {
                name: Cow::Borrowed("a_tool"),
                title: None,
                description: Some(Cow::Borrowed("First tool")),
                input_schema: Arc::new(schema_a),
                output_schema: None,
                annotations: None,
                execution: None,
                icons: None,
                meta: None,
            },
        ];

        let result = convert_tools(&tools);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "a_tool"); // sorted
        assert_eq!(result[1].name, "z_tool");
    }

    #[test]
    fn test_invalid_target() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scan_live_server("ftp://example.com"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, LiveScanError::InvalidTarget(_)));
    }

    #[test]
    fn test_stdio_empty_command() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scan_live_server("stdio:"));
        assert!(result.is_err());
    }
}
