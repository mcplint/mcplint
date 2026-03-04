use mcplint_core::adapters;
use mcplint_core::{apply_policy, GuardConfig, ScanContext};
use mcplint_report::OutputFormat;
use mcplint_rules::default_registry;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{schemars, tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// --- Tool parameter structs ---

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScanParams {
    /// Absolute path to an MCP configuration file to scan.
    #[serde(default)]
    pub path: Option<String>,
    /// Raw MCP configuration JSON content to scan (use instead of path).
    #[serde(default)]
    pub content: Option<String>,
    /// Output format: text, json, markdown, or sarif (default: json).
    #[serde(default)]
    pub format: Option<String>,
    /// Minimum severity to include: low, medium, high, critical (default: low).
    #[serde(default)]
    pub min_severity: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExplainParams {
    /// Rule ID to explain (e.g., MG001, MG002).
    pub rule_id: String,
}

// --- Server ---

/// MCP server that exposes mcplint scanning as tools for AI agents.
#[derive(Debug, Clone)]
pub struct McplintServer {
    tool_router: ToolRouter<Self>,
}

impl McplintServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

impl Default for McplintServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl McplintServer {
    #[tool(
        name = "mcplint_scan",
        description = "Scan an MCP configuration file or raw JSON content for security vulnerabilities. Returns findings with severity levels, exploit scenarios, evidence, and remediation steps. Provide either 'path' (file path) or 'content' (raw JSON)."
    )]
    async fn scan(
        &self,
        Parameters(params): Parameters<ScanParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let registry = default_registry();
        let guard_config = GuardConfig::default();

        let result = match (params.path, params.content) {
            (Some(p), _) => {
                let pb = PathBuf::from(&p);
                adapters::auto_load(&pb).map_err(|e| {
                    ErrorData::new(
                        ErrorCode::INVALID_PARAMS,
                        format!("Failed to load config from {}: {}", p, e),
                        None,
                    )
                })?
            }
            (_, Some(c)) => adapters::auto_load_content(&c, "scan-input.json").map_err(|e| {
                ErrorData::new(
                    ErrorCode::INVALID_PARAMS,
                    format!("Failed to parse config content: {}", e),
                    None,
                )
            })?,
            (None, None) => {
                return Err(ErrorData::new(
                    ErrorCode::INVALID_PARAMS,
                    "Either 'path' or 'content' must be provided".to_string(),
                    None,
                ));
            }
        };

        let source = "mcp-scan".to_string();
        let ctx = if let Some(map) = result.location_map {
            ScanContext::with_location_map(result.config, source, map, result.server_pointers)
        } else {
            ScanContext::new(result.config, source)
        };

        let findings = registry.run_all(&ctx);
        let findings = apply_policy(&guard_config, findings);

        let findings = if let Some(ref min) = params.min_severity {
            let threshold = parse_severity(min);
            findings
                .into_iter()
                .filter(|f| f.meets_threshold(threshold))
                .collect()
        } else {
            findings
        };

        let fmt = match params.format.as_deref() {
            Some("text") => OutputFormat::Text,
            Some("markdown") | Some("md") => OutputFormat::Markdown,
            Some("sarif") => OutputFormat::Sarif,
            _ => OutputFormat::Json,
        };

        let output = if fmt == OutputFormat::Sarif {
            let rules_meta = rules_metadata(&registry);
            mcplint_report::render_sarif(
                &findings,
                "mcp-scan",
                env!("CARGO_PKG_VERSION"),
                &rules_meta,
            )
        } else {
            mcplint_report::render(&findings, "mcp-scan", fmt)
        };

        if findings.is_empty() {
            Ok(CallToolResult::success(vec![Content::text(
                "No security issues found. The MCP configuration looks clean.",
            )]))
        } else {
            let summary = format!(
                "Found {} security issue{}.",
                findings.len(),
                if findings.len() == 1 { "" } else { "s" }
            );
            Ok(CallToolResult::success(vec![
                Content::text(summary),
                Content::text(output),
            ]))
        }
    }

    #[tool(
        name = "mcplint_list_rules",
        description = "List all available mcplint security rules with their IDs, descriptions, categories, and CWE/OWASP mappings."
    )]
    async fn list_rules(&self) -> Result<CallToolResult, ErrorData> {
        let registry = default_registry();

        let rules: Vec<RuleInfo> = registry
            .rules()
            .iter()
            .map(|r| RuleInfo {
                id: r.id().to_string(),
                description: r.description().to_string(),
                category: r.category().to_string(),
                cwe_ids: r.cwe_ids().iter().map(|s| s.to_string()).collect(),
                owasp_ids: r.owasp_ids().iter().map(|s| s.to_string()).collect(),
                owasp_mcp_ids: r.owasp_mcp_ids().iter().map(|s| s.to_string()).collect(),
            })
            .collect();

        let output = serde_json::to_string_pretty(&rules).unwrap_or_else(|_| "[]".to_string());
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    #[tool(
        name = "mcplint_explain",
        description = "Get a detailed explanation of a specific mcplint security rule, including rationale, CWE/OWASP mappings, and remediation guidance."
    )]
    async fn explain(
        &self,
        Parameters(params): Parameters<ExplainParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let registry = default_registry();

        let rule = registry.find_rule(&params.rule_id).ok_or_else(|| {
            ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                format!(
                    "Unknown rule: '{}'. Use mcplint_list_rules to see available rules.",
                    params.rule_id
                ),
                None,
            )
        })?;

        let detail = RuleDetail {
            id: rule.id().to_string(),
            description: rule.description().to_string(),
            category: rule.category().to_string(),
            explanation: rule.explain().to_string(),
            rationale: rule.rationale().to_string(),
            cwe_ids: rule.cwe_ids().iter().map(|s| s.to_string()).collect(),
            owasp_ids: rule.owasp_ids().iter().map(|s| s.to_string()).collect(),
            owasp_mcp_ids: rule.owasp_mcp_ids().iter().map(|s| s.to_string()).collect(),
            references: rule.references().iter().map(|s| s.to_string()).collect(),
        };

        let output = serde_json::to_string_pretty(&detail).unwrap_or_else(|_| "{}".to_string());
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }
}

#[tool_handler]
impl ServerHandler for McplintServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "mcplint is a static security analyzer for MCP (Model Context Protocol) \
                 configurations. Use mcplint_scan to check MCP config files for security \
                 vulnerabilities like injection risks, over-permissioning, weak auth, and \
                 metadata leakage. Use mcplint_list_rules to see all available rules, and \
                 mcplint_explain to get detailed guidance on any rule."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// --- Helper types ---

#[derive(Serialize, Deserialize)]
struct RuleInfo {
    id: String,
    description: String,
    category: String,
    cwe_ids: Vec<String>,
    owasp_ids: Vec<String>,
    owasp_mcp_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct RuleDetail {
    id: String,
    description: String,
    category: String,
    explanation: String,
    rationale: String,
    cwe_ids: Vec<String>,
    owasp_ids: Vec<String>,
    owasp_mcp_ids: Vec<String>,
    references: Vec<String>,
}

fn parse_severity(s: &str) -> mcplint_core::Severity {
    match s.to_lowercase().as_str() {
        "critical" => mcplint_core::Severity::Critical,
        "high" => mcplint_core::Severity::High,
        "medium" => mcplint_core::Severity::Medium,
        _ => mcplint_core::Severity::Low,
    }
}

fn rules_metadata(
    registry: &mcplint_core::rule::RuleRegistry,
) -> Vec<(String, String, String, String)> {
    registry
        .rules()
        .iter()
        .map(|r| {
            (
                r.id().to_string(),
                r.description().to_string(),
                r.category().to_string(),
                r.explain().to_string(),
            )
        })
        .collect()
}

/// Run the MCP server on stdio transport.
pub async fn run_stdio() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let server = McplintServer::new();
    let service = server.serve(rmcp::transport::stdio()).await.map_err(|e| {
        tracing::error!("Failed to start MCP server: {}", e);
        e
    })?;

    service.waiting().await?;
    Ok(())
}
