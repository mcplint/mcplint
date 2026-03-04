use mcplint_core::{Confidence, Evidence, Finding, FindingCategory, Rule, ScanContext, Severity};
use regex::Regex;
use std::sync::OnceLock;

/// MG006: Sensitive metadata leakage.
/// Detects tool descriptions, error messages, or schemas exposing internal paths,
/// table names, infrastructure details, or sensitive identifiers.
pub struct Mg006MetadataLeakage;

/// Patterns that indicate sensitive metadata in descriptions or schemas.
struct LeakagePattern {
    name: &'static str,
    description: &'static str,
    pattern: &'static str,
    severity: Severity,
}

struct CompiledLeakagePattern {
    name: &'static str,
    description: &'static str,
    regex: Regex,
    severity: Severity,
}

fn compiled_patterns() -> &'static [CompiledLeakagePattern] {
    static PATTERNS: OnceLock<Vec<CompiledLeakagePattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        LEAKAGE_PATTERNS
            .iter()
            .map(|lp| CompiledLeakagePattern {
                regex: Regex::new(lp.pattern)
                    .unwrap_or_else(|e| panic!("Invalid MG006 pattern '{}': {}", lp.pattern, e)),
                severity: lp.severity,
                name: lp.name,
                description: lp.description,
            })
            .collect()
    })
}

const LEAKAGE_PATTERNS: &[LeakagePattern] = &[
    LeakagePattern {
        name: "absolute_path",
        description: "Absolute filesystem path",
        pattern: r#"(?:^|[\s"'(])(/(?:home|var|etc|usr|opt|tmp|srv|root|mnt|data|app|lib|bin|boot|proc|sys|dev|sbin|run)[/\w.-]+)"#,
        severity: Severity::Medium,
    },
    LeakagePattern {
        name: "windows_path",
        description: "Windows filesystem path",
        pattern: r"[A-Z]:\\[\w\\.-]+",
        severity: Severity::Medium,
    },
    LeakagePattern {
        name: "database_table",
        description: "Database table/schema reference",
        pattern: r"\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|INTO|JOIN|TABLE)\s+\w+",
        severity: Severity::Medium,
    },
    LeakagePattern {
        name: "internal_url",
        description: "Internal URL or endpoint",
        pattern: r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[\w/.:?&=-]*",
        severity: Severity::Medium,
    },
    LeakagePattern {
        name: "ip_address",
        description: "Internal IP address",
        pattern: r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        severity: Severity::Medium,
    },
    LeakagePattern {
        name: "connection_string",
        description: "Database connection string",
        pattern: r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)://\S+",
        severity: Severity::Critical,
    },
    LeakagePattern {
        name: "aws_resource",
        description: "AWS resource identifier",
        pattern: r"arn:aws:\w+:\w*:\d*:\S+",
        severity: Severity::High,
    },
    LeakagePattern {
        name: "env_variable_ref",
        description: "Environment variable with sensitive name",
        pattern: r"\$\{?(?:AWS_SECRET|DB_PASS|API_KEY|PRIVATE_KEY|SECRET_KEY|TOKEN|PASSWORD)\}?",
        severity: Severity::High,
    },
];

impl Rule for Mg006MetadataLeakage {
    fn id(&self) -> &'static str {
        "MG006"
    }

    fn description(&self) -> &'static str {
        "Sensitive metadata leakage: tool descriptions, error messages, or schemas exposing \
         internal paths, table names, infrastructure details, or sensitive identifiers."
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Static
    }

    fn explain(&self) -> &'static str {
        "MG006 scans all tool descriptions, parameter descriptions, server descriptions, \
         and schema values for leaked internal metadata. This includes absolute filesystem \
         paths, internal IP addresses, database table names, connection strings, AWS ARNs, \
         and environment variable references. Leaking such information helps attackers \
         understand internal architecture, identify attack targets, and craft precise exploits. \
         Remediation: remove internal details from user-facing descriptions. Use generic \
         references and document internal details separately."
    }

    fn cwe_ids(&self) -> Vec<&'static str> {
        vec!["CWE-200", "CWE-538"]
    }

    fn owasp_ids(&self) -> Vec<&'static str> {
        vec!["A01:2021"]
    }

    fn owasp_mcp_ids(&self) -> Vec<&'static str> {
        vec!["MCP01:2025", "MCP10:2025"]
    }

    fn rationale(&self) -> &'static str {
        "Internal infrastructure details in tool descriptions aid reconnaissance for attackers."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://cwe.mitre.org/data/definitions/200.html"]
    }

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let compiled = compiled_patterns();

        for server in &ctx.config.servers {
            let server_ptr = ctx.server_pointer(&server.name, "");
            let server_region = server_ptr
                .as_ref()
                .and_then(|ptr| ctx.region_for(ptr).cloned());

            // Check server description
            self.check_text(
                compiled,
                &server.description,
                &format!("{} > servers[{}].description", ctx.source_path, server.name),
                &server.name,
                "server description",
                server_region.clone(),
                &ctx.source_path,
                server_ptr.clone(),
                None,
                None,
                &mut findings,
            );

            for (tool_idx, tool) in server.tools.iter().enumerate() {
                let tool_ptr = ctx
                    .server_pointer(&server.name, &format!("tools/{}", tool_idx))
                    .or_else(|| ctx.server_pointer(&server.name, ""));
                let tool_region = tool_ptr
                    .as_ref()
                    .and_then(|ptr| ctx.region_for(ptr).cloned());

                // Check tool description
                self.check_text(
                    compiled,
                    &tool.description,
                    &format!(
                        "{} > servers[{}] > tools[{}].description",
                        ctx.source_path, server.name, tool.name
                    ),
                    &server.name,
                    &format!("tool '{}' description", tool.name),
                    tool_region.clone(),
                    &ctx.source_path,
                    tool_ptr.clone(),
                    Some(&tool.name),
                    None,
                    &mut findings,
                );

                // Check parameter descriptions
                for (param_idx, param) in tool.parameters.iter().enumerate() {
                    let param_ptr = ctx
                        .server_pointer(
                            &server.name,
                            &format!("tools/{}/parameters/{}", tool_idx, param_idx),
                        )
                        .or_else(|| ctx.server_pointer(&server.name, ""));
                    let param_region = param_ptr
                        .as_ref()
                        .and_then(|ptr| ctx.region_for(ptr).cloned());

                    self.check_text(
                        compiled,
                        &param.description,
                        &format!(
                            "{} > servers[{}] > tools[{}] > parameters[{}].description",
                            ctx.source_path, server.name, tool.name, param.name
                        ),
                        &server.name,
                        &format!("parameter '{}' in tool '{}'", param.name, tool.name),
                        param_region,
                        &ctx.source_path,
                        param_ptr,
                        Some(&tool.name),
                        Some(&param.name),
                        &mut findings,
                    );
                }
            }
        }

        findings
    }
}

impl Mg006MetadataLeakage {
    #[allow(clippy::too_many_arguments)]
    fn check_text(
        &self,
        patterns: &[CompiledLeakagePattern],
        text: &str,
        location: &str,
        server_name: &str,
        context_desc: &str,
        region: Option<mcplint_core::json_locator::Region>,
        source_path: &str,
        json_pointer: Option<String>,
        tool_name: Option<&str>,
        param_name: Option<&str>,
        findings: &mut Vec<Finding>,
    ) {
        if text.is_empty() {
            return;
        }

        for lp in patterns {
            if let Some(m) = lp.regex.find(text) {
                findings.push(Finding {
                    id: "MG006".to_string(),
                    title: format!(
                        "{} leaked in {} (server '{}')",
                        lp.description, context_desc, server_name
                    ),
                    severity: lp.severity,
                    confidence: Confidence::High,
                    category: FindingCategory::Static,
                    description: format!(
                        "Found {} in {}: '{}'. This reveals internal infrastructure \
                         details that can aid attackers in reconnaissance.",
                        lp.description,
                        context_desc,
                        m.as_str()
                    ),
                    exploit_scenario: format!(
                        "An attacker reads the MCP tool schema and discovers {} '{}' in {}. \
                         This information reveals internal architecture and can be used to \
                         craft targeted attacks against the infrastructure.",
                        lp.description,
                        m.as_str(),
                        context_desc
                    ),
                    evidence: vec![Evidence {
                        location: location.to_string(),
                        description: format!("{} pattern '{}' matched", lp.name, lp.description),
                        raw_value: Some(m.as_str().to_string()),
                        region: region.clone(),
                        file: Some(source_path.to_string()),
                        json_pointer: json_pointer.clone(),
                        server: Some(server_name.to_string()),
                        tool: tool_name.map(|s| s.to_string()),
                        parameter: param_name.map(|s| s.to_string()),
                    }],
                    cwe_ids: vec!["CWE-200".to_string(), "CWE-538".to_string()],
                    owasp_ids: vec!["A01:2021".to_string()],
                    owasp_mcp_ids: vec![],
                    remediation: format!(
                        "Remove the {} from {}. Use generic descriptions that don't \
                         reveal internal infrastructure. Document internal details in \
                         separate, non-exposed documentation.",
                        lp.description, context_desc
                    ),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcplint_core::*;
    use std::collections::BTreeMap;

    fn make_context(tools: Vec<ToolDefinition>) -> ScanContext {
        ScanContext::new(
            McpConfig {
                servers: vec![McpServer {
                    name: "test-server".into(),
                    description: "".into(),
                    tools,
                    auth: AuthConfig::None,
                    transport: "stdio".into(),
                    url: None,
                    command: None,
                    args: vec![],
                    env: BTreeMap::new(),
                }],
            },
            "test.json".into(),
        )
    }

    #[test]
    fn detects_internal_path() {
        let ctx = make_context(vec![ToolDefinition {
            name: "read_logs".into(),
            description: "Read logs from /var/log/app/production.log".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg006MetadataLeakage;
        let findings = rule.check(&ctx);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("path")));
    }

    #[test]
    fn detects_internal_ip() {
        let ctx = make_context(vec![ToolDefinition {
            name: "query_db".into(),
            description: "Connects to the database at 192.168.1.100".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg006MetadataLeakage;
        let findings = rule.check(&ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn detects_connection_string() {
        let ctx = make_context(vec![ToolDefinition {
            name: "query".into(),
            description: "Uses postgres://admin:pass@db.internal:5432/prod".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg006MetadataLeakage;
        let findings = rule.check(&ctx);
        assert!(!findings.is_empty());
        // Connection strings with credentials should be Critical
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "connection string with creds should be Critical"
        );
    }

    #[test]
    fn no_finding_for_clean_description() {
        let ctx = make_context(vec![ToolDefinition {
            name: "get_weather".into(),
            description: "Returns current weather for a city".into(),
            parameters: vec![ToolParameter {
                name: "city".into(),
                param_type: "string".into(),
                description: "City name".into(),
                required: true,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg006MetadataLeakage;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn all_patterns_compile() {
        let patterns = compiled_patterns();
        assert_eq!(
            patterns.len(),
            LEAKAGE_PATTERNS.len(),
            "All leakage patterns should compile successfully"
        );
    }
}
