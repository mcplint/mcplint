use mcplint_core::{Confidence, Evidence, Finding, FindingCategory, Rule, ScanContext, Severity};

/// MG001: Unbounded string to dangerous sink.
/// Detects free-form string inputs flowing into exec, SQL, filesystem, HTTP,
/// or eval-like behavior without constraints.
pub struct Mg001UnboundedString;

/// Sinks that indicate dangerous operations when fed unbounded strings.
const DANGEROUS_SINK_PATTERNS: &[&str] = &[
    "exec", "execute", "eval", "run", "shell", "command", "cmd", "query", "sql", "script",
    "system", "spawn", "fork", "write", "delete", "remove", "fetch", "request", "http", "curl",
    "wget",
];

/// Checks if a tool name or description indicates a dangerous sink.
fn is_dangerous_sink(name: &str, description: &str) -> Vec<&'static str> {
    let combined = format!("{} {}", name, description).to_lowercase();
    DANGEROUS_SINK_PATTERNS
        .iter()
        .filter(|pattern| combined.contains(**pattern))
        .copied()
        .collect()
}

/// Returns the sink-specific maxLength threshold.
fn sink_threshold(sink: &str) -> u64 {
    match sink {
        "exec" | "shell" | "command" | "eval" | "run" | "system" | "spawn" | "fork" => 500,
        "sql" | "query" | "select" => 2_000,
        "write" | "delete" | "remove" | "script" => 1_000,
        "http" | "fetch" | "request" | "curl" | "wget" => 4_000,
        _ => 10_000,
    }
}

/// Checks if a parameter is an unbounded string (no meaningful constraints).
/// Returns None if constrained, Some(severity) if unconstrained or weakly constrained.
fn check_string_constraint(
    param: &mcplint_core::ToolParameter,
    matched_sink: &str,
) -> Option<Severity> {
    if param.param_type.to_lowercase() != "string" {
        return None;
    }
    let has_enum = param.constraints.contains_key("enum");
    let has_format = param.constraints.contains_key("format");

    let has_meaningful_pattern = param
        .constraints
        .get("pattern")
        .and_then(|v| v.as_str())
        .is_some_and(|p| !is_trivial_pattern(p));

    if has_enum || has_meaningful_pattern || has_format {
        return None; // Properly constrained
    }

    let threshold = sink_threshold(matched_sink);
    if let Some(max_len) = param.constraints.get("maxLength").and_then(|v| v.as_u64()) {
        if max_len > 0 && max_len <= threshold {
            return None; // maxLength within sink-specific threshold
        }
        // maxLength exists but too large for this sink type
        return Some(Severity::Medium);
    }

    // No maxLength at all
    Some(Severity::High)
}

/// Returns true if a regex pattern is trivially permissive.
fn is_trivial_pattern(pattern: &str) -> bool {
    // Normalize: strip anchors and outer grouping
    let normalized = pattern
        .trim()
        .trim_start_matches('^')
        .trim_end_matches('$')
        .trim_start_matches('(')
        .trim_end_matches(')');

    let trivial = [
        ".*",
        ".+",
        ".*?",
        ".+?",
        "[\\s\\S]*",
        "[\\s\\S]+",
        "[\\w\\W]*",
        "[\\w\\W]+",
        "[^]*",
        "[^]+",
        ".{0,}",
        ".{1,}",
        ".*\\S.*",
    ];

    trivial.contains(&normalized) || normalized.is_empty()
}

impl Rule for Mg001UnboundedString {
    fn id(&self) -> &'static str {
        "MG001"
    }

    fn description(&self) -> &'static str {
        "Unbounded string to dangerous sink: free-form string inputs flowing into exec, SQL, \
         filesystem, HTTP, or eval-like behavior without constraints."
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Static
    }

    fn explain(&self) -> &'static str {
        "MG001 detects MCP tools that accept unconstrained string parameters and pass them \
         to dangerous operations (execution, database queries, filesystem operations, or \
         network requests). An attacker who controls the string input can inject malicious \
         payloads — SQL injection, command injection, path traversal, or SSRF. \
         Remediation: add constraints such as enum values, regex patterns, maxLength limits, \
         or format specifications to all string parameters that flow to sensitive operations."
    }

    fn cwe_ids(&self) -> Vec<&'static str> {
        vec!["CWE-77", "CWE-89", "CWE-78"]
    }

    fn owasp_ids(&self) -> Vec<&'static str> {
        vec!["A03:2021"]
    }

    fn owasp_mcp_ids(&self) -> Vec<&'static str> {
        vec!["MCP05:2025", "MCP06:2025"]
    }

    fn rationale(&self) -> &'static str {
        "Unbounded string parameters flowing to execution sinks enable injection attacks."
    }

    fn references(&self) -> Vec<&'static str> {
        vec![
            "https://cwe.mitre.org/data/definitions/77.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ]
    }

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for server in &ctx.config.servers {
            for (tool_idx, tool) in server.tools.iter().enumerate() {
                let sinks = is_dangerous_sink(&tool.name, &tool.description);
                if sinks.is_empty() {
                    continue;
                }

                let unbounded_params: Vec<(usize, &mcplint_core::ToolParameter, Severity, &str)> =
                    tool.parameters
                        .iter()
                        .enumerate()
                        .filter_map(|(i, p)| {
                            // Pick the first matching sink for threshold calculation
                            let matched = sinks.first().unwrap();
                            check_string_constraint(p, matched).map(|sev| (i, p, sev, *matched))
                        })
                        .collect();

                for (param_idx, param, severity, _matched_sink) in &unbounded_params {
                    let sink_list = sinks.join(", ");

                    // Try to resolve region from server pointer + tool/param path
                    let param_pointer = ctx
                        .server_pointer(
                            &server.name,
                            &format!("tools/{}/parameters/{}", tool_idx, param_idx),
                        )
                        .or_else(|| ctx.server_pointer(&server.name, ""));
                    let region = param_pointer
                        .as_ref()
                        .and_then(|ptr| ctx.region_for(ptr).cloned());

                    findings.push(Finding {
                        id: "MG001".to_string(),
                        title: format!(
                            "Unbounded string '{}' flows to dangerous sink in tool '{}'",
                            param.name, tool.name
                        ),
                        severity: *severity,
                        confidence: Confidence::High,
                        category: FindingCategory::Static,
                        description: format!(
                            "Parameter '{}' in tool '{}' (server '{}') is an unconstrained \
                             string that flows to dangerous operation(s): {}. No enum, pattern, \
                             maxLength, or format constraints are defined.",
                            param.name, tool.name, server.name, sink_list
                        ),
                        exploit_scenario: format!(
                            "An attacker controlling the '{}' parameter can inject malicious \
                             content targeting the {} sink(s). For example, if this is a SQL \
                             query parameter, the attacker could execute 'DROP TABLE users; --' \
                             or exfiltrate data via UNION-based injection.",
                            param.name, sink_list
                        ),
                        evidence: vec![Evidence {
                            location: format!(
                                "{} > servers[{}] > tools[{}] > parameters[{}]",
                                ctx.source_path, server.name, tool.name, param.name
                            ),
                            description: format!(
                                "Unconstrained string parameter '{}' with type '{}' and no \
                                 validation constraints, in tool with dangerous sink indicators: {}",
                                param.name, param.param_type, sink_list
                            ),
                            raw_value: Some(format!(
                                "{{ \"name\": \"{}\", \"type\": \"{}\", \"constraints\": {{}} }}",
                                param.name, param.param_type
                            )),
                            region,
                            file: Some(ctx.source_path.clone()),
                            json_pointer: param_pointer,
                            server: Some(server.name.clone()),
                            tool: Some(tool.name.clone()),
                            parameter: Some(param.name.clone()),
                        }],
                        cwe_ids: vec![
                            "CWE-77".to_string(),
                            "CWE-89".to_string(),
                            "CWE-78".to_string(),
                        ],
                        owasp_ids: vec!["A03:2021".to_string()],
                        owasp_mcp_ids: vec![],
                        remediation: format!(
                            "Add input constraints to parameter '{}': use an enum for known \
                             values, a regex pattern for structured input, maxLength to limit \
                             size, or a format specifier. Consider parameterized queries for \
                             SQL sinks and allowlists for command execution.",
                            param.name
                        ),
                    });
                }
            }
        }

        findings
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
    fn detects_unbounded_sql_query() {
        let ctx = make_context(vec![ToolDefinition {
            name: "run_query".into(),
            description: "Execute a SQL query against the database".into(),
            parameters: vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL query".into(),
                required: true,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "MG001");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn no_finding_for_constrained_param() {
        let mut constraints = BTreeMap::new();
        constraints.insert("enum".to_string(), serde_json::json!(["SELECT", "INSERT"]));

        let ctx = make_context(vec![ToolDefinition {
            name: "run_query".into(),
            description: "Execute a SQL query".into(),
            parameters: vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL query".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_trivial_pattern_constraint() {
        // pattern: ".*" is effectively no constraint
        let mut constraints = BTreeMap::new();
        constraints.insert("pattern".to_string(), serde_json::json!(".*"));

        let ctx = make_context(vec![ToolDefinition {
            name: "run_query".into(),
            description: "Execute a SQL query".into(),
            parameters: vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL query".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert_eq!(
            findings.len(),
            1,
            "trivial pattern '.*' should not suppress finding"
        );
    }

    #[test]
    fn detects_absurd_max_length() {
        // maxLength: 999999 is effectively no constraint
        let mut constraints = BTreeMap::new();
        constraints.insert("maxLength".to_string(), serde_json::json!(999_999));

        let ctx = make_context(vec![ToolDefinition {
            name: "run_query".into(),
            description: "Execute a SQL query".into(),
            parameters: vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL query".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert_eq!(
            findings.len(),
            1,
            "absurdly large maxLength should not suppress finding"
        );
    }

    #[test]
    fn no_finding_for_meaningful_pattern() {
        let mut constraints = BTreeMap::new();
        constraints.insert("pattern".to_string(), serde_json::json!("^[a-zA-Z_]+$"));

        let ctx = make_context(vec![ToolDefinition {
            name: "run_query".into(),
            description: "Execute a SQL query".into(),
            parameters: vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL query".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert!(
            findings.is_empty(),
            "meaningful pattern should suppress finding"
        );
    }

    #[test]
    fn no_finding_for_safe_tool() {
        let ctx = make_context(vec![ToolDefinition {
            name: "get_time".into(),
            description: "Returns the current time".into(),
            parameters: vec![ToolParameter {
                name: "timezone".into(),
                param_type: "string".into(),
                description: "Timezone name".into(),
                required: false,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn trivial_anchored_pattern() {
        let mut constraints = BTreeMap::new();
        constraints.insert("pattern".to_string(), serde_json::json!("^.*$"));

        let ctx = make_context(vec![ToolDefinition {
            name: "run_query".into(),
            description: "Execute a SQL query".into(),
            parameters: vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL query".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1, "^.*$ is trivial — should still flag");
    }

    #[test]
    fn trivial_nongreedy_pattern() {
        assert!(is_trivial_pattern(".*?"));
        assert!(is_trivial_pattern(".+?"));
    }

    #[test]
    fn trivial_cross_line_pattern() {
        assert!(is_trivial_pattern("[\\s\\S]*"));
        assert!(is_trivial_pattern("[\\w\\W]*"));
    }

    #[test]
    fn trivial_grouped_pattern() {
        assert!(is_trivial_pattern("(.+)"));
    }

    #[test]
    fn nontrivial_patterns() {
        assert!(!is_trivial_pattern("^[a-zA-Z0-9_]+$"));
        assert!(!is_trivial_pattern("\\d{3}-\\d{4}"));
    }

    #[test]
    fn sql_param_with_safe_max_length() {
        // maxLength=500 is within the SQL threshold of 2000 — no finding
        let mut constraints = BTreeMap::new();
        constraints.insert("maxLength".to_string(), serde_json::json!(500));

        let ctx = make_context(vec![ToolDefinition {
            name: "run_query".into(),
            description: "Execute a SQL query".into(),
            parameters: vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL query".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty(), "maxLength=500 for SQL should be safe");
    }

    #[test]
    fn sql_param_above_threshold_is_medium() {
        // maxLength=5000 exceeds SQL threshold (2000) — Medium severity
        let mut constraints = BTreeMap::new();
        constraints.insert("maxLength".to_string(), serde_json::json!(5000));

        let ctx = make_context(vec![ToolDefinition {
            name: "run_query".into(),
            description: "Execute a SQL query".into(),
            parameters: vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL query".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn sql_param_no_max_length_is_high() {
        // No maxLength at all — High severity
        let ctx = make_context(vec![ToolDefinition {
            name: "run_query".into(),
            description: "Execute a SQL query".into(),
            parameters: vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL query".into(),
                required: true,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn exec_param_with_safe_max_length() {
        let mut constraints = BTreeMap::new();
        constraints.insert("maxLength".to_string(), serde_json::json!(200));

        let ctx = make_context(vec![ToolDefinition {
            name: "exec_command".into(),
            description: "Execute a shell command".into(),
            parameters: vec![ToolParameter {
                name: "cmd".into(),
                param_type: "string".into(),
                description: "command".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty(), "maxLength=200 for exec should be safe");
    }

    #[test]
    fn exec_param_above_threshold_is_medium() {
        let mut constraints = BTreeMap::new();
        constraints.insert("maxLength".to_string(), serde_json::json!(2000));

        let ctx = make_context(vec![ToolDefinition {
            name: "exec_command".into(),
            description: "Execute a shell command".into(),
            parameters: vec![ToolParameter {
                name: "cmd".into(),
                param_type: "string".into(),
                description: "command".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg001UnboundedString;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }
}
