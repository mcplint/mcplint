use mcplint_core::{Confidence, Evidence, Finding, FindingCategory, Rule, ScanContext, Severity};

/// MG007: Overly broad tool parameter scopes.
/// Detects tools with unconstrained or excessively permissive parameters — the
/// "accepts anything" anti-pattern that lets an LLM pass arbitrary data.
pub struct Mg007BroadScope;

/// Patterns from MG001 — tools matching these are already covered and should be
/// skipped by MG007 to avoid double-counting.
const MG001_SINK_PATTERNS: &[&str] = &[
    "exec", "execute", "eval", "run", "shell", "command", "cmd", "query", "sql", "script",
    "system", "spawn", "fork", "write", "delete", "remove", "fetch", "request", "http", "curl",
    "wget",
];

/// Words in a tool description suggesting it takes input (for zero-param check).
const INPUT_SUGGESTING_WORDS: &[&str] = &[
    "query", "input", "command", "path", "url", "request", "execute", "search",
];

/// Returns true if the tool name/description matches MG001 dangerous sink patterns.
fn is_mg001_sink(name: &str, description: &str) -> bool {
    let combined = format!("{} {}", name, description).to_lowercase();
    MG001_SINK_PATTERNS
        .iter()
        .any(|pattern| combined.contains(pattern))
}

/// Returns true if a parameter already has any meaningful constraint.
fn has_any_constraint(constraints: &std::collections::BTreeMap<String, serde_json::Value>) -> bool {
    let constraint_keys = [
        "enum",
        "pattern",
        "maxLength",
        "minLength",
        "minimum",
        "maximum",
        "items",
        "properties",
    ];
    for key in constraint_keys {
        if constraints.contains_key(key) {
            return true;
        }
    }
    // additionalProperties: false is also a constraint
    if let Some(v) = constraints.get("additionalProperties") {
        if v == &serde_json::Value::Bool(false) {
            return true;
        }
    }
    false
}

impl Rule for Mg007BroadScope {
    fn id(&self) -> &'static str {
        "MG007"
    }

    fn description(&self) -> &'static str {
        "Overly broad tool parameter scopes: unconstrained types, missing type definitions, \
         or excessively permissive parameter schemas that accept arbitrary data."
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Static
    }

    fn explain(&self) -> &'static str {
        "MG007 detects tools with parameters that are too permissive. This includes: \
         parameters with no type defined, object types with no property schema, array types \
         with no items constraint, and completely unbounded strings on non-dangerous-sink \
         tools (MG001 handles dangerous sinks). It also flags tools with zero parameters \
         but input-suggesting descriptions. Remediation: add type definitions, property \
         schemas, items constraints, enum values, or patterns to constrain what an LLM \
         can pass to each parameter."
    }

    fn cwe_ids(&self) -> Vec<&'static str> {
        vec!["CWE-20"]
    }

    fn owasp_ids(&self) -> Vec<&'static str> {
        vec!["A03:2021"]
    }

    fn owasp_mcp_ids(&self) -> Vec<&'static str> {
        vec!["MCP02:2025", "MCP05:2025"]
    }

    fn rationale(&self) -> &'static str {
        "Unconstrained parameters accept arbitrary data, enabling unexpected or malicious inputs."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://cwe.mitre.org/data/definitions/20.html"]
    }

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for server in &ctx.config.servers {
            for (tool_idx, tool) in server.tools.iter().enumerate() {
                let is_sink = is_mg001_sink(&tool.name, &tool.description);

                // Check 5: zero params but input-suggesting description
                if tool.parameters.is_empty() {
                    let desc_lower = tool.description.to_lowercase();
                    if INPUT_SUGGESTING_WORDS
                        .iter()
                        .any(|w| desc_lower.contains(w))
                    {
                        let tool_ptr = ctx
                            .server_pointer(&server.name, &format!("tools/{}", tool_idx))
                            .or_else(|| ctx.server_pointer(&server.name, ""));
                        let region = tool_ptr
                            .as_ref()
                            .and_then(|ptr| ctx.region_for(ptr).cloned());

                        findings.push(Finding {
                            id: "MG007".to_string(),
                            title: format!("Overly broad parameter scope on tool '{}'", tool.name),
                            severity: Severity::Medium,
                            confidence: Confidence::Medium,
                            category: FindingCategory::Static,
                            description: format!(
                                "Tool '{}' (server '{}') has zero parameters defined but its \
                                 description suggests it accepts input. This means the tool's \
                                 input schema is completely unconstrained.",
                                tool.name, server.name
                            ),
                            exploit_scenario: format!(
                                "An LLM could pass unexpected or malicious data to tool '{}' \
                                 because no parameters or constraints are defined, despite the \
                                 description indicating input is expected.",
                                tool.name
                            ),
                            evidence: vec![Evidence {
                                location: format!(
                                    "{} > servers[{}] > tools[{}]",
                                    ctx.source_path, server.name, tool.name
                                ),
                                description: format!(
                                    "Tool '{}' has zero parameters but description suggests input",
                                    tool.name
                                ),
                                raw_value: Some(format!(
                                    "{{ \"name\": \"{}\", \"parameters\": [] }}",
                                    tool.name
                                )),
                                region,
                                file: Some(ctx.source_path.clone()),
                                json_pointer: tool_ptr,
                                server: Some(server.name.clone()),
                                tool: Some(tool.name.clone()),
                                parameter: None,
                            }],
                            cwe_ids: vec!["CWE-20".to_string()],
                            owasp_ids: vec!["A03:2021".to_string()],
                            owasp_mcp_ids: vec![],
                            remediation: format!(
                                "Define explicit parameters for tool '{}' with type constraints, \
                                 enum values, or patterns. If the tool truly takes no input, \
                                 clarify the description.",
                                tool.name
                            ),
                        });
                    }
                    continue;
                }

                // Skip tools covered by MG001
                if is_sink {
                    continue;
                }

                for (param_idx, param) in tool.parameters.iter().enumerate() {
                    // Skip params that already have any constraint
                    if has_any_constraint(&param.constraints) {
                        continue;
                    }

                    let param_ptr = ctx
                        .server_pointer(
                            &server.name,
                            &format!("tools/{}/parameters/{}", tool_idx, param_idx),
                        )
                        .or_else(|| ctx.server_pointer(&server.name, ""));
                    let region = param_ptr
                        .as_ref()
                        .and_then(|ptr| ctx.region_for(ptr).cloned());

                    let issue = if param.param_type.is_empty() {
                        // Check 1: missing type
                        Some((
                            "no type defined",
                            "Add a type definition (string, number, boolean, object, or array) \
                             to constrain the parameter's accepted values.",
                        ))
                    } else {
                        match param.param_type.to_lowercase().as_str() {
                            "object" => {
                                // Check 2: object with no properties
                                Some((
                                    "unconstrained object (no properties defined)",
                                    "Define a properties schema and consider setting \
                                     additionalProperties: false to restrict accepted keys.",
                                ))
                            }
                            "array" => {
                                // Check 3: array with no items
                                Some((
                                    "unconstrained array (no items constraint)",
                                    "Define an items schema to constrain what elements the \
                                     array can contain.",
                                ))
                            }
                            "string" => {
                                // Check 4: unbounded string on non-sink
                                Some((
                                    "completely unbounded string (no enum, pattern, or maxLength)",
                                    "Add enum values, a regex pattern, or maxLength to constrain \
                                     the string parameter.",
                                ))
                            }
                            _ => None,
                        }
                    };

                    if let Some((issue_desc, remediation_detail)) = issue {
                        findings.push(Finding {
                            id: "MG007".to_string(),
                            title: format!("Overly broad parameter scope on tool '{}'", tool.name),
                            severity: Severity::Medium,
                            confidence: Confidence::Medium,
                            category: FindingCategory::Static,
                            description: format!(
                                "Parameter '{}' in tool '{}' (server '{}') has {}. \
                                 An LLM can pass arbitrary data without validation.",
                                param.name, tool.name, server.name, issue_desc
                            ),
                            exploit_scenario: format!(
                                "An LLM could pass unexpected or malicious data through the \
                                 unconstrained '{}' parameter because no type, enum, pattern, \
                                 or length constraints are defined.",
                                param.name
                            ),
                            evidence: vec![Evidence {
                                location: format!(
                                    "{} > servers[{}] > tools[{}] > parameters[{}]",
                                    ctx.source_path, server.name, tool.name, param.name
                                ),
                                description: format!(
                                    "Parameter '{}' has {}",
                                    param.name, issue_desc
                                ),
                                raw_value: Some(format!(
                                    "{{ \"name\": \"{}\", \"type\": \"{}\" }}",
                                    param.name, param.param_type
                                )),
                                region,
                                file: Some(ctx.source_path.clone()),
                                json_pointer: param_ptr,
                                server: Some(server.name.clone()),
                                tool: Some(tool.name.clone()),
                                parameter: Some(param.name.clone()),
                            }],
                            cwe_ids: vec!["CWE-20".to_string()],
                            owasp_ids: vec!["A03:2021".to_string()],
                            owasp_mcp_ids: vec![],
                            remediation: format!(
                                "Constrain parameter '{}' in tool '{}': {}",
                                param.name, tool.name, remediation_detail
                            ),
                        });
                    }
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

    fn make_context(servers: Vec<McpServer>) -> ScanContext {
        ScanContext::new(McpConfig { servers }, "test.json".into())
    }

    fn make_server(tools: Vec<ToolDefinition>) -> McpServer {
        McpServer {
            name: "test-server".into(),
            description: "".into(),
            tools,
            auth: AuthConfig::None,
            transport: "stdio".into(),
            url: None,
            command: None,
            args: vec![],
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn detects_missing_type() {
        let ctx = make_context(vec![make_server(vec![ToolDefinition {
            name: "get_data".into(),
            description: "Gets some data".into(),
            parameters: vec![ToolParameter {
                name: "filter".into(),
                param_type: "".into(),
                description: "Filter criteria".into(),
                required: false,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }])]);

        let rule = Mg007BroadScope;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("no type defined"));
    }

    #[test]
    fn detects_unconstrained_object() {
        let ctx = make_context(vec![make_server(vec![ToolDefinition {
            name: "process_data".into(),
            description: "Process data".into(),
            parameters: vec![ToolParameter {
                name: "payload".into(),
                param_type: "object".into(),
                description: "Data payload".into(),
                required: true,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }])]);

        let rule = Mg007BroadScope;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("unconstrained object"));
    }

    #[test]
    fn detects_unconstrained_array() {
        let ctx = make_context(vec![make_server(vec![ToolDefinition {
            name: "batch_process".into(),
            description: "Process items".into(),
            parameters: vec![ToolParameter {
                name: "items".into(),
                param_type: "array".into(),
                description: "Items to process".into(),
                required: true,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }])]);

        let rule = Mg007BroadScope;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("unconstrained array"));
    }

    #[test]
    fn detects_unbounded_string_on_non_sink() {
        let ctx = make_context(vec![make_server(vec![ToolDefinition {
            name: "get_weather".into(),
            description: "Gets weather info".into(),
            parameters: vec![ToolParameter {
                name: "location".into(),
                param_type: "string".into(),
                description: "Location".into(),
                required: true,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }])]);

        let rule = Mg007BroadScope;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("unbounded string"));
    }

    #[test]
    fn skips_mg001_sink_tools() {
        // MG001 covers this tool — MG007 should skip it
        let ctx = make_context(vec![make_server(vec![ToolDefinition {
            name: "run_query".into(),
            description: "Execute a SQL query".into(),
            parameters: vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL".into(),
                required: true,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }])]);

        let rule = Mg007BroadScope;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty(), "MG001 sink should be skipped by MG007");
    }

    #[test]
    fn skips_constrained_params() {
        let mut constraints = BTreeMap::new();
        constraints.insert("maxLength".to_string(), serde_json::json!(100));

        let ctx = make_context(vec![make_server(vec![ToolDefinition {
            name: "get_weather".into(),
            description: "Gets weather".into(),
            parameters: vec![ToolParameter {
                name: "city".into(),
                param_type: "string".into(),
                description: "City".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }])]);

        let rule = Mg007BroadScope;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty(), "Constrained param should be skipped");
    }

    #[test]
    fn detects_zero_params_with_input_description() {
        let ctx = make_context(vec![make_server(vec![ToolDefinition {
            name: "lookup".into(),
            description: "Search for items by query".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }])]);

        let rule = Mg007BroadScope;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("zero parameters defined"));
    }

    #[test]
    fn no_finding_for_zero_params_without_input_description() {
        let ctx = make_context(vec![make_server(vec![ToolDefinition {
            name: "get_time".into(),
            description: "Returns the current time".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }])]);

        let rule = Mg007BroadScope;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }
}
