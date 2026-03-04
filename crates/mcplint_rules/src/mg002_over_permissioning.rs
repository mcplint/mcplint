use mcplint_core::{
    Confidence, Evidence, Finding, FindingCategory, Rule, ScanContext, Severity, ToolDefinition,
};

/// MG002: Semantic over-permissioning.
/// Detects tools whose description claims limited scope but whose name/parameters
/// imply broader capability.
pub struct Mg002OverPermissioning;

/// Keywords indicating limited/read-only intent in descriptions.
const LIMITED_INTENT_KEYWORDS: &[&str] = &[
    "read", "view", "list", "get", "fetch", "search", "lookup", "check", "inspect", "query",
    "retrieve", "display", "show", "browse", "find",
];

/// Keywords indicating dangerous/write/broad capability in names or parameters.
const BROAD_CAPABILITY_KEYWORDS: &[&str] = &[
    "write",
    "delete",
    "remove",
    "update",
    "create",
    "modify",
    "execute",
    "exec",
    "run",
    "admin",
    "manage",
    "drop",
    "alter",
    "insert",
    "put",
    "patch",
    "deploy",
    "install",
    "upload",
    "send",
    "post",
    "kill",
    "terminate",
    "shutdown",
    "restart",
    "grant",
    "revoke",
];

/// Check if `text` contains `keyword` as a whole word (delimited by non-alphanumeric chars).
fn contains_word(text: &str, keyword: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric() && c != '\'')
        .any(|word| word == keyword)
}

fn description_implies_limited(desc: &str) -> Vec<&'static str> {
    let lower = desc.to_lowercase();
    LIMITED_INTENT_KEYWORDS
        .iter()
        .filter(|kw| contains_word(&lower, kw))
        .copied()
        .collect()
}

fn name_or_params_imply_broad(tool: &ToolDefinition) -> Vec<&'static str> {
    let mut combined = tool.name.to_lowercase();
    for p in &tool.parameters {
        combined.push(' ');
        combined.push_str(&p.name.to_lowercase());
        combined.push(' ');
        combined.push_str(&p.description.to_lowercase());
    }

    // Split on non-alphanumeric (treating underscores as delimiters too)
    let words: Vec<&str> = combined
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();

    BROAD_CAPABILITY_KEYWORDS
        .iter()
        .filter(|kw| words.iter().any(|w| w == *kw))
        .copied()
        .collect()
}

impl Rule for Mg002OverPermissioning {
    fn id(&self) -> &'static str {
        "MG002"
    }

    fn description(&self) -> &'static str {
        "Semantic over-permissioning: tool intent described as limited, but name/args imply \
         broader capability."
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Semantic
    }

    fn explain(&self) -> &'static str {
        "MG002 identifies tools where the description suggests read-only or limited access, \
         but the tool name or parameter names reveal write, delete, execute, or administrative \
         capabilities. This mismatch can mislead users or automated systems into granting \
         excessive permissions, as the description understates the tool's actual power. \
         Remediation: ensure tool descriptions accurately reflect all capabilities, or \
         split tools so each has a single, well-described responsibility."
    }

    fn cwe_ids(&self) -> Vec<&'static str> {
        vec!["CWE-285"]
    }

    fn owasp_ids(&self) -> Vec<&'static str> {
        vec!["A01:2021"]
    }

    fn owasp_mcp_ids(&self) -> Vec<&'static str> {
        vec!["MCP02:2025"]
    }

    fn rationale(&self) -> &'static str {
        "Tool descriptions that understate capabilities mislead users and LLMs about actual risk."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://cwe.mitre.org/data/definitions/285.html"]
    }

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for server in &ctx.config.servers {
            for (tool_idx, tool) in server.tools.iter().enumerate() {
                let limited = description_implies_limited(&tool.description);
                if limited.is_empty() {
                    continue;
                }

                let broad = name_or_params_imply_broad(tool);
                if broad.is_empty() {
                    continue;
                }

                let tool_pointer = ctx
                    .server_pointer(&server.name, &format!("tools/{}", tool_idx))
                    .or_else(|| ctx.server_pointer(&server.name, ""));
                let region = tool_pointer
                    .as_ref()
                    .and_then(|ptr| ctx.region_for(ptr).cloned());

                findings.push(Finding {
                    id: "MG002".to_string(),
                    title: format!(
                        "Over-permissioned tool '{}': description implies limited scope but \
                         capabilities are broad",
                        tool.name
                    ),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    category: FindingCategory::Semantic,
                    description: format!(
                        "Tool '{}' (server '{}') description uses limited-intent language ({}) \
                         but its name/parameters contain broad-capability indicators ({}). \
                         This mismatch may hide dangerous operations behind benign descriptions.",
                        tool.name,
                        server.name,
                        limited.join(", "),
                        broad.join(", ")
                    ),
                    exploit_scenario: format!(
                        "An LLM or user grants access to '{}' based on its benign description \
                         (containing: {}), without realizing it can also perform dangerous \
                         operations implied by: {}. An attacker exploits this mismatch to \
                         escalate privileges through the tool.",
                        tool.name,
                        limited.join(", "),
                        broad.join(", ")
                    ),
                    evidence: vec![
                        Evidence {
                            location: format!(
                                "{} > servers[{}] > tools[{}].description",
                                ctx.source_path, server.name, tool.name
                            ),
                            description: format!(
                                "Description implies limited scope with keywords: {}",
                                limited.join(", ")
                            ),
                            raw_value: Some(tool.description.clone()),
                            region: region.clone(),
                            file: Some(ctx.source_path.clone()),
                            json_pointer: tool_pointer.clone(),
                            server: Some(server.name.clone()),
                            tool: Some(tool.name.clone()),
                            parameter: None,
                        },
                        Evidence {
                            location: format!(
                                "{} > servers[{}] > tools[{}].name/parameters",
                                ctx.source_path, server.name, tool.name
                            ),
                            description: format!(
                                "Name/parameters imply broad capabilities: {}",
                                broad.join(", ")
                            ),
                            raw_value: Some(tool.name.clone()),
                            region,
                            file: Some(ctx.source_path.clone()),
                            json_pointer: tool_pointer,
                            server: Some(server.name.clone()),
                            tool: Some(tool.name.clone()),
                            parameter: None,
                        },
                    ],
                    cwe_ids: vec!["CWE-285".to_string()],
                    owasp_ids: vec!["A01:2021".to_string()],
                    owasp_mcp_ids: vec![],
                    remediation: format!(
                        "Update the description of tool '{}' to accurately reflect all \
                         capabilities including: {}. Alternatively, split the tool into \
                         separate read-only and write/execute tools.",
                        tool.name,
                        broad.join(", ")
                    ),
                });
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
    fn detects_read_description_with_delete_name() {
        let ctx = make_context(vec![ToolDefinition {
            name: "delete_records".into(),
            description: "Read and list records from the database".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg002OverPermissioning;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "MG002");
    }

    #[test]
    fn no_finding_for_honest_description() {
        let ctx = make_context(vec![ToolDefinition {
            name: "delete_records".into(),
            description: "Delete and remove records from the database".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg002OverPermissioning;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_finding_for_safe_tool() {
        let ctx = make_context(vec![ToolDefinition {
            name: "list_items".into(),
            description: "List all items".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg002OverPermissioning;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_false_positive_on_substring_match() {
        // "read" should not match "thread", "get" should not match "target"
        let ctx = make_context(vec![ToolDefinition {
            name: "update_thread".into(),
            description: "Spread the budget targets already set".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg002OverPermissioning;
        let findings = rule.check(&ctx);
        assert!(
            findings.is_empty(),
            "should not match 'read' in 'spread' or 'already', 'get' in 'target/budget'"
        );
    }

    #[test]
    fn no_false_positive_thread_reader() {
        // "thread_reader" splits into ["thread", "reader"] — "reader" != "read"
        let ctx = make_context(vec![ToolDefinition {
            name: "thread_reader".into(),
            description: "Read thread data from the forum".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg002OverPermissioning;
        let findings = rule.check(&ctx);
        assert!(
            findings.is_empty(),
            "thread_reader should not trigger MG002 — name has no broad keywords"
        );
    }

    #[test]
    fn detects_write_name_with_read_description() {
        // Name has "write" (broad), description says "read" (limited) — mismatch
        let ctx = make_context(vec![ToolDefinition {
            name: "write_file".into(),
            description: "Read and list file contents from the filesystem".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg002OverPermissioning;
        let findings = rule.check(&ctx);
        assert!(
            !findings.is_empty(),
            "write_file with read-only description should trigger MG002"
        );
    }

    #[test]
    fn no_false_positive_data_reader() {
        // Description says read-only, name confirms read intent — no mismatch
        let ctx = make_context(vec![ToolDefinition {
            name: "data_reader".into(),
            description: "This tool only reads data from the store".into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg002OverPermissioning;
        let findings = rule.check(&ctx);
        assert!(
            findings.is_empty(),
            "data_reader with read-only description should not trigger MG002"
        );
    }
}
