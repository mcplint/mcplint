use mcplint_core::{Confidence, Evidence, Finding, FindingCategory, Rule, ScanContext, Severity};

/// MG004: Filesystem scope violations.
/// Detects arbitrary path access, globbing, or write access without confinement.
pub struct Mg004FilesystemScope;

/// Keywords indicating filesystem operations.
const FS_TOOL_PATTERNS: &[&str] = &[
    "file",
    "path",
    "directory",
    "dir",
    "folder",
    "fs",
    "filesystem",
    "read_file",
    "write_file",
    "delete_file",
    "list_dir",
    "mkdir",
    "copy",
    "move",
    "rename",
];

/// Keywords indicating path parameters that may allow traversal.
const PATH_PARAM_PATTERNS: &[&str] = &[
    "path",
    "file",
    "filename",
    "filepath",
    "directory",
    "dir",
    "folder",
    "location",
    "target",
    "source",
    "destination",
    "glob",
    "pattern",
];

/// Check if `text` contains `keyword` as a whole word (delimited by non-alphanumeric chars).
fn contains_word(text: &str, keyword: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric())
        .any(|word| word == keyword)
}

/// Checks if a tool operates on the filesystem.
fn is_filesystem_tool(name: &str, description: &str) -> bool {
    let combined = format!("{} {}", name, description).to_lowercase();
    FS_TOOL_PATTERNS.iter().any(|p| contains_word(&combined, p))
}

/// Checks if a parameter represents a file path.
fn is_path_parameter(name: &str, description: &str) -> bool {
    let combined = format!("{} {}", name, description).to_lowercase();
    PATH_PARAM_PATTERNS
        .iter()
        .any(|p| contains_word(&combined, p))
}

impl Rule for Mg004FilesystemScope {
    fn id(&self) -> &'static str {
        "MG004"
    }

    fn description(&self) -> &'static str {
        "Filesystem scope violations: arbitrary path access, globbing, or write access \
         without confinement."
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Static
    }

    fn explain(&self) -> &'static str {
        "MG004 identifies MCP tools that provide filesystem access through unconstrained \
         path parameters. Without explicit path confinement (e.g., allowlisted directories, \
         chroot, or path validation), these tools allow path traversal attacks (../../etc/passwd), \
         arbitrary file reads/writes, and glob-based data discovery. \
         Remediation: constrain path parameters to specific directories using allowlists, \
         validate paths to prevent traversal, and limit glob patterns to safe scopes."
    }

    fn cwe_ids(&self) -> Vec<&'static str> {
        vec!["CWE-22", "CWE-73"]
    }

    fn owasp_ids(&self) -> Vec<&'static str> {
        vec!["A01:2021"]
    }

    fn owasp_mcp_ids(&self) -> Vec<&'static str> {
        vec!["MCP05:2025", "MCP10:2025"]
    }

    fn rationale(&self) -> &'static str {
        "Filesystem tools without path confinement allow reading or writing arbitrary files."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://cwe.mitre.org/data/definitions/22.html"]
    }

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for server in &ctx.config.servers {
            for (tool_idx, tool) in server.tools.iter().enumerate() {
                if !is_filesystem_tool(&tool.name, &tool.description) {
                    continue;
                }

                for (param_idx, param) in tool.parameters.iter().enumerate() {
                    if !is_path_parameter(&param.name, &param.description) {
                        continue;
                    }

                    // Check for lack of constraints
                    let has_pattern = param.constraints.contains_key("pattern");
                    let has_enum = param.constraints.contains_key("enum");
                    let has_allowed_dirs = param.constraints.contains_key("allowedDirectories")
                        || param.constraints.contains_key("allowed_directories")
                        || param.constraints.contains_key("basePath")
                        || param.constraints.contains_key("base_path");

                    if has_pattern || has_enum || has_allowed_dirs {
                        continue;
                    }

                    // Check if tool name implies write operations (higher severity)
                    let is_write = {
                        let lower = format!("{} {}", tool.name, tool.description).to_lowercase();
                        lower.contains("write")
                            || lower.contains("delete")
                            || lower.contains("remove")
                            || lower.contains("create")
                            || lower.contains("modify")
                    };

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
                        id: "MG004".to_string(),
                        title: format!(
                            "Unconfined filesystem access in tool '{}' via parameter '{}'",
                            tool.name, param.name
                        ),
                        severity: if is_write {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        confidence: Confidence::High,
                        category: FindingCategory::Static,
                        description: format!(
                            "Tool '{}' (server '{}') accepts an unconstrained path parameter \
                             '{}' for filesystem operations. No allowedDirectories, basePath, \
                             pattern, or enum constraints are defined, allowing arbitrary \
                             filesystem access{}.",
                            tool.name,
                            server.name,
                            param.name,
                            if is_write { " including writes" } else { "" }
                        ),
                        exploit_scenario: format!(
                            "An attacker provides a path like '../../etc/passwd' or \
                             '/etc/shadow' to parameter '{}' in tool '{}', traversing \
                             outside any intended directory scope to {} sensitive files.",
                            param.name,
                            tool.name,
                            if is_write {
                                "overwrite or delete"
                            } else {
                                "read"
                            }
                        ),
                        evidence: vec![Evidence {
                            location: format!(
                                "{} > servers[{}] > tools[{}] > parameters[{}]",
                                ctx.source_path, server.name, tool.name, param.name
                            ),
                            description: format!(
                                "Unconstrained path parameter '{}' in filesystem tool with \
                                 no directory scoping",
                                param.name
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
                        cwe_ids: vec!["CWE-22".to_string(), "CWE-73".to_string()],
                        owasp_ids: vec!["A01:2021".to_string()],
                        owasp_mcp_ids: vec![],
                        remediation: format!(
                            "Add path constraints to parameter '{}': define \
                             'allowedDirectories' or 'basePath' to confine access to specific \
                             directories. Add a 'pattern' constraint to reject path traversal \
                             sequences. Consider using a chroot or sandbox for filesystem tools.",
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
    fn detects_unconfined_read() {
        let ctx = make_context(vec![ToolDefinition {
            name: "read_file".into(),
            description: "Read a file from disk".into(),
            parameters: vec![ToolParameter {
                name: "path".into(),
                param_type: "string".into(),
                description: "File path to read".into(),
                required: true,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg004FilesystemScope;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn detects_unconfined_write_as_critical() {
        let ctx = make_context(vec![ToolDefinition {
            name: "write_file".into(),
            description: "Write content to a file".into(),
            parameters: vec![ToolParameter {
                name: "path".into(),
                param_type: "string".into(),
                description: "File path to write".into(),
                required: true,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg004FilesystemScope;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn no_finding_for_constrained_path() {
        let mut constraints = BTreeMap::new();
        constraints.insert(
            "allowedDirectories".to_string(),
            serde_json::json!(["/tmp", "/var/data"]),
        );

        let ctx = make_context(vec![ToolDefinition {
            name: "read_file".into(),
            description: "Read a file from disk".into(),
            parameters: vec![ToolParameter {
                name: "path".into(),
                param_type: "string".into(),
                description: "File path to read".into(),
                required: true,
                constraints,
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg004FilesystemScope;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_false_positive_on_substring_match() {
        // "file" should not match "profile", "path" should not match "xpath"
        let ctx = make_context(vec![ToolDefinition {
            name: "get_profile".into(),
            description: "Get user profile via xpath query".into(),
            parameters: vec![ToolParameter {
                name: "xpath_expression".into(),
                param_type: "string".into(),
                description: "The classpath for the profile query".into(),
                required: true,
                constraints: BTreeMap::new(),
            }],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }]);

        let rule = Mg004FilesystemScope;
        let findings = rule.check(&ctx);
        assert!(
            findings.is_empty(),
            "should not match 'file' in 'profile' or 'path' in 'xpath/classpath'"
        );
    }
}
