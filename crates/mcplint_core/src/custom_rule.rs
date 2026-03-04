//! Declarative custom rule system.
//!
//! Allows users to define pattern-matching security rules in YAML without
//! writing Rust. Each rule is a single YAML file with match conditions
//! evaluated against servers, tools, and parameters.

use crate::finding::{Confidence, Evidence, Finding, FindingCategory, Severity};
use crate::mcp_schema::{AuthConfig, McpServer, ToolDefinition, ToolParameter};
use crate::rule::Rule;
use crate::scan_context::ScanContext;
use serde::Deserialize;
use std::path::Path;

// ── Data model ──────────────────────────────────────────────────────────────

/// A complete custom rule definition parsed from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomRuleDefinition {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    #[serde(default = "default_confidence")]
    pub confidence: String,
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub exploit_scenario: String,
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    #[serde(default)]
    pub owasp_ids: Vec<String>,
    #[serde(rename = "match")]
    pub match_config: MatchConfig,
}

fn default_confidence() -> String {
    "medium".into()
}
fn default_category() -> String {
    "static".into()
}

/// Match configuration — all specified sections must match (AND).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MatchConfig {
    #[serde(default)]
    pub server: Option<ServerMatch>,
    #[serde(default)]
    pub tool: Option<ToolMatch>,
    #[serde(default)]
    pub parameter: Option<ParameterMatch>,
}

/// Server-level match conditions.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerMatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub env: Option<EnvMatch>,
}

/// Environment variable match conditions.
#[derive(Debug, Clone, Deserialize)]
pub struct EnvMatch {
    #[serde(default)]
    pub has_key: Option<String>,
    #[serde(default)]
    pub value_matches: Option<String>,
}

/// Tool-level match conditions.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolMatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Parameter-level match conditions.
#[derive(Debug, Clone, Deserialize)]
pub struct ParameterMatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "type")]
    pub param_type: Option<String>,
    #[serde(default)]
    pub unconstrained: Option<bool>,
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CustomRuleError {
    #[error("I/O error reading {0}: {1}")]
    Io(String, #[source] std::io::Error),
    #[error("Parse error in {0}: {1}")]
    Parse(String, String),
    #[error("Rule ID '{0}' uses reserved prefix 'MG'")]
    ReservedId(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid severity: {0}")]
    InvalidSeverity(String),
}

// ── Glob matching ───────────────────────────────────────────────────────────

/// Simple glob matching: `*` matches any sequence, `?` matches one char.
/// Case-insensitive. Supports `|` for alternatives.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    pattern
        .split('|')
        .any(|p| glob_match_single(p.trim(), text))
}

fn glob_match_single(pattern: &str, text: &str) -> bool {
    let p = pattern.to_lowercase();
    let t = text.to_lowercase();
    glob_recursive(p.as_bytes(), t.as_bytes())
}

fn glob_recursive(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            // '*' matches zero chars (skip star) or one char (advance text)
            glob_recursive(&pattern[1..], text)
                || (!text.is_empty() && glob_recursive(pattern, &text[1..]))
        }
        (Some(b'?'), Some(_)) => glob_recursive(&pattern[1..], &text[1..]),
        (Some(a), Some(b)) if a == b => glob_recursive(&pattern[1..], &text[1..]),
        _ => false,
    }
}

/// Check if a value matches a pipe-separated list of exact values (case-insensitive).
fn pipe_match(pattern: &str, value: &str) -> bool {
    let lower = value.to_lowercase();
    pattern.split('|').any(|p| p.trim().to_lowercase() == lower)
}

// ── Severity/confidence/category parsing ────────────────────────────────────

fn parse_severity(s: &str) -> Result<Severity, CustomRuleError> {
    match s.to_lowercase().as_str() {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(CustomRuleError::InvalidSeverity(s.to_string())),
    }
}

fn parse_confidence(s: &str) -> Confidence {
    match s.to_lowercase().as_str() {
        "low" => Confidence::Low,
        "high" => Confidence::High,
        _ => Confidence::Medium,
    }
}

fn parse_category(s: &str) -> FindingCategory {
    match s.to_lowercase().as_str() {
        "semantic" => FindingCategory::Semantic,
        "compositional" => FindingCategory::Compositional,
        _ => FindingCategory::Static,
    }
}

fn auth_to_string(auth: &AuthConfig) -> &'static str {
    match auth {
        AuthConfig::None => "none",
        AuthConfig::ApiKey { .. } => "api_key",
        AuthConfig::Bearer { .. } => "bearer",
        AuthConfig::OAuth { .. } => "oauth",
        AuthConfig::Custom { .. } => "custom",
    }
}

// ── Leak helper ─────────────────────────────────────────────────────────────

/// Leak a string to get `&'static str`. Acceptable because custom rules are
/// loaded once at process start and live for the entire process lifetime.
fn leak_string(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

fn leak_strings(v: &[String]) -> Vec<&'static str> {
    v.iter().map(|s| leak_string(s)).collect()
}

// ── CustomRule ──────────────────────────────────────────────────────────────

/// A custom rule wrapping a YAML definition, implementing the Rule trait.
#[derive(Debug)]
pub struct CustomRule {
    pub(crate) def: CustomRuleDefinition,
}

impl CustomRule {
    pub fn new(def: CustomRuleDefinition) -> Result<Self, CustomRuleError> {
        if def.id.is_empty() || def.title.is_empty() {
            return Err(CustomRuleError::MissingField("id or title".into()));
        }
        if def.id.to_uppercase().starts_with("MG") {
            return Err(CustomRuleError::ReservedId(def.id.clone()));
        }
        parse_severity(&def.severity)?;
        Ok(Self { def })
    }

    fn matches_server(&self, sm: &ServerMatch, server: &McpServer) -> bool {
        if let Some(ref pat) = sm.name {
            if !glob_match(pat, &server.name) {
                return false;
            }
        }
        if let Some(ref pat) = sm.transport {
            if !pipe_match(pat, &server.transport) {
                return false;
            }
        }
        if let Some(ref pat) = sm.auth {
            let auth_str = auth_to_string(&server.auth);
            if !pipe_match(pat, auth_str) {
                return false;
            }
        }
        if let Some(ref pat) = sm.url {
            let url_value = server
                .url
                .as_deref()
                .or(server.command.as_deref())
                .unwrap_or("");
            if !glob_match(pat, url_value) {
                return false;
            }
        }
        if let Some(ref env_match) = sm.env {
            if !self.matches_env(env_match, server) {
                return false;
            }
        }
        true
    }

    fn matches_env(&self, em: &EnvMatch, server: &McpServer) -> bool {
        if let Some(ref key_pat) = em.has_key {
            if !server.env.keys().any(|k| glob_match(key_pat, k)) {
                return false;
            }
        }
        if let Some(ref val_pat) = em.value_matches {
            if !server.env.values().any(|v| glob_match(val_pat, v)) {
                return false;
            }
        }
        true
    }

    fn matches_tool(&self, tm: &ToolMatch, tool: &ToolDefinition) -> bool {
        if let Some(ref pat) = tm.name {
            if !glob_match(pat, &tool.name) {
                return false;
            }
        }
        if let Some(ref pat) = tm.description {
            if !glob_match(pat, &tool.description) {
                return false;
            }
        }
        true
    }

    fn matches_parameter(&self, pm: &ParameterMatch, param: &ToolParameter) -> bool {
        if let Some(ref pat) = pm.name {
            if !pipe_match(pat, &param.name) {
                return false;
            }
        }
        if let Some(ref pat) = pm.param_type {
            if pat.to_lowercase() != param.param_type.to_lowercase() {
                return false;
            }
        }
        if let Some(true) = pm.unconstrained {
            let has_max_length = param.constraints.contains_key("maxLength");
            let has_enum = param.constraints.contains_key("enum");
            let has_pattern = param.constraints.contains_key("pattern");
            if has_max_length || has_enum || has_pattern {
                return false;
            }
        }
        true
    }

    fn build_finding(
        &self,
        server: &McpServer,
        tool: Option<&ToolDefinition>,
        param: Option<&ToolParameter>,
        ctx: &ScanContext,
    ) -> Finding {
        // Build location string
        let mut location = format!("{} > servers[{}]", ctx.source_path, server.name);
        if let Some(t) = tool {
            location.push_str(&format!(" > tools[{}]", t.name));
        }
        if let Some(p) = param {
            location.push_str(&format!(" > parameters[{}]", p.name));
        }

        // Build JSON pointer
        let pointer_suffix = if let Some(p) = param {
            if let Some(t) = tool {
                format!(
                    "tools/{}/parameters/{}",
                    t.name,
                    crate::json_locator::escape_pointer(&p.name)
                )
            } else {
                String::new()
            }
        } else if let Some(t) = tool {
            format!("tools/{}", t.name)
        } else {
            String::new()
        };
        let json_pointer = ctx.server_pointer(&server.name, &pointer_suffix);

        // Build raw_value description
        let raw_value = if let Some(p) = param {
            format!(
                "parameter '{}' on tool '{}' of server '{}', matched rule {}",
                p.name,
                tool.map_or("", |t| &t.name),
                server.name,
                self.def.id,
            )
        } else if let Some(t) = tool {
            format!(
                "tool '{}' on server '{}', matched rule {}",
                t.name, server.name, self.def.id,
            )
        } else {
            format!(
                "server '{}' auth={}, matched rule {}",
                server.name,
                auth_to_string(&server.auth),
                self.def.id,
            )
        };

        let region = json_pointer
            .as_ref()
            .and_then(|ptr| ctx.region_for(ptr).cloned());

        Finding {
            id: self.def.id.clone(),
            title: self.def.title.clone(),
            severity: parse_severity(&self.def.severity).unwrap_or(Severity::Medium),
            confidence: parse_confidence(&self.def.confidence),
            category: parse_category(&self.def.category),
            description: self.def.description.clone(),
            exploit_scenario: self.def.exploit_scenario.clone(),
            evidence: vec![Evidence {
                location,
                description: raw_value.clone(),
                raw_value: Some(raw_value),
                region,
                file: Some(ctx.source_path.clone()),
                json_pointer,
                server: Some(server.name.clone()),
                tool: tool.map(|t| t.name.clone()),
                parameter: param.map(|p| p.name.clone()),
            }],
            remediation: self.def.remediation.clone(),
            cwe_ids: self.def.cwe_ids.clone(),
            owasp_ids: self.def.owasp_ids.clone(),
            owasp_mcp_ids: vec![],
        }
    }
}

impl Rule for CustomRule {
    fn id(&self) -> &'static str {
        leak_string(&self.def.id)
    }

    fn description(&self) -> &'static str {
        leak_string(&self.def.description)
    }

    fn category(&self) -> FindingCategory {
        parse_category(&self.def.category)
    }

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for server in &ctx.config.servers {
            if let Some(ref sm) = self.def.match_config.server {
                if !self.matches_server(sm, server) {
                    continue;
                }
            }

            if self.def.match_config.tool.is_none() && self.def.match_config.parameter.is_none() {
                findings.push(self.build_finding(server, None, None, ctx));
                continue;
            }

            for tool in &server.tools {
                if let Some(ref tm) = self.def.match_config.tool {
                    if !self.matches_tool(tm, tool) {
                        continue;
                    }
                }

                if self.def.match_config.parameter.is_none() {
                    findings.push(self.build_finding(server, Some(tool), None, ctx));
                    continue;
                }

                for param in &tool.parameters {
                    if let Some(ref pm) = self.def.match_config.parameter {
                        if !self.matches_parameter(pm, param) {
                            continue;
                        }
                    }
                    findings.push(self.build_finding(server, Some(tool), Some(param), ctx));
                }
            }
        }

        findings
    }

    fn explain(&self) -> &'static str {
        if self.def.rationale.is_empty() {
            leak_string(&self.def.description)
        } else {
            leak_string(&self.def.rationale)
        }
    }

    fn cwe_ids(&self) -> Vec<&'static str> {
        leak_strings(&self.def.cwe_ids)
    }

    fn owasp_ids(&self) -> Vec<&'static str> {
        leak_strings(&self.def.owasp_ids)
    }

    fn rationale(&self) -> &'static str {
        leak_string(&self.def.rationale)
    }

    fn references(&self) -> Vec<&'static str> {
        vec![]
    }
}

// ── Loading ─────────────────────────────────────────────────────────────────

/// Load a single custom rule from a YAML file.
pub fn load_custom_rule(path: &Path) -> Result<CustomRule, CustomRuleError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| CustomRuleError::Io(path.display().to_string(), e))?;
    let def: CustomRuleDefinition = serde_yaml::from_str(&content)
        .map_err(|e| CustomRuleError::Parse(path.display().to_string(), e.to_string()))?;
    CustomRule::new(def)
}

/// Load all custom rules from a directory (*.yaml, *.yml files).
/// Returns rules and any warnings for files that failed to load.
pub fn load_custom_rules_from_dir(
    dir: &Path,
) -> Result<(Vec<CustomRule>, Vec<String>), CustomRuleError> {
    let mut rules = Vec::new();
    let mut warnings = Vec::new();

    if !dir.is_dir() {
        return Ok((rules, warnings));
    }

    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| CustomRuleError::Io(dir.display().to_string(), e))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_lowercase();
            name.ends_with(".yaml") || name.ends_with(".yml")
        })
        .collect();

    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        match load_custom_rule(&entry.path()) {
            Ok(rule) => rules.push(rule),
            Err(e) => warnings.push(format!("Skipping {}: {}", entry.path().display(), e)),
        }
    }

    // Check for duplicate IDs
    let mut seen = std::collections::HashSet::new();
    for rule in &rules {
        if !seen.insert(rule.def.id.clone()) {
            warnings.push(format!(
                "Duplicate custom rule ID '{}' — later definition wins",
                rule.def.id
            ));
        }
    }

    Ok((rules, warnings))
}

/// Load custom rules from a path that may be a file or directory.
pub fn load_custom_rules(path: &Path) -> Result<(Vec<CustomRule>, Vec<String>), CustomRuleError> {
    if path.is_dir() {
        load_custom_rules_from_dir(path)
    } else {
        let rule = load_custom_rule(path)?;
        Ok((vec![rule], vec![]))
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_schema::{AuthConfig, McpConfig, McpServer, ToolDefinition, ToolParameter};
    use crate::scan_context::ScanContext;
    use std::collections::BTreeMap;

    fn make_server(name: &str, auth: AuthConfig, transport: &str) -> McpServer {
        McpServer {
            name: name.to_string(),
            description: String::new(),
            tools: vec![],
            auth,
            transport: transport.to_string(),
            url: None,
            command: None,
            args: vec![],
            env: BTreeMap::new(),
        }
    }

    fn make_tool(name: &str, desc: &str, params: Vec<ToolParameter>) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: desc.to_string(),
            parameters: params,
            tags: vec![],
            provenance: Default::default(),
        }
    }

    fn make_param(
        name: &str,
        ptype: &str,
        constraints: BTreeMap<String, serde_json::Value>,
    ) -> ToolParameter {
        ToolParameter {
            name: name.to_string(),
            param_type: ptype.to_string(),
            description: String::new(),
            required: false,
            constraints,
        }
    }

    fn make_ctx(servers: Vec<McpServer>) -> ScanContext {
        ScanContext::new(McpConfig { servers }, "test.json".to_string())
    }

    fn parse_rule(yaml: &str) -> CustomRule {
        let def: CustomRuleDefinition = serde_yaml::from_str(yaml).unwrap();
        CustomRule::new(def).unwrap()
    }

    // ── Glob matching tests ─────────────────────────────────────────────

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("prod-*", "prod-api"));
        assert!(glob_match("prod-*", "prod-"));
        assert!(!glob_match("prod-*", "dev-api"));
        assert!(!glob_match("prod-*", "production"));
    }

    #[test]
    fn glob_match_question_mark() {
        assert!(glob_match("prod-?", "prod-a"));
        assert!(!glob_match("prod-?", "prod-ab"));
        assert!(!glob_match("prod-?", "prod-"));
    }

    #[test]
    fn glob_match_alternatives() {
        assert!(glob_match("none|api_key", "none"));
        assert!(glob_match("none|api_key", "api_key"));
        assert!(!glob_match("none|api_key", "bearer"));
    }

    #[test]
    fn glob_match_case_insensitive() {
        assert!(glob_match("PROD-*", "prod-api"));
        assert!(glob_match("prod-*", "PROD-API"));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "helloo"));
        assert!(!glob_match("hello", "hell"));
    }

    #[test]
    fn glob_match_complex() {
        assert!(glob_match("*password*", "my_password_var"));
        assert!(glob_match("*password*", "password"));
        assert!(!glob_match("*password*", "pass"));
    }

    // ── Parsing tests ───────────────────────────────────────────────────

    #[test]
    fn parse_valid_rule() {
        let yaml = r#"
id: "TEST001"
title: "All servers must have authentication"
description: "MCP servers without authentication allow unauthorized access."
severity: high
confidence: high
category: static
rationale: "Unauthenticated servers are exposed."
remediation: "Add OAuth or API key authentication."
exploit_scenario: "Attacker discovers endpoint."
cwe_ids: ["CWE-306"]
owasp_ids: ["A07:2021"]
match:
  server:
    auth: "none"
"#;
        let rule = parse_rule(yaml);
        assert_eq!(rule.def.id, "TEST001");
        assert_eq!(rule.def.title, "All servers must have authentication");
        assert_eq!(rule.def.cwe_ids, vec!["CWE-306"]);
        assert_eq!(rule.def.owasp_ids, vec!["A07:2021"]);
    }

    #[test]
    fn parse_minimal_rule() {
        let yaml = r#"
id: "MIN001"
title: "Minimal rule"
description: "Just the required fields."
severity: low
match:
  server:
    auth: "none"
"#;
        let rule = parse_rule(yaml);
        assert_eq!(rule.def.confidence, "medium");
        assert_eq!(rule.def.category, "static");
        assert!(rule.def.rationale.is_empty());
        assert!(rule.def.cwe_ids.is_empty());
    }

    #[test]
    fn reject_mg_prefix() {
        let yaml = r#"
id: "MG999"
title: "Bad rule"
description: "Uses reserved prefix."
severity: high
match:
  server:
    auth: "none"
"#;
        let def: CustomRuleDefinition = serde_yaml::from_str(yaml).unwrap();
        let err = CustomRule::new(def).unwrap_err();
        assert!(matches!(err, CustomRuleError::ReservedId(_)));
    }

    #[test]
    fn reject_mg_prefix_lowercase() {
        let yaml = r#"
id: "mg100"
title: "Bad rule"
description: "Uses reserved prefix lowercase."
severity: high
match:
  server:
    auth: "none"
"#;
        let def: CustomRuleDefinition = serde_yaml::from_str(yaml).unwrap();
        let err = CustomRule::new(def).unwrap_err();
        assert!(matches!(err, CustomRuleError::ReservedId(_)));
    }

    #[test]
    fn reject_empty_id() {
        let yaml = r#"
id: ""
title: "Bad rule"
description: "Empty ID."
severity: high
match:
  server:
    auth: "none"
"#;
        let def: CustomRuleDefinition = serde_yaml::from_str(yaml).unwrap();
        let err = CustomRule::new(def).unwrap_err();
        assert!(matches!(err, CustomRuleError::MissingField(_)));
    }

    #[test]
    fn reject_invalid_severity() {
        let yaml = r#"
id: "TEST099"
title: "Bad severity"
description: "Invalid severity value."
severity: extreme
match:
  server:
    auth: "none"
"#;
        let def: CustomRuleDefinition = serde_yaml::from_str(yaml).unwrap();
        let err = CustomRule::new(def).unwrap_err();
        assert!(matches!(err, CustomRuleError::InvalidSeverity(_)));
    }

    // ── Match logic tests ───────────────────────────────────────────────

    #[test]
    fn match_server_auth_none() {
        let rule = parse_rule(
            r#"
id: "T001"
title: "No auth"
description: "Detect no auth"
severity: high
match:
  server:
    auth: "none"
"#,
        );
        let mut server = make_server("api", AuthConfig::None, "stdio");
        server.tools = vec![]; // no tools
        let ctx = make_ctx(vec![server]);
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "T001");
    }

    #[test]
    fn match_server_auth_oauth_no_match() {
        let rule = parse_rule(
            r#"
id: "T001"
title: "No auth"
description: "Detect no auth"
severity: high
match:
  server:
    auth: "none"
"#,
        );
        let server = make_server("api", AuthConfig::OAuth { scopes: vec![] }, "stdio");
        let ctx = make_ctx(vec![server]);
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn match_tool_name_glob() {
        let rule = parse_rule(
            r#"
id: "T002"
title: "Exec tools"
description: "Detect exec tools"
severity: critical
match:
  tool:
    name: "exec_*|run_*|shell_*"
"#,
        );
        let mut server = make_server("api", AuthConfig::None, "stdio");
        server.tools = vec![
            make_tool("exec_command", "Execute", vec![]),
            make_tool("list_files", "List files", vec![]),
            make_tool("run_script", "Run script", vec![]),
        ];
        let ctx = make_ctx(vec![server]);
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 2);
        let ids: Vec<_> = findings
            .iter()
            .flat_map(|f| f.evidence.iter().map(|e| e.tool.clone()))
            .collect();
        assert!(ids.contains(&Some("exec_command".to_string())));
        assert!(ids.contains(&Some("run_script".to_string())));
    }

    #[test]
    fn match_parameter_unconstrained() {
        let rule = parse_rule(
            r#"
id: "T004"
title: "Unconstrained strings"
description: "Strings without constraints"
severity: medium
match:
  parameter:
    type: "string"
    unconstrained: true
"#,
        );
        let mut constrained = BTreeMap::new();
        constrained.insert("maxLength".to_string(), serde_json::json!(100));

        let mut server = make_server("api", AuthConfig::None, "stdio");
        server.tools = vec![make_tool(
            "query",
            "Query",
            vec![
                make_param("sql", "string", BTreeMap::new()), // unconstrained
                make_param("limit", "string", constrained),   // constrained
                make_param("count", "integer", BTreeMap::new()), // wrong type
            ],
        )];
        let ctx = make_ctx(vec![server]);
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence[0].parameter.as_deref(), Some("sql"));
    }

    #[test]
    fn match_env_pattern() {
        let rule = parse_rule(
            r#"
id: "T005"
title: "Hardcoded DB URLs"
description: "Database URLs should use env refs"
severity: critical
match:
  server:
    env:
      has_key: "*DATABASE*"
      value_matches: "postgres://*"
"#,
        );
        let mut server1 = make_server("db", AuthConfig::None, "stdio");
        server1.env.insert(
            "DATABASE_URL".to_string(),
            "postgres://admin:secret@db:5432/prod".to_string(),
        );

        let mut server2 = make_server("safe", AuthConfig::None, "stdio");
        server2
            .env
            .insert("DATABASE_URL".to_string(), "${DB_URL}".to_string());

        let ctx = make_ctx(vec![server1, server2]);
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence[0].server.as_deref(), Some("db"));
    }

    #[test]
    fn match_server_name_glob() {
        let rule = parse_rule(
            r#"
id: "T006"
title: "Prod servers"
description: "Production servers must use HTTPS"
severity: high
match:
  server:
    name: "prod-*|production-*"
    url: "http://*"
"#,
        );
        let mut server1 = make_server("prod-api", AuthConfig::None, "http");
        server1.url = Some("http://api.example.com".to_string());

        let mut server2 = make_server("dev-api", AuthConfig::None, "http");
        server2.url = Some("http://localhost:8080".to_string());

        let mut server3 = make_server("prod-db", AuthConfig::None, "http");
        server3.url = Some("https://db.example.com".to_string());

        let ctx = make_ctx(vec![server1, server2, server3]);
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence[0].server.as_deref(), Some("prod-api"));
    }

    #[test]
    fn load_from_directory() {
        let dir = std::env::temp_dir()
            .join("mcplint-custom-rule-test")
            .join(format!("{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let rules_yaml = [
            (
                "rule1.yaml",
                r#"
id: "LOAD001"
title: "Rule 1"
description: "First rule"
severity: high
match:
  server:
    auth: "none"
"#,
            ),
            (
                "rule2.yml",
                r#"
id: "LOAD002"
title: "Rule 2"
description: "Second rule"
severity: medium
match:
  tool:
    name: "exec_*"
"#,
            ),
            ("not_a_rule.txt", "this is not yaml"),
        ];

        for (name, content) in &rules_yaml {
            std::fs::write(dir.join(name), content).unwrap();
        }

        let (rules, warnings) = load_custom_rules_from_dir(&dir).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(warnings.is_empty());

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_id_warning() {
        let dir = std::env::temp_dir()
            .join("mcplint-dup-rule-test")
            .join(format!("{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let yaml = r#"
id: "DUP001"
title: "Duplicate"
description: "Duplicate rule"
severity: high
match:
  server:
    auth: "none"
"#;
        std::fs::write(dir.join("dup1.yaml"), yaml).unwrap();
        std::fs::write(dir.join("dup2.yaml"), yaml).unwrap();

        let (_rules, warnings) = load_custom_rules_from_dir(&dir).unwrap();
        assert!(warnings.iter().any(|w| w.contains("Duplicate")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rule_trait_impl() {
        let rule = parse_rule(
            r#"
id: "TRAIT001"
title: "Trait test"
description: "Testing trait impl"
severity: high
confidence: high
category: semantic
rationale: "Test rationale"
cwe_ids: ["CWE-001"]
owasp_ids: ["A01:2021"]
match:
  server:
    auth: "none"
"#,
        );
        assert_eq!(rule.id(), "TRAIT001");
        assert_eq!(rule.description(), "Testing trait impl");
        assert_eq!(rule.category(), FindingCategory::Semantic);
        assert_eq!(rule.explain(), "Test rationale");
        assert_eq!(rule.cwe_ids(), vec!["CWE-001"]);
        assert_eq!(rule.owasp_ids(), vec!["A01:2021"]);
        assert_eq!(rule.rationale(), "Test rationale");
    }

    #[test]
    fn finding_has_fingerprint() {
        let rule = parse_rule(
            r#"
id: "FP001"
title: "Fingerprint test"
description: "Testing fingerprint"
severity: high
match:
  server:
    auth: "none"
"#,
        );
        let server = make_server("api", AuthConfig::None, "stdio");
        let ctx = make_ctx(vec![server]);
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        let fp = findings[0].fingerprint();
        assert_eq!(fp.len(), 64);
    }

    #[test]
    fn server_plus_tool_match() {
        let rule = parse_rule(
            r#"
id: "ST001"
title: "Server + tool match"
description: "Both server and tool must match"
severity: high
match:
  server:
    name: "prod-*"
  tool:
    name: "exec_*"
"#,
        );
        let mut server = make_server("prod-api", AuthConfig::None, "stdio");
        server.tools = vec![
            make_tool("exec_cmd", "Execute", vec![]),
            make_tool("list_files", "List", vec![]),
        ];
        let ctx = make_ctx(vec![server]);
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence[0].tool.as_deref(), Some("exec_cmd"));
    }
}
