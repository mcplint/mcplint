use mcplint_core::{
    Confidence, Evidence, Finding, FindingCategory, Rule, ScanContext, Severity, ToolDefinition,
};
use std::collections::HashSet;

/// MG003: Explicit escalation chains (compositional).
/// Detects tool graphs that form source → amplifier → sink paths,
/// both within a single server and across servers in the same config scope.
pub struct Mg003EscalationChains;

// ── Capability model ──

/// Capability classes for escalation analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CapClass {
    /// Data read, file read, secret read.
    Source,
    /// Network egress, HTTP request, send capability.
    Egress,
    /// Exec, shell, eval, file-write, destructive actions.
    Sink,
}

/// A tool with its classified capabilities and provenance.
#[derive(Debug, Clone)]
struct ToolCap {
    server_name: String,
    tool_name: String,
    caps: HashSet<CapClass>,
    /// Keywords that triggered the classification (for evidence).
    signals: Vec<String>,
}

// Classification patterns — conservative to minimize false positives.

// SOURCE: tools that can read or access data.
const SOURCE_PATTERNS: &[&str] = &[
    "read", "get", "fetch", "query", "list", "search", "retrieve", "lookup", "load", "access",
    "view", "browse", "scan", "select", "find", "db", "secret",
];

// EGRESS: tools with network/send capability (potential exfiltration).
const EGRESS_PATTERNS: &[&str] = &[
    "http", "request", "fetch", "curl", "api", "send", "forward", "relay", "proxy", "webhook",
    "network", "post", "upload", "email", "notify", "push",
];

// SINK: tools that can write, execute, or destroy.
const SINK_PATTERNS: &[&str] = &[
    "write", "exec", "execute", "run", "shell", "command", "deploy", "delete", "remove", "install",
    "eval", "system", "spawn", "put", "modify", "insert", "drop",
];

/// Classify a single tool into capability classes.
fn classify_tool(tool: &ToolDefinition, server_name: &str) -> ToolCap {
    let combined = format!(
        "{} {} {}",
        tool.name.replace('_', " "),
        tool.description,
        tool.parameters
            .iter()
            .map(|p| format!("{} {}", p.name.replace('_', " "), p.description))
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_lowercase();

    let words: HashSet<&str> = combined
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();

    let mut caps = HashSet::new();
    let mut signals = Vec::new();

    for &p in SOURCE_PATTERNS {
        if words.contains(p) {
            caps.insert(CapClass::Source);
            signals.push(format!("source:{}", p));
            break;
        }
    }
    for &p in EGRESS_PATTERNS {
        if words.contains(p) {
            caps.insert(CapClass::Egress);
            signals.push(format!("egress:{}", p));
            break;
        }
    }
    for &p in SINK_PATTERNS {
        if words.contains(p) {
            caps.insert(CapClass::Sink);
            signals.push(format!("sink:{}", p));
            break;
        }
    }

    ToolCap {
        server_name: server_name.to_string(),
        tool_name: tool.name.clone(),
        caps,
        signals,
    }
}

/// Classify all tools across all servers.
fn classify_all(ctx: &ScanContext) -> Vec<ToolCap> {
    let mut all = Vec::new();
    for server in &ctx.config.servers {
        for tool in &server.tools {
            let tc = classify_tool(tool, &server.name);
            if !tc.caps.is_empty() {
                all.push(tc);
            }
        }
    }
    all
}

// ── Template matching ──

// Escalation template types (for documentation; matching is done via if-chains).
// T1: SOURCE + EGRESS (exfiltration)
// T2: SOURCE + EGRESS + SINK (full escalation)
// T3: SOURCE + SINK (local destructive)

/// Pick the best (most representative) tools for each capability class.
/// Returns up to `limit` tools, preferring tools from different servers.
fn pick_best<'a>(tools: &[&'a ToolCap], limit: usize) -> Vec<&'a ToolCap> {
    let mut seen_servers = HashSet::new();
    let mut result = Vec::new();

    // First pass: one tool per distinct server.
    for t in tools {
        if seen_servers.insert(&t.server_name) {
            result.push(*t);
            if result.len() >= limit {
                return result;
            }
        }
    }

    // Second pass: fill remaining with any tools.
    for t in tools {
        if result.len() >= limit {
            break;
        }
        if !result
            .iter()
            .any(|r: &&ToolCap| r.tool_name == t.tool_name && r.server_name == t.server_name)
        {
            result.push(*t);
        }
    }

    result
}

/// Check if a chain is cross-server (tools span more than one server).
fn is_cross_server(tools: &[&ToolCap]) -> bool {
    let servers: HashSet<&str> = tools.iter().map(|t| t.server_name.as_str()).collect();
    servers.len() > 1
}

/// Build evidence entries for the selected tools.
fn build_evidence(tools: &[&ToolCap], role: &str, ctx: &ScanContext) -> Vec<Evidence> {
    tools
        .iter()
        .map(|tc| {
            let server_pointer = ctx.server_pointer(&tc.server_name, "");
            let region = server_pointer
                .as_ref()
                .and_then(|ptr| ctx.region_for(ptr).cloned());

            Evidence {
                location: format!(
                    "{} > servers[{}] > tools[{}]",
                    ctx.source_path, tc.server_name, tc.tool_name
                ),
                description: format!(
                    "{} tool '{}' on server '{}' (signals: {})",
                    role,
                    tc.tool_name,
                    tc.server_name,
                    tc.signals.join(", ")
                ),
                raw_value: Some(format!(
                    "tool={}, server={}, role={}, matched_keywords=[{}]",
                    tc.tool_name,
                    tc.server_name,
                    role.to_lowercase(),
                    tc.signals.join(", ")
                )),
                region,
                file: Some(ctx.source_path.clone()),
                json_pointer: server_pointer,
                server: Some(tc.server_name.clone()),
                tool: Some(tc.tool_name.clone()),
                parameter: None,
            }
        })
        .collect()
}

impl Rule for Mg003EscalationChains {
    fn id(&self) -> &'static str {
        "MG003"
    }

    fn description(&self) -> &'static str {
        "Explicit escalation chains: detects tool graphs that form source → amplifier → sink \
         paths enabling data exfiltration or privilege escalation, both within and across servers."
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Compositional
    }

    fn explain(&self) -> &'static str {
        "MG003 performs compositional analysis across all tools in an MCP configuration to \
         identify escalation chains. It classifies each tool as a source (data access), \
         egress (network/send), or sink (write/execute) and detects when the config contains \
         tools forming dangerous combinations. Analysis covers both single-server and \
         cross-server chains — if Server A provides data read, Server B provides network \
         egress, and Server C provides exec, the combined config enables a full attack chain. \
         Templates: T1 (exfiltration: source+egress), T2 (full chain: source+egress+sink), \
         T3 (local destructive: source+sink with exec/eval/write). All applicable templates \
         are reported independently. Remediation: remove unnecessary tool combinations, add \
         explicit authorization between tool invocations, restrict egress, or split configs \
         into separate trust domains."
    }

    fn cwe_ids(&self) -> Vec<&'static str> {
        vec!["CWE-269", "CWE-284"]
    }

    fn owasp_ids(&self) -> Vec<&'static str> {
        vec!["A01:2021"]
    }

    fn owasp_mcp_ids(&self) -> Vec<&'static str> {
        vec!["MCP02:2025", "MCP03:2025"]
    }

    fn rationale(&self) -> &'static str {
        "Composing tools across servers can create privilege escalation paths not visible in isolation."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://cwe.mitre.org/data/definitions/269.html"]
    }

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let all_tools = classify_all(ctx);
        if all_tools.len() < 2 {
            return vec![];
        }

        // Build per-class buckets.
        let sources: Vec<&ToolCap> = all_tools
            .iter()
            .filter(|t| t.caps.contains(&CapClass::Source))
            .collect();
        let egresses: Vec<&ToolCap> = all_tools
            .iter()
            .filter(|t| t.caps.contains(&CapClass::Egress))
            .collect();
        let sinks: Vec<&ToolCap> = all_tools
            .iter()
            .filter(|t| t.caps.contains(&CapClass::Sink))
            .collect();

        // Require at least 2 distinct tools across all buckets to avoid self-chain noise.
        let all_candidates: Vec<&ToolCap> = sources
            .iter()
            .chain(egresses.iter())
            .chain(sinks.iter())
            .copied()
            .collect();
        let distinct: HashSet<(&str, &str)> = all_candidates
            .iter()
            .map(|t| (t.server_name.as_str(), t.tool_name.as_str()))
            .collect();
        if distinct.len() < 2 {
            return vec![];
        }

        let mut findings = Vec::new();

        // Emit findings for all applicable templates.

        // T2: Full chain (SOURCE + EGRESS + SINK)
        if !sources.is_empty() && !egresses.is_empty() && !sinks.is_empty() {
            let src_pick = pick_best(&sources, 3);
            let egr_pick = pick_best(&egresses, 3);
            let snk_pick = pick_best(&sinks, 3);

            let all_picks: Vec<&ToolCap> = src_pick
                .iter()
                .chain(egr_pick.iter())
                .chain(snk_pick.iter())
                .copied()
                .collect();
            let cross = is_cross_server(&all_picks);
            let scope = if cross {
                "cross-server"
            } else {
                "single-server"
            };

            let src_desc = format_tool_list(&src_pick);
            let egr_desc = format_tool_list(&egr_pick);
            let snk_desc = format_tool_list(&snk_pick);

            let mut evidence = Vec::new();
            evidence.extend(build_evidence(&src_pick, "Source", ctx));
            evidence.extend(build_evidence(&egr_pick, "Egress", ctx));
            evidence.extend(build_evidence(&snk_pick, "Sink", ctx));

            findings.push(Finding {
                id: "MG003".to_string(),
                title: format!("Full escalation chain detected ({})", scope),
                severity: Severity::Critical,
                confidence: Confidence::Medium,
                category: FindingCategory::Compositional,
                description: format!(
                    "The MCP configuration contains a complete source → egress → sink \
                     escalation chain across {} tools. Sources: [{}]. Egress: [{}]. \
                     Sinks: [{}]. This combination allows data to be read, exfiltrated \
                     over the network, and used for arbitrary writes or command execution.",
                    scope, src_desc, egr_desc, snk_desc
                ),
                exploit_scenario: format!(
                    "An attacker chains: (1) use source tool(s) [{}] to access sensitive \
                     data, (2) use egress tool(s) [{}] to exfiltrate data to an external \
                     server, (3) use sink tool(s) [{}] to write, execute, or deploy \
                     malicious payloads — achieving full data exfiltration and code execution.",
                    src_desc, egr_desc, snk_desc
                ),
                evidence,
                cwe_ids: vec!["CWE-269".to_string(), "CWE-284".to_string()],
                owasp_ids: vec!["A01:2021".to_string()],
                owasp_mcp_ids: vec![],
                remediation: format!(
                    "Break the {} escalation chain: restrict egress tools to approved \
                     destinations, scope source tools to non-sensitive data, remove \
                     unnecessary exec/write sinks, add authorization gates between \
                     tools, or split into separate configs with distinct trust domains.",
                    scope
                ),
            });
        }

        // T1: Exfiltration (SOURCE + EGRESS, no sink needed)
        if !sources.is_empty() && !egresses.is_empty() {
            let src_pick = pick_best(&sources, 3);
            let egr_pick = pick_best(&egresses, 3);

            let all_picks: Vec<&ToolCap> =
                src_pick.iter().chain(egr_pick.iter()).copied().collect();
            let cross = is_cross_server(&all_picks);
            let scope = if cross {
                "cross-server"
            } else {
                "single-server"
            };

            let src_desc = format_tool_list(&src_pick);
            let egr_desc = format_tool_list(&egr_pick);

            let mut evidence = Vec::new();
            evidence.extend(build_evidence(&src_pick, "Source", ctx));
            evidence.extend(build_evidence(&egr_pick, "Egress", ctx));

            findings.push(Finding {
                id: "MG003".to_string(),
                title: format!("Exfiltration chain detected ({})", scope),
                severity: Severity::High,
                confidence: Confidence::Medium,
                category: FindingCategory::Compositional,
                description: format!(
                    "The MCP configuration contains a {} source → egress chain. \
                     Sources: [{}]. Egress: [{}]. Data can be read and sent to \
                     external destinations without restriction.",
                    scope, src_desc, egr_desc
                ),
                exploit_scenario: format!(
                    "An attacker uses source tool(s) [{}] to access sensitive data, \
                     then uses egress tool(s) [{}] to send the data to an attacker-controlled \
                     server, achieving data exfiltration.",
                    src_desc, egr_desc
                ),
                evidence,
                cwe_ids: vec!["CWE-269".to_string(), "CWE-284".to_string()],
                owasp_ids: vec!["A01:2021".to_string()],
                owasp_mcp_ids: vec![],
                remediation: format!(
                    "Break the {} exfiltration chain: restrict egress tools to \
                     approved destinations, scope source tools to non-sensitive data, \
                     or require user confirmation for network operations.",
                    scope
                ),
            });
        }

        // T3: Local destructive (SOURCE + SINK with exec/eval/write)
        if !sources.is_empty() && !sinks.is_empty() {
            let src_pick = pick_best(&sources, 3);
            let snk_pick = pick_best(&sinks, 3);

            let all_picks: Vec<&ToolCap> =
                src_pick.iter().chain(snk_pick.iter()).copied().collect();
            let cross = is_cross_server(&all_picks);
            let scope = if cross {
                "cross-server"
            } else {
                "single-server"
            };

            let src_desc = format_tool_list(&src_pick);
            let snk_desc = format_tool_list(&snk_pick);

            let mut evidence = Vec::new();
            evidence.extend(build_evidence(&src_pick, "Source", ctx));
            evidence.extend(build_evidence(&snk_pick, "Sink", ctx));

            findings.push(Finding {
                id: "MG003".to_string(),
                title: format!("Local destructive chain detected ({})", scope),
                severity: Severity::High,
                confidence: Confidence::Medium,
                category: FindingCategory::Compositional,
                description: format!(
                    "The MCP configuration contains a {} source → sink chain. \
                     Sources: [{}]. Sinks: [{}]. Data can be read and used to \
                     drive write, execute, or destructive operations.",
                    scope, src_desc, snk_desc
                ),
                exploit_scenario: format!(
                    "An attacker uses source tool(s) [{}] to read sensitive data or \
                     configuration, then uses sink tool(s) [{}] to write malicious \
                     files, execute commands, or destroy data.",
                    src_desc, snk_desc
                ),
                evidence,
                cwe_ids: vec!["CWE-269".to_string(), "CWE-284".to_string()],
                owasp_ids: vec!["A01:2021".to_string()],
                owasp_mcp_ids: vec![],
                remediation: format!(
                    "Break the {} destructive chain: scope source tools to \
                     non-sensitive data, restrict sink tools to safe operations, \
                     add authorization gates, or split into separate configs.",
                    scope
                ),
            });
        }

        findings
    }
}

/// Format a list of ToolCaps as "server/tool" strings for display.
fn format_tool_list(tools: &[&ToolCap]) -> String {
    tools
        .iter()
        .map(|t| format!("{}/{}", t.server_name, t.tool_name))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcplint_core::*;
    use std::collections::BTreeMap;

    fn make_server(name: &str, tools: Vec<ToolDefinition>) -> McpServer {
        McpServer {
            name: name.into(),
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

    fn make_context(tools: Vec<ToolDefinition>) -> ScanContext {
        ScanContext::new(
            McpConfig {
                servers: vec![make_server("test-server", tools)],
            },
            "test.json".into(),
        )
    }

    fn make_multi_server_context(servers: Vec<McpServer>) -> ScanContext {
        ScanContext::new(McpConfig { servers }, "test.json".into())
    }

    fn tool(name: &str, desc: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.into(),
            description: desc.into(),
            parameters: vec![],
            tags: vec![],
            provenance: ToolProvenance::default(),
        }
    }

    #[test]
    fn detects_source_amplifier_sink_chain() {
        let ctx = make_context(vec![
            tool("read_database", "Read records from the database"),
            tool("http_request", "Send an HTTP request to any URL"),
            tool("execute_command", "Execute a shell command"),
        ]);

        let rule = Mg003EscalationChains;
        let findings = rule.check(&ctx);
        // Should find T2 (full chain), T1 (exfiltration), and T3 (local destructive)
        assert!(!findings.is_empty());
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "should have a Critical full-chain finding"
        );
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Full escalation chain")));
    }

    #[test]
    fn no_chain_with_only_sources() {
        let ctx = make_context(vec![
            tool("read_file", "Read a file"),
            tool("list_items", "List items"),
        ]);

        let rule = Mg003EscalationChains;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn cross_server_full_chain() {
        let ctx = make_multi_server_context(vec![
            make_server(
                "data-server",
                vec![tool("read_database", "Read records from the database")],
            ),
            make_server(
                "network-server",
                vec![tool("http_request", "Send an HTTP request to any URL")],
            ),
            make_server(
                "exec-server",
                vec![tool("execute_command", "Execute a shell command")],
            ),
        ]);

        let rule = Mg003EscalationChains;
        let findings = rule.check(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("cross-server")),
            "should detect a cross-server full chain"
        );
        // Evidence should reference all three servers in the full-chain finding.
        let full_chain = findings
            .iter()
            .find(|f| f.title.contains("Full escalation"))
            .unwrap();
        let servers_in_evidence: HashSet<&str> = full_chain
            .evidence
            .iter()
            .filter_map(|e| {
                let loc = &e.location;
                let start = loc.find("servers[")? + 8;
                let end = loc[start..].find(']')? + start;
                Some(&loc[start..end])
            })
            .collect();
        assert!(servers_in_evidence.contains("data-server"));
        assert!(servers_in_evidence.contains("network-server"));
        assert!(servers_in_evidence.contains("exec-server"));
    }

    #[test]
    fn cross_server_exfiltration() {
        let ctx = make_multi_server_context(vec![
            make_server(
                "db-server",
                vec![tool("read_secrets", "Read secret values from vault")],
            ),
            make_server(
                "net-server",
                vec![tool("send_email", "Send email to any address")],
            ),
        ]);

        let rule = Mg003EscalationChains;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Exfiltration chain"));
        assert!(findings[0].title.contains("cross-server"));
    }

    #[test]
    fn cross_server_local_destructive() {
        let ctx = make_multi_server_context(vec![
            make_server(
                "reader",
                vec![tool("read_config", "Read application configuration")],
            ),
            make_server(
                "writer",
                vec![tool("write_file", "Write content to a file on disk")],
            ),
        ]);

        let rule = Mg003EscalationChains;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Local destructive chain"));
    }

    #[test]
    fn no_chain_when_insufficient_tools() {
        let ctx = make_multi_server_context(vec![make_server(
            "lonely",
            vec![tool("do_math", "Calculate a result")],
        )]);

        let rule = Mg003EscalationChains;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn emits_all_applicable_chains() {
        // With source + egress + sink, should emit T2, T1, and T3
        let ctx = make_multi_server_context(vec![
            make_server(
                "s1",
                vec![
                    tool("read_db", "Read database"),
                    tool("list_files", "List files"),
                ],
            ),
            make_server(
                "s2",
                vec![
                    tool("http_post", "Send HTTP POST request"),
                    tool("send_data", "Send data to API"),
                ],
            ),
            make_server(
                "s3",
                vec![
                    tool("exec_cmd", "Execute shell command"),
                    tool("deploy_app", "Deploy application"),
                ],
            ),
        ]);

        let rule = Mg003EscalationChains;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 3, "Should emit T2, T1, and T3 findings");
        assert!(findings.iter().any(|f| f.title.contains("Full escalation")));
        assert!(findings.iter().any(|f| f.title.contains("Exfiltration")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Local destructive")));
    }

    #[test]
    fn safe_config_no_findings() {
        // Servers with only source-like tools, no egress or sink.
        let ctx = make_multi_server_context(vec![
            make_server(
                "analytics",
                vec![
                    tool("view_dashboard", "View analytics dashboard"),
                    tool("list_reports", "List generated reports"),
                ],
            ),
            make_server("search", vec![tool("search_docs", "Search documentation")]),
        ]);

        let rule = Mg003EscalationChains;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_false_positive_update_dataset() {
        // "update_dataset" should not classify as Source — "data" removed from patterns,
        // "dataset" is one word that doesn't match any source keyword
        let tc = classify_tool(&tool("update_dataset", "Update the training dataset"), "s1");
        assert!(
            !tc.caps.contains(&CapClass::Source),
            "update_dataset should not be classified as Source"
        );
    }

    #[test]
    fn no_false_positive_create_report() {
        // "create" removed from sink patterns — "create_report" is benign
        let tc = classify_tool(
            &tool("create_report", "Generate a PDF report from data"),
            "s1",
        );
        assert!(
            !tc.caps.contains(&CapClass::Sink),
            "create_report should not be classified as Sink"
        );
    }

    #[test]
    fn read_database_is_source() {
        let tc = classify_tool(
            &tool("read_database", "Read records from the database"),
            "s1",
        );
        assert!(tc.caps.contains(&CapClass::Source));
    }

    #[test]
    fn evidence_has_raw_value() {
        let ctx = make_multi_server_context(vec![
            make_server(
                "db-server",
                vec![tool("read_secrets", "Read secret values from vault")],
            ),
            make_server(
                "net-server",
                vec![tool("send_email", "Send email to any address")],
            ),
        ]);

        let rule = Mg003EscalationChains;
        let findings = rule.check(&ctx);
        assert!(!findings.is_empty());
        for finding in &findings {
            for ev in &finding.evidence {
                assert!(
                    ev.raw_value.is_some(),
                    "Evidence should have raw_value with tool/server/role/keywords"
                );
                let rv = ev.raw_value.as_ref().unwrap();
                assert!(rv.contains("tool="), "raw_value should contain tool name");
                assert!(
                    rv.contains("server="),
                    "raw_value should contain server name"
                );
                assert!(rv.contains("role="), "raw_value should contain role");
            }
        }
    }
}
