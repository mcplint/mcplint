//! Baseline creation, diffing, and drift detection for MCP configurations.
//!
//! A baseline captures a deterministic fingerprint of an MCP configuration
//! so that future scans can detect capability drift ("rug-pull" detection).

use crate::mcp_schema::{McpConfig, McpServer, ToolDefinition, ToolParameter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// ── Baseline types ──

/// Top-level baseline artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Schema version (always 1 for now).
    pub version: u32,
    /// ISO 8601 timestamp when baseline was created (excluded from comparisons).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Source metadata (excluded from comparisons).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<BaselineSource>,
    /// Servers in deterministic order.
    pub servers: Vec<BaselineServer>,
}

/// Source metadata (informational, not compared).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSource {
    pub adapter: String,
    pub path: String,
}

/// Fingerprint of a single MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineServer {
    pub server_id: String,
    pub name: String,
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    pub tools: Vec<BaselineTool>,
    pub server_fingerprint: String,
}

/// Fingerprint of a single tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineTool {
    pub tool_id: String,
    pub name: String,
    pub description_fingerprint: String,
    pub schema_fingerprint: String,
    pub capability_flags: Vec<String>,
    pub sinks: Vec<String>,
    pub tool_fingerprint: String,
}

// ── Capability flag keywords ──

const EXEC_KEYWORDS: &[&str] = &[
    "exec", "execute", "eval", "run", "shell", "command", "cmd", "system", "spawn",
];
const FS_READ_KEYWORDS: &[&str] = &[
    "read_file",
    "read",
    "list_dir",
    "list_files",
    "glob",
    "search_files",
];
const FS_WRITE_KEYWORDS: &[&str] = &[
    "write_file",
    "write",
    "delete",
    "remove",
    "mkdir",
    "create_file",
];
const NET_KEYWORDS: &[&str] = &[
    "http", "fetch", "request", "curl", "api", "send", "webhook", "post", "upload", "download",
    "url",
];
const DB_KEYWORDS: &[&str] = &[
    "query",
    "sql",
    "database",
    "db",
    "select",
    "insert",
    "update",
    "delete_row",
];
const SECRETS_KEYWORDS: &[&str] = &["secret", "credential", "password", "token", "key", "auth"];

const SINK_CATEGORIES: &[(&str, &[&str])] = &[
    ("sql", &["query", "sql", "database"]),
    (
        "shell",
        &[
            "exec", "execute", "run", "shell", "command", "cmd", "system", "spawn",
        ],
    ),
    (
        "fs",
        &[
            "write_file",
            "write",
            "read_file",
            "read",
            "delete",
            "remove",
        ],
    ),
    (
        "http",
        &[
            "http", "fetch", "request", "curl", "send", "webhook", "post",
        ],
    ),
];

// ── Redaction patterns ──

/// Simple deterministic redaction of suspicious credential-like strings.
pub fn redact_secrets(s: &str) -> String {
    let mut result = s.to_string();
    // Token patterns: ghp_*, gho_*, ghs_*, ghu_*, github_pat_*, sk-*, xox*-*
    let token_prefixes = &[
        "ghp_",
        "gho_",
        "ghs_",
        "ghu_",
        "github_pat_",
        "sk-",
        "sk_live_",
        "sk_test_",
    ];
    for prefix in token_prefixes {
        if let Some(pos) = result.find(prefix) {
            let end = result[pos..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',')
                .map_or(result.len(), |e| pos + e);
            result.replace_range(pos..end, "REDACTED");
        }
    }
    // AWS access key: AKIA followed by 16 uppercase alphanumeric
    if let Some(pos) = result.find("AKIA") {
        let candidate = &result[pos..];
        if candidate.len() >= 20
            && candidate[4..20]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            result.replace_range(pos..pos + 20, "REDACTED");
        }
    }
    // Bearer tokens
    if let Some(pos) = result.to_lowercase().find("bearer ") {
        let start = pos + 7;
        let end = result[start..]
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .map_or(result.len(), |e| start + e);
        if end - start > 10 {
            result.replace_range(start..end, "REDACTED");
        }
    }
    result
}

/// Normalize whitespace: collapse runs of whitespace to single space, trim.
pub fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Normalize paths: replace user home with ~.
pub fn normalize_path(s: &str) -> String {
    if let Some(home) = home_dir_prefix() {
        s.replace(&home, "~")
    } else {
        s.to_string()
    }
}

fn home_dir_prefix() -> Option<String> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
}

// ── Hashing ──

/// Compute a hex-encoded SHA-256 hash.
pub fn fingerprint_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    // Format as hex string manually to avoid hex crate dependency
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Capability inference ──

fn infer_capability_flags(tool: &ToolDefinition) -> Vec<String> {
    let combined = format!(
        "{} {} {}",
        tool.name,
        tool.description,
        tool.parameters
            .iter()
            .map(|p| format!("{} {}", p.name, p.description))
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_lowercase();

    let mut flags = BTreeSet::new();
    for kw in EXEC_KEYWORDS {
        if combined.contains(kw) {
            flags.insert("exec".to_string());
            break;
        }
    }
    for kw in FS_READ_KEYWORDS {
        if combined.contains(kw) {
            flags.insert("fs_read".to_string());
            break;
        }
    }
    for kw in FS_WRITE_KEYWORDS {
        if combined.contains(kw) {
            flags.insert("fs_write".to_string());
            break;
        }
    }
    for kw in NET_KEYWORDS {
        if combined.contains(kw) {
            flags.insert("net".to_string());
            break;
        }
    }
    for kw in DB_KEYWORDS {
        if combined.contains(kw) {
            flags.insert("db".to_string());
            break;
        }
    }
    for kw in SECRETS_KEYWORDS {
        if combined.contains(kw) {
            flags.insert("secrets".to_string());
            break;
        }
    }
    flags.into_iter().collect()
}

fn infer_sinks(tool: &ToolDefinition) -> Vec<String> {
    let combined = format!("{} {}", tool.name, tool.description).to_lowercase();
    let mut sinks = BTreeSet::new();
    for (category, keywords) in SINK_CATEGORIES {
        for kw in *keywords {
            if combined.contains(kw) {
                sinks.insert(category.to_string());
                break;
            }
        }
    }
    sinks.into_iter().collect()
}

fn schema_canonical(params: &[ToolParameter]) -> String {
    let mut parts: Vec<String> = params
        .iter()
        .map(|p| {
            let constraints: serde_json::Value =
                serde_json::to_value(&p.constraints).unwrap_or_default();
            format!("{}:{}:{}:{}", p.name, p.param_type, p.required, constraints)
        })
        .collect();
    parts.sort();
    parts.join("|")
}

// ── Baseline creation ──

/// Create a baseline tool from a ToolDefinition.
fn baseline_tool(tool: &ToolDefinition, server_id: &str) -> BaselineTool {
    let desc_norm = normalize_whitespace(&tool.description);
    let description_fingerprint = fingerprint_hash(desc_norm.as_bytes());
    let schema_canon = schema_canonical(&tool.parameters);
    let schema_fingerprint = fingerprint_hash(schema_canon.as_bytes());
    let capability_flags = infer_capability_flags(tool);
    let sinks = infer_sinks(tool);

    let tool_id_input = format!("{}|{}|{}", server_id, tool.name, schema_fingerprint);
    let tool_id = fingerprint_hash(tool_id_input.as_bytes());

    let fp_input = format!(
        "{}|{}|{}|{}",
        tool.name,
        description_fingerprint,
        schema_fingerprint,
        capability_flags.join(",")
    );
    let tool_fingerprint = fingerprint_hash(fp_input.as_bytes());

    BaselineTool {
        tool_id,
        name: tool.name.clone(),
        description_fingerprint,
        schema_fingerprint,
        capability_flags,
        sinks,
        tool_fingerprint,
    }
}

/// Create a baseline server from an McpServer.
fn baseline_server(server: &McpServer) -> BaselineServer {
    let transport = server.transport.to_lowercase();
    let command = server
        .command
        .as_deref()
        .map(|c| redact_secrets(&normalize_path(c)));
    let args: Vec<String> = server
        .args
        .iter()
        .map(|a| redact_secrets(&normalize_path(a)))
        .collect();

    let id_input = format!(
        "{}|{}|{}",
        transport,
        command.as_deref().unwrap_or(""),
        args.join("|")
    );
    let server_id = fingerprint_hash(id_input.as_bytes());

    let mut tools: Vec<BaselineTool> = server
        .tools
        .iter()
        .map(|t| baseline_tool(t, &server_id))
        .collect();
    tools.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.tool_id.cmp(&b.tool_id)));

    let fp_input = format!(
        "{}|{}|{}|{}",
        server.name,
        transport,
        command.as_deref().unwrap_or(""),
        tools
            .iter()
            .map(|t| t.tool_fingerprint.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    let server_fingerprint = fingerprint_hash(fp_input.as_bytes());

    BaselineServer {
        server_id,
        name: server.name.clone(),
        transport,
        command,
        args,
        tools,
        server_fingerprint,
    }
}

/// Create a baseline from an McpConfig.
pub fn create_baseline(config: &McpConfig, source: Option<BaselineSource>) -> Baseline {
    let mut servers: Vec<BaselineServer> = config.servers.iter().map(baseline_server).collect();
    servers.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.server_id.cmp(&b.server_id))
    });

    Baseline {
        version: 1,
        created_at: None,
        source,
        servers,
    }
}

// ── Diff types ──

/// Result of comparing two baselines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiff {
    pub added_servers: Vec<ServerChange>,
    pub removed_servers: Vec<ServerChange>,
    pub changed_servers: Vec<ServerDiff>,
    /// True if any risky drift was detected.
    pub has_risky_drift: bool,
}

/// A server that was added or removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerChange {
    pub server_id: String,
    pub name: String,
    pub transport: String,
    pub tool_count: usize,
}

/// Changes within a matched server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerDiff {
    pub server_id: String,
    pub name: String,
    pub transport_changed: Option<TransportChange>,
    pub added_tools: Vec<ToolChange>,
    pub removed_tools: Vec<ToolChange>,
    pub changed_tools: Vec<ToolDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportChange {
    pub from: String,
    pub to: String,
}

/// A tool that was added or removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolChange {
    pub tool_id: String,
    pub name: String,
    pub capability_flags: Vec<String>,
    pub sinks: Vec<String>,
}

/// Changes within a matched tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDiff {
    pub tool_id: String,
    pub name: String,
    pub description_changed: bool,
    pub schema_changed: bool,
    pub capability_flags_added: Vec<String>,
    pub capability_flags_removed: Vec<String>,
    pub sinks_added: Vec<String>,
    pub sinks_removed: Vec<String>,
}

// ── Risky capability flags ──
const RISKY_FLAGS: &[&str] = &["exec", "fs_write", "net", "db"];

impl BaselineDiff {
    pub fn is_empty(&self) -> bool {
        self.added_servers.is_empty()
            && self.removed_servers.is_empty()
            && self.changed_servers.is_empty()
    }
}

impl fmt::Display for BaselineDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return writeln!(f, "No drift detected.");
        }

        for s in &self.added_servers {
            writeln!(
                f,
                "  + server '{}' ({}, {} tools)",
                s.name, s.transport, s.tool_count
            )?;
        }
        for s in &self.removed_servers {
            writeln!(
                f,
                "  - server '{}' ({}, {} tools)",
                s.name, s.transport, s.tool_count
            )?;
        }
        for s in &self.changed_servers {
            writeln!(f, "  ~ server '{}':", s.name)?;
            if let Some(tc) = &s.transport_changed {
                writeln!(f, "      transport: {} → {}", tc.from, tc.to)?;
            }
            for t in &s.added_tools {
                writeln!(
                    f,
                    "      + tool '{}' [{}]",
                    t.name,
                    t.capability_flags.join(", ")
                )?;
            }
            for t in &s.removed_tools {
                writeln!(f, "      - tool '{}'", t.name)?;
            }
            for t in &s.changed_tools {
                write!(f, "      ~ tool '{}':", t.name)?;
                if t.description_changed {
                    write!(f, " description-changed")?;
                }
                if t.schema_changed {
                    write!(f, " schema-changed")?;
                }
                if !t.capability_flags_added.is_empty() {
                    write!(f, " +flags[{}]", t.capability_flags_added.join(","))?;
                }
                if !t.capability_flags_removed.is_empty() {
                    write!(f, " -flags[{}]", t.capability_flags_removed.join(","))?;
                }
                if !t.sinks_added.is_empty() {
                    write!(f, " +sinks[{}]", t.sinks_added.join(","))?;
                }
                writeln!(f)?;
            }
        }

        if self.has_risky_drift {
            writeln!(f, "\n⚠ Risky drift detected.")?;
        }
        Ok(())
    }
}

// ── Diff engine ──

/// Compute the diff between an old baseline and a new baseline.
pub fn diff_baselines(old: &Baseline, new: &Baseline) -> BaselineDiff {
    let old_map: BTreeMap<&str, &BaselineServer> =
        old.servers.iter().map(|s| (s.name.as_str(), s)).collect();
    let new_map: BTreeMap<&str, &BaselineServer> =
        new.servers.iter().map(|s| (s.name.as_str(), s)).collect();

    let mut added_servers = Vec::new();
    let mut removed_servers = Vec::new();
    let mut changed_servers = Vec::new();
    let mut has_risky_drift = false;

    // Added servers
    for (name, ns) in &new_map {
        if !old_map.contains_key(name) {
            let has_risky_tools = ns.tools.iter().any(|t| {
                t.capability_flags
                    .iter()
                    .any(|f| RISKY_FLAGS.contains(&f.as_str()))
            });
            if has_risky_tools {
                has_risky_drift = true;
            }
            added_servers.push(ServerChange {
                server_id: ns.server_id.clone(),
                name: ns.name.clone(),
                transport: ns.transport.clone(),
                tool_count: ns.tools.len(),
            });
        }
    }

    // Removed servers
    for (name, os) in &old_map {
        if !new_map.contains_key(name) {
            removed_servers.push(ServerChange {
                server_id: os.server_id.clone(),
                name: os.name.clone(),
                transport: os.transport.clone(),
                tool_count: os.tools.len(),
            });
        }
    }

    // Changed servers
    for (name, os) in &old_map {
        if let Some(ns) = new_map.get(name) {
            if os.server_fingerprint == ns.server_fingerprint {
                continue;
            }
            let transport_changed = if os.transport != ns.transport {
                if os.transport == "stdio" && (ns.transport == "http" || ns.transport == "sse") {
                    has_risky_drift = true;
                }
                Some(TransportChange {
                    from: os.transport.clone(),
                    to: ns.transport.clone(),
                })
            } else {
                None
            };

            let old_tools: BTreeMap<&str, &BaselineTool> =
                os.tools.iter().map(|t| (t.name.as_str(), t)).collect();
            let new_tools: BTreeMap<&str, &BaselineTool> =
                ns.tools.iter().map(|t| (t.name.as_str(), t)).collect();

            let mut added_tools = Vec::new();
            let mut removed_tools = Vec::new();
            let mut changed_tools = Vec::new();

            for (tname, nt) in &new_tools {
                if !old_tools.contains_key(tname) {
                    if nt
                        .capability_flags
                        .iter()
                        .any(|f| RISKY_FLAGS.contains(&f.as_str()))
                    {
                        has_risky_drift = true;
                    }
                    added_tools.push(ToolChange {
                        tool_id: nt.tool_id.clone(),
                        name: nt.name.clone(),
                        capability_flags: nt.capability_flags.clone(),
                        sinks: nt.sinks.clone(),
                    });
                }
            }

            for (tname, ot) in &old_tools {
                if !new_tools.contains_key(tname) {
                    removed_tools.push(ToolChange {
                        tool_id: ot.tool_id.clone(),
                        name: ot.name.clone(),
                        capability_flags: ot.capability_flags.clone(),
                        sinks: ot.sinks.clone(),
                    });
                }
            }

            for (tname, ot) in &old_tools {
                if let Some(nt) = new_tools.get(tname) {
                    if ot.tool_fingerprint == nt.tool_fingerprint {
                        continue;
                    }
                    let old_flags: BTreeSet<&str> =
                        ot.capability_flags.iter().map(|s| s.as_str()).collect();
                    let new_flags: BTreeSet<&str> =
                        nt.capability_flags.iter().map(|s| s.as_str()).collect();
                    let flags_added: Vec<String> = new_flags
                        .difference(&old_flags)
                        .map(|s| s.to_string())
                        .collect();
                    let flags_removed: Vec<String> = old_flags
                        .difference(&new_flags)
                        .map(|s| s.to_string())
                        .collect();

                    if flags_added
                        .iter()
                        .any(|f| RISKY_FLAGS.contains(&f.as_str()))
                    {
                        has_risky_drift = true;
                    }

                    let old_sinks: BTreeSet<&str> = ot.sinks.iter().map(|s| s.as_str()).collect();
                    let new_sinks: BTreeSet<&str> = nt.sinks.iter().map(|s| s.as_str()).collect();

                    changed_tools.push(ToolDiff {
                        tool_id: nt.tool_id.clone(),
                        name: nt.name.clone(),
                        description_changed: ot.description_fingerprint
                            != nt.description_fingerprint,
                        schema_changed: ot.schema_fingerprint != nt.schema_fingerprint,
                        capability_flags_added: flags_added,
                        capability_flags_removed: flags_removed,
                        sinks_added: new_sinks
                            .difference(&old_sinks)
                            .map(|s| s.to_string())
                            .collect(),
                        sinks_removed: old_sinks
                            .difference(&new_sinks)
                            .map(|s| s.to_string())
                            .collect(),
                    });
                }
            }

            added_tools.sort_by(|a, b| a.name.cmp(&b.name));
            removed_tools.sort_by(|a, b| a.name.cmp(&b.name));
            changed_tools.sort_by(|a, b| a.name.cmp(&b.name));

            if transport_changed.is_some()
                || !added_tools.is_empty()
                || !removed_tools.is_empty()
                || !changed_tools.is_empty()
            {
                changed_servers.push(ServerDiff {
                    server_id: ns.server_id.clone(),
                    name: ns.name.clone(),
                    transport_changed,
                    added_tools,
                    removed_tools,
                    changed_tools,
                });
            }
        }
    }

    added_servers.sort_by(|a, b| a.name.cmp(&b.name));
    removed_servers.sort_by(|a, b| a.name.cmp(&b.name));
    changed_servers.sort_by(|a, b| a.name.cmp(&b.name));

    BaselineDiff {
        added_servers,
        removed_servers,
        changed_servers,
        has_risky_drift,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_schema::*;

    fn make_tool(name: &str, desc: &str, params: Vec<(&str, &str)>) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: desc.to_string(),
            parameters: params
                .into_iter()
                .map(|(n, t)| ToolParameter {
                    name: n.to_string(),
                    param_type: t.to_string(),
                    description: String::new(),
                    required: true,
                    constraints: Default::default(),
                })
                .collect(),
            tags: vec![],
            provenance: ToolProvenance::Declared,
        }
    }

    fn make_server(name: &str, tools: Vec<ToolDefinition>) -> McpServer {
        McpServer {
            name: name.to_string(),
            description: String::new(),
            tools,
            auth: AuthConfig::None,
            transport: "stdio".to_string(),
            url: None,
            command: Some("npx".to_string()),
            args: vec!["-y".to_string(), format!("@mcp/server-{}", name)],
            env: Default::default(),
        }
    }

    #[test]
    fn fingerprint_hash_deterministic() {
        let a = fingerprint_hash(b"hello world");
        let b = fingerprint_hash(b"hello world");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // SHA-256 hex
    }

    #[test]
    fn fingerprint_hash_different_input() {
        let a = fingerprint_hash(b"hello");
        let b = fingerprint_hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn redaction_removes_github_token() {
        assert_eq!(redact_secrets("ghp_abc123def456ghi789jklmnop"), "REDACTED");
        assert_eq!(
            redact_secrets("prefix ghp_abc123def456ghi789jklmnop suffix"),
            "prefix REDACTED suffix"
        );
    }

    #[test]
    fn redaction_removes_openai_key() {
        assert_eq!(redact_secrets("sk-abc123def456ghi789jklmnop"), "REDACTED");
    }

    #[test]
    fn redaction_safe_strings_unchanged() {
        assert_eq!(redact_secrets("hello world"), "hello world");
        assert_eq!(redact_secrets("npx -y @mcp/server"), "npx -y @mcp/server");
    }

    #[test]
    fn normalize_whitespace_works() {
        assert_eq!(normalize_whitespace("  hello   world  "), "hello world");
        assert_eq!(normalize_whitespace("single"), "single");
    }

    #[test]
    fn baseline_creation_deterministic() {
        let config = McpConfig {
            servers: vec![make_server(
                "filesystem",
                vec![
                    make_tool("read_file", "Read a file", vec![("path", "string")]),
                    make_tool(
                        "write_file",
                        "Write a file",
                        vec![("path", "string"), ("content", "string")],
                    ),
                ],
            )],
        };
        let b1 = create_baseline(&config, None);
        let b2 = create_baseline(&config, None);

        let j1 = serde_json::to_string(&b1).unwrap();
        let j2 = serde_json::to_string(&b2).unwrap();
        assert_eq!(j1, j2);
    }

    #[test]
    fn server_id_stable() {
        let s = make_server("test", vec![]);
        let bs1 = baseline_server(&s);
        let bs2 = baseline_server(&s);
        assert_eq!(bs1.server_id, bs2.server_id);
    }

    #[test]
    fn tool_id_stable() {
        let t = make_tool("run_query", "Execute SQL", vec![("query", "string")]);
        let bt1 = baseline_tool(&t, "server123");
        let bt2 = baseline_tool(&t, "server123");
        assert_eq!(bt1.tool_id, bt2.tool_id);
    }

    #[test]
    fn capability_flags_inferred() {
        let t = make_tool(
            "execute_command",
            "Run a shell command",
            vec![("cmd", "string")],
        );
        let bt = baseline_tool(&t, "x");
        assert!(bt.capability_flags.contains(&"exec".to_string()));
    }

    #[test]
    fn sinks_inferred() {
        let t = make_tool("run_query", "Execute SQL query", vec![("sql", "string")]);
        let bt = baseline_tool(&t, "x");
        assert!(bt.sinks.contains(&"sql".to_string()));
    }

    #[test]
    fn diff_no_changes() {
        let config = McpConfig {
            servers: vec![make_server(
                "fs",
                vec![make_tool("read_file", "Read", vec![("path", "string")])],
            )],
        };
        let b = create_baseline(&config, None);
        let d = diff_baselines(&b, &b);
        assert!(d.is_empty());
        assert!(!d.has_risky_drift);
    }

    #[test]
    fn diff_detects_added_server() {
        let old = McpConfig { servers: vec![] };
        let new = McpConfig {
            servers: vec![make_server(
                "shell",
                vec![make_tool(
                    "exec",
                    "Execute command",
                    vec![("cmd", "string")],
                )],
            )],
        };
        let d = diff_baselines(&create_baseline(&old, None), &create_baseline(&new, None));
        assert_eq!(d.added_servers.len(), 1);
        assert_eq!(d.added_servers[0].name, "shell");
        assert!(d.has_risky_drift);
    }

    #[test]
    fn diff_detects_removed_server() {
        let old = McpConfig {
            servers: vec![make_server("fs", vec![])],
        };
        let new = McpConfig { servers: vec![] };
        let d = diff_baselines(&create_baseline(&old, None), &create_baseline(&new, None));
        assert_eq!(d.removed_servers.len(), 1);
    }

    #[test]
    fn diff_detects_added_tool_with_risky_flag() {
        let old_config = McpConfig {
            servers: vec![make_server(
                "db",
                vec![make_tool(
                    "read_query",
                    "Read data",
                    vec![("query", "string")],
                )],
            )],
        };
        let new_config = McpConfig {
            servers: vec![make_server(
                "db",
                vec![
                    make_tool("read_query", "Read data", vec![("query", "string")]),
                    make_tool(
                        "execute_command",
                        "Run shell command",
                        vec![("cmd", "string")],
                    ),
                ],
            )],
        };
        let d = diff_baselines(
            &create_baseline(&old_config, None),
            &create_baseline(&new_config, None),
        );
        assert_eq!(d.changed_servers.len(), 1);
        assert_eq!(d.changed_servers[0].added_tools.len(), 1);
        assert_eq!(d.changed_servers[0].added_tools[0].name, "execute_command");
        assert!(d.has_risky_drift);
    }

    #[test]
    fn diff_detects_capability_expansion() {
        let old_tool = make_tool("helper", "Read data safely", vec![("input", "string")]);
        let new_tool = make_tool(
            "helper",
            "Execute commands and read data",
            vec![("input", "string")],
        );
        let old = McpConfig {
            servers: vec![make_server("s", vec![old_tool])],
        };
        let new = McpConfig {
            servers: vec![make_server("s", vec![new_tool])],
        };
        let d = diff_baselines(&create_baseline(&old, None), &create_baseline(&new, None));
        assert!(!d.changed_servers.is_empty());
        let changed = &d.changed_servers[0].changed_tools;
        assert!(!changed.is_empty());
        assert!(changed[0].description_changed);
    }
}
