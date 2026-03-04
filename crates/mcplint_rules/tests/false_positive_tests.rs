//! False-positive regression tests.
//!
//! Verify that legitimate configurations do NOT produce false findings.
//! Each test scans a safe scenario and asserts zero findings from the relevant rule.

use mcplint_core::*;
use std::collections::BTreeMap;

fn make_server_with_tools(name: &str, tools: Vec<ToolDefinition>) -> McpServer {
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

fn make_server_with_env(name: &str, env: BTreeMap<String, String>) -> McpServer {
    McpServer {
        name: name.into(),
        description: "".into(),
        tools: vec![],
        auth: AuthConfig::None,
        transport: "stdio".into(),
        url: None,
        command: None,
        args: vec![],
        env,
    }
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

fn tool_with_params(name: &str, desc: &str, params: Vec<ToolParameter>) -> ToolDefinition {
    ToolDefinition {
        name: name.into(),
        description: desc.into(),
        parameters: params,
        tags: vec![],
        provenance: ToolProvenance::default(),
    }
}

fn ctx_from_servers(servers: Vec<McpServer>) -> ScanContext {
    ScanContext::new(McpConfig { servers }, "test.json".into())
}

fn run_rule(ctx: &ScanContext, rule_id: &str) -> Vec<Finding> {
    let registry = mcplint_rules::default_registry();
    registry
        .run_all(ctx)
        .into_iter()
        .filter(|f| f.id == rule_id)
        .collect()
}

// ── MG002: no false positive on derived word forms ──

#[test]
fn safe_tool_names_no_mg002() {
    // "thread_reader" should not match "read" claim keyword
    let ctx = ctx_from_servers(vec![make_server_with_tools(
        "s1",
        vec![tool("thread_reader", "Reads thread data from the forum")],
    )]);
    let findings = run_rule(&ctx, "MG002");
    assert!(
        findings.is_empty(),
        "thread_reader with read description is not over-permissioned"
    );
}

// ── MG003: no false positive on substring patterns ──

#[test]
fn safe_dataset_tool_no_mg003() {
    // "update_dataset" should not match Source via "data" substring
    // "create_report" should not match Sink via "create"
    let ctx = ctx_from_servers(vec![make_server_with_tools(
        "s1",
        vec![
            tool("update_dataset", "Update the training dataset"),
            tool("send_notification", "Send a push notification"),
        ],
    )]);
    let findings = run_rule(&ctx, "MG003");
    assert!(
        findings.is_empty(),
        "update_dataset + send_notification is not an escalation chain (no source)"
    );
}

// ── MG001: no false positive when properly constrained ──

#[test]
fn constrained_sql_no_mg001() {
    let mut constraints = BTreeMap::new();
    constraints.insert("maxLength".to_string(), serde_json::json!(200));
    constraints.insert("pattern".to_string(), serde_json::json!("^SELECT "));

    let ctx = ctx_from_servers(vec![make_server_with_tools(
        "s1",
        vec![tool_with_params(
            "run_query",
            "Execute a SQL query",
            vec![ToolParameter {
                name: "query".into(),
                param_type: "string".into(),
                description: "SQL query".into(),
                required: true,
                constraints,
            }],
        )],
    )]);
    let findings = run_rule(&ctx, "MG001");
    assert!(
        findings.is_empty(),
        "maxLength=200 + pattern constraint should suppress MG001"
    );
}

// ── MG009: no false positive for safe env vars ──

#[test]
fn safe_env_vars_no_mg009() {
    let env = BTreeMap::from([
        ("NODE_ENV".into(), "production".into()),
        ("PORT".into(), "3000".into()),
        ("LOG_LEVEL".into(), "debug".into()),
        ("RUST_LOG".into(), "info".into()),
    ]);
    let ctx = ctx_from_servers(vec![make_server_with_env("s1", env)]);
    let findings = run_rule(&ctx, "MG009");
    assert!(
        findings.is_empty(),
        "Safe env vars should not trigger MG009"
    );
}

// ── MG008: no false positive for localhost ──

#[test]
fn localhost_http_no_mg008() {
    let ctx = ctx_from_servers(vec![McpServer {
        name: "local".into(),
        description: "".into(),
        tools: vec![],
        auth: AuthConfig::None,
        transport: "stdio".into(),
        url: Some("http://localhost:3000".into()),
        command: None,
        args: vec![],
        env: BTreeMap::new(),
    }]);
    let findings = run_rule(&ctx, "MG008");
    assert!(
        findings.is_empty(),
        "localhost HTTP should not trigger MG008"
    );
}

// ── MG006: no false positive for public domain URLs ──

#[test]
fn documentation_url_no_mg006() {
    let ctx = ctx_from_servers(vec![make_server_with_tools(
        "s1",
        vec![tool(
            "api_client",
            "Connects to the API at https://api.example.com",
        )],
    )]);
    let findings = run_rule(&ctx, "MG006");
    assert!(
        findings.is_empty(),
        "Public URL https://api.example.com should not trigger MG006"
    );
}

// ── MG009: no false positive for public keys ──

#[test]
fn public_key_env_no_mg009() {
    let env = BTreeMap::from([("SSH_PUBLIC_KEY".into(), "ssh-rsa AAAA...".into())]);
    let ctx = ctx_from_servers(vec![make_server_with_env("s1", env)]);
    let findings: Vec<_> = run_rule(&ctx, "MG009")
        .into_iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();
    assert!(
        findings.is_empty(),
        "SSH_PUBLIC_KEY should not trigger Critical MG009"
    );
}

// ── MG005: no false positive for OAuth auth ──

#[test]
fn oauth_auth_no_mg005() {
    let ctx = ctx_from_servers(vec![McpServer {
        name: "oauth-server".into(),
        description: "".into(),
        tools: vec![],
        auth: AuthConfig::OAuth {
            scopes: vec!["read".into()],
        },
        transport: "stdio".into(),
        url: None,
        command: None,
        args: vec![],
        env: BTreeMap::new(),
    }]);
    let findings = run_rule(&ctx, "MG005");
    assert!(findings.is_empty(), "OAuth auth should not trigger MG005");
}

// ── MG003: create_report is not a sink ──

#[test]
fn create_report_no_mg003_sink() {
    let ctx = ctx_from_servers(vec![make_server_with_tools(
        "s1",
        vec![
            tool("read_data", "Read data from the database"),
            tool("send_email", "Send email to recipients"),
            tool("create_report", "Generate a PDF report"),
        ],
    )]);

    let findings = run_rule(&ctx, "MG003");
    // Should get T1 (exfiltration: read_data → send_email) but NOT T2 (full chain)
    // because create_report is not classified as Sink
    for f in &findings {
        assert!(
            !f.title.contains("Full escalation"),
            "create_report should not form a full chain — it's not a sink"
        );
    }
}
