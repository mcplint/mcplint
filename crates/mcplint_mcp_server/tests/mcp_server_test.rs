use std::io::Write;
use tempfile::NamedTempFile;

/// Helper to create a temp file with MCP config content and return the path.
fn write_temp_config(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::with_suffix(".tools.json").unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

const VULNERABLE_CONFIG: &str = r#"{
    "server_name": "unsafe-server",
    "tools": [{
        "name": "run_command",
        "description": "Execute arbitrary shell commands",
        "parameters": [
            { "name": "command", "type": "string", "required": true }
        ]
    }]
}"#;

const CLEAN_CONFIG: &str = r#"{
    "server_name": "safe-server",
    "tools": [{
        "name": "get_time",
        "description": "Returns the current UTC time",
        "parameters": []
    }]
}"#;

#[test]
fn test_server_construction() {
    let _server = mcplint_mcp_server::McplintServer::new();
}

#[tokio::test]
async fn test_scan_with_content() {
    let registry = mcplint_rules::default_registry();
    let result =
        mcplint_core::adapters::auto_load_content(VULNERABLE_CONFIG, "unsafe_scan.tools.json")
            .unwrap();

    let ctx = mcplint_core::ScanContext::new(result.config, "test".to_string());
    let findings = registry.run_all(&ctx);
    assert!(
        !findings.is_empty(),
        "Should find security issues in unsafe config"
    );
}

#[test]
fn test_scan_file_path() {
    let f = write_temp_config(VULNERABLE_CONFIG);
    let result = mcplint_core::adapters::auto_load(f.path()).unwrap();
    let registry = mcplint_rules::default_registry();
    let ctx = mcplint_core::ScanContext::new(result.config, "test".to_string());
    let findings = registry.run_all(&ctx);
    assert!(
        !findings.is_empty(),
        "Should find issues in unsafe file config"
    );
}

#[test]
fn test_clean_config_no_findings() {
    let result =
        mcplint_core::adapters::auto_load_content(CLEAN_CONFIG, "clean_test.tools.json").unwrap();
    let registry = mcplint_rules::default_registry();
    let ctx = mcplint_core::ScanContext::new(result.config, "test".to_string());
    let findings = registry.run_all(&ctx);
    // MG005 (weak auth) and MG008 (transport) may fire on minimal configs
    let ignored = ["MG005", "MG008"];
    let unexpected: Vec<_> = findings
        .iter()
        .filter(|f| !ignored.contains(&f.id.as_str()))
        .collect();
    for f in &unexpected {
        eprintln!("  UNEXPECTED: {} - {} ({})", f.id, f.title, f.severity);
    }
    assert!(
        unexpected.is_empty(),
        "Clean config should have no findings besides auth/transport"
    );
}

#[test]
fn test_list_rules_returns_all() {
    let registry = mcplint_rules::default_registry();
    let rules = registry.rules();
    assert!(
        rules.len() >= 9,
        "Should have at least 9 rules (MG001-MG009)"
    );

    for rule in rules {
        assert!(!rule.id().is_empty());
        assert!(!rule.description().is_empty());
        assert!(!rule.explain().is_empty());
    }
}

#[test]
fn test_explain_known_rule() {
    let registry = mcplint_rules::default_registry();
    let rule = registry.find_rule("MG001").expect("MG001 should exist");
    assert!(!rule.explain().is_empty());
    assert!(!rule.cwe_ids().is_empty());
    assert!(!rule.owasp_ids().is_empty());
    assert!(!rule.owasp_mcp_ids().is_empty());
}

#[test]
fn test_explain_unknown_rule() {
    let registry = mcplint_rules::default_registry();
    assert!(registry.find_rule("NONEXISTENT").is_none());
}

// ── Snapshot tests ──

#[test]
fn snapshot_list_rules_structure() {
    let registry = mcplint_rules::default_registry();
    let rules: Vec<serde_json::Value> = registry
        .rules()
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id(),
                "description": r.description(),
                "category": r.category().to_string(),
                "cwe_ids": r.cwe_ids(),
                "owasp_ids": r.owasp_ids(),
                "owasp_mcp_ids": r.owasp_mcp_ids(),
            })
        })
        .collect();

    insta::assert_json_snapshot!("list_rules", rules);
}

#[test]
fn snapshot_explain_mg001() {
    let registry = mcplint_rules::default_registry();
    let rule = registry.find_rule("MG001").unwrap();
    let detail = serde_json::json!({
        "id": rule.id(),
        "description": rule.description(),
        "category": rule.category().to_string(),
        "rationale": rule.rationale(),
        "cwe_ids": rule.cwe_ids(),
        "owasp_ids": rule.owasp_ids(),
        "owasp_mcp_ids": rule.owasp_mcp_ids(),
        "references": rule.references(),
    });

    insta::assert_json_snapshot!("explain_mg001", detail);
}

#[test]
fn snapshot_explain_mg005() {
    let registry = mcplint_rules::default_registry();
    let rule = registry.find_rule("MG005").unwrap();
    let detail = serde_json::json!({
        "id": rule.id(),
        "description": rule.description(),
        "category": rule.category().to_string(),
        "rationale": rule.rationale(),
        "cwe_ids": rule.cwe_ids(),
        "owasp_ids": rule.owasp_ids(),
        "owasp_mcp_ids": rule.owasp_mcp_ids(),
        "references": rule.references(),
    });

    insta::assert_json_snapshot!("explain_mg005", detail);
}

#[test]
fn snapshot_scan_vulnerable_config() {
    let registry = mcplint_rules::default_registry();
    let result =
        mcplint_core::adapters::auto_load_content(VULNERABLE_CONFIG, "test.tools.json").unwrap();
    let ctx = mcplint_core::ScanContext::new(result.config, "test".to_string());
    let findings = registry.run_all(&ctx);

    // Snapshot finding IDs, severities, and MCP threat IDs (stable across runs)
    let summary: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.to_string(),
                "cwe_ids": f.cwe_ids,
                "owasp_ids": f.owasp_ids,
                "owasp_mcp_ids": f.owasp_mcp_ids,
            })
        })
        .collect();

    insta::assert_json_snapshot!("scan_vulnerable_findings", summary);
}

#[test]
fn snapshot_scan_json_output() {
    let result =
        mcplint_core::adapters::auto_load_content(VULNERABLE_CONFIG, "test.tools.json").unwrap();
    let registry = mcplint_rules::default_registry();
    let ctx = mcplint_core::ScanContext::new(result.config, "test".to_string());
    let findings = registry.run_all(&ctx);

    let output = mcplint_report::render(
        &findings,
        "test.tools.json",
        mcplint_report::OutputFormat::Json,
    );
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    // Verify JSON output is valid and contains expected structure
    let findings_arr = parsed["findings"].as_array().unwrap();
    assert!(!findings_arr.is_empty());

    // Every finding should have owasp_mcp_ids
    for finding in findings_arr {
        assert!(finding.get("id").is_some());
        assert!(finding.get("severity").is_some());
        assert!(
            finding.get("owasp_mcp_ids").is_some(),
            "Finding {} should have owasp_mcp_ids in JSON output",
            finding["id"]
        );
    }
}

#[test]
fn test_all_rules_have_owasp_mcp_ids() {
    let registry = mcplint_rules::default_registry();
    for rule in registry.rules() {
        let mcp_ids = rule.owasp_mcp_ids();
        assert!(
            !mcp_ids.is_empty(),
            "Rule {} should have OWASP MCP Top 10 mappings",
            rule.id()
        );
        for id in &mcp_ids {
            assert!(
                id.starts_with("MCP") && id.contains(":2025"),
                "Rule {} has malformed MCP ID: {}",
                rule.id(),
                id
            );
        }
    }
}

#[test]
fn test_scan_findings_inherit_owasp_mcp_ids() {
    let registry = mcplint_rules::default_registry();
    let result =
        mcplint_core::adapters::auto_load_content(VULNERABLE_CONFIG, "test.tools.json").unwrap();
    let ctx = mcplint_core::ScanContext::new(result.config, "test".to_string());
    let findings = registry.run_all(&ctx);

    for finding in &findings {
        assert!(
            !finding.owasp_mcp_ids.is_empty(),
            "Finding {} '{}' should have OWASP MCP IDs populated",
            finding.id,
            finding.title
        );
    }
}

#[test]
fn test_scan_sarif_output_has_mcp_ids() {
    let result =
        mcplint_core::adapters::auto_load_content(VULNERABLE_CONFIG, "test.tools.json").unwrap();
    let registry = mcplint_rules::default_registry();
    let ctx = mcplint_core::ScanContext::new(result.config, "test".to_string());
    let findings = registry.run_all(&ctx);

    let rules_meta: Vec<(String, String, String, String)> = registry
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
        .collect();

    let sarif = mcplint_report::render_sarif(&findings, "test.tools.json", "0.1.0", &rules_meta);
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

    // Check results have owasp_mcp_ids in properties
    let results = parsed["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty());
    for result in results {
        let mcp_ids = &result["properties"]["owaspMcpIds"];
        assert!(
            mcp_ids.is_array() && !mcp_ids.as_array().unwrap().is_empty(),
            "SARIF result for {} should have owaspMcpIds in properties",
            result["ruleId"]
        );
    }
}

#[test]
fn test_min_severity_filtering() {
    let registry = mcplint_rules::default_registry();
    let result =
        mcplint_core::adapters::auto_load_content(VULNERABLE_CONFIG, "test.tools.json").unwrap();
    let ctx = mcplint_core::ScanContext::new(result.config, "test".to_string());
    let all_findings = registry.run_all(&ctx);

    let critical_only: Vec<_> = all_findings
        .iter()
        .filter(|f| f.meets_threshold(mcplint_core::Severity::Critical))
        .collect();

    assert!(
        critical_only.len() < all_findings.len(),
        "Filtering by critical should return fewer findings than all"
    );
    assert!(
        !all_findings.is_empty(),
        "Should have findings in vulnerable config"
    );
}
