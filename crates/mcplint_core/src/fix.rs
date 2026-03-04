//! Auto-fix engine for remediating MCP configuration findings.
//!
//! Supports auto-fixing rules MG001, MG004, MG005, and MG006.
//! Rules MG002 and MG003 require semantic understanding and are skipped.

use crate::finding::Finding;

/// Result of applying a single fix.
#[derive(Debug, Clone)]
pub struct FixResult {
    pub rule_id: String,
    pub description: String,
    pub applied: bool,
    pub requires_user_action: bool,
}

/// Engine that applies auto-fixes to MCP configuration JSON.
pub struct FixEngine;

impl FixEngine {
    /// Given original JSON content and a list of findings, produce a patched
    /// JSON string and a list of fix results.
    pub fn apply_fixes(
        content: &str,
        findings: &[Finding],
    ) -> Result<(String, Vec<FixResult>), serde_json::Error> {
        let mut value: serde_json::Value = serde_json::from_str(content)?;
        let mut results = Vec::new();

        for finding in findings {
            let fix_result = match finding.id.as_str() {
                "MG001" => fix_mg001(&mut value, finding),
                "MG004" => fix_mg004(&mut value, finding),
                "MG005" => fix_mg005(&mut value, finding),
                "MG006" => fix_mg006(&mut value, finding),
                _ => None,
            };

            if let Some(result) = fix_result {
                results.push(result);
            }
        }

        let patched = serde_json::to_string_pretty(&value)?;
        Ok((patched, results))
    }
}

/// Navigate a serde_json::Value by JSON pointer, returning a mutable reference.
fn pointer_mut<'a>(
    value: &'a mut serde_json::Value,
    pointer: &str,
) -> Option<&'a mut serde_json::Value> {
    if pointer.is_empty() {
        return Some(value);
    }
    value.pointer_mut(pointer)
}

/// MG001: Add maxLength constraint to unbounded string parameters.
fn fix_mg001(value: &mut serde_json::Value, finding: &Finding) -> Option<FixResult> {
    let evidence = finding.evidence.first()?;
    let pointer = evidence.json_pointer.as_deref()?;
    if pointer.is_empty() {
        return None;
    }

    let param = pointer_mut(value, pointer)?;

    // Check if already constrained
    if let Some(obj) = param.as_object() {
        if let Some(max_len) = obj
            .get("maxLength")
            .or_else(|| obj.get("constraints").and_then(|c| c.get("maxLength")))
        {
            if let Some(n) = max_len.as_u64() {
                if n <= 10000 {
                    return None; // Already constrained
                }
            }
        }
    }

    // Add maxLength
    if let Some(obj) = param.as_object_mut() {
        obj.insert(
            "maxLength".to_string(),
            serde_json::Value::Number(1000.into()),
        );
    }

    let param_name = evidence.parameter.as_deref().unwrap_or("unknown");
    let tool_name = evidence.tool.as_deref().unwrap_or("unknown");

    Some(FixResult {
        rule_id: "MG001".to_string(),
        description: format!(
            "Added maxLength: 1000 to parameter '{}' on tool '{}'",
            param_name, tool_name
        ),
        applied: true,
        requires_user_action: false,
    })
}

/// MG004: Add allowedDirectories constraint to filesystem tools.
fn fix_mg004(value: &mut serde_json::Value, finding: &Finding) -> Option<FixResult> {
    let evidence = finding.evidence.first()?;
    let pointer = evidence.json_pointer.as_deref()?;
    if pointer.is_empty() {
        return None;
    }

    let param = pointer_mut(value, pointer)?;

    // Check if already constrained
    if let Some(obj) = param.as_object() {
        let has_constraint = obj.get("allowedDirectories").is_some()
            || obj.get("basePath").is_some()
            || obj
                .get("constraints")
                .and_then(|c| c.get("allowedDirectories").or_else(|| c.get("basePath")))
                .is_some();
        if has_constraint {
            return None;
        }
    }

    // Add allowedDirectories
    if let Some(obj) = param.as_object_mut() {
        obj.insert("allowedDirectories".to_string(), serde_json::json!(["."]));
    }

    let tool_name = evidence.tool.as_deref().unwrap_or("unknown");

    Some(FixResult {
        rule_id: "MG004".to_string(),
        description: format!("Added allowedDirectories: [\".\"] to tool '{}'", tool_name),
        applied: true,
        requires_user_action: false,
    })
}

/// MG005: Add auth placeholder to servers with no authentication.
fn fix_mg005(value: &mut serde_json::Value, finding: &Finding) -> Option<FixResult> {
    let evidence = finding.evidence.first()?;
    let pointer = evidence.json_pointer.as_deref()?;

    // MG005 env-var findings have /env/ in the pointer — skip those (not fixable)
    if pointer.contains("/env/") {
        return None;
    }

    // Navigate to the server entry. The pointer may be like /mcpServers/name or
    // /servers/0 or just the server-level pointer. We need to add "auth" to it.
    // If pointer ends with /auth, go to parent; otherwise add /auth ourselves.
    let (server_pointer, existing_auth) = if pointer.ends_with("/auth") {
        (pointer.trim_end_matches("/auth"), true)
    } else {
        (pointer, false)
    };

    let server = if server_pointer.is_empty() {
        Some(value as &mut serde_json::Value)
    } else {
        pointer_mut(value, server_pointer)
    };
    let server = server?;

    // Check if auth already exists and is non-None
    if existing_auth || server.get("auth").is_some() {
        if let Some(auth) = server.get("auth") {
            if let Some(obj) = auth.as_object() {
                let auth_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("none");
                if auth_type != "none" {
                    return None; // Already has real auth
                }
            }
        }
    }

    // Add bearer auth placeholder
    if let Some(obj) = server.as_object_mut() {
        obj.insert(
            "auth".to_string(),
            serde_json::json!({
                "type": "bearer",
                "token": "REPLACE_ME"
            }),
        );
    }

    let server_name = evidence.server.as_deref().unwrap_or("unknown");

    Some(FixResult {
        rule_id: "MG005".to_string(),
        description: format!(
            "Added bearer auth placeholder to server '{}' — replace REPLACE_ME with actual token",
            server_name
        ),
        applied: true,
        requires_user_action: true,
    })
}

/// MG006: Redact leaked metadata from descriptions.
fn fix_mg006(value: &mut serde_json::Value, finding: &Finding) -> Option<FixResult> {
    let evidence = finding.evidence.first()?;
    let pointer = evidence.json_pointer.as_deref()?;
    if pointer.is_empty() {
        return None;
    }

    let target = pointer_mut(value, pointer)?;

    // Try to find and redact in description field
    let redacted = if let Some(obj) = target.as_object_mut() {
        redact_in_object(obj)
    } else if let Some(s) = target.as_str() {
        let redacted_str = redact_sensitive(s);
        if redacted_str != s {
            *target = serde_json::Value::String(redacted_str);
            true
        } else {
            false
        }
    } else {
        false
    };

    if !redacted {
        return None;
    }

    let tool_name = evidence.tool.as_deref().unwrap_or("unknown");

    Some(FixResult {
        rule_id: "MG006".to_string(),
        description: format!(
            "Redacted sensitive metadata from tool '{}' description",
            tool_name
        ),
        applied: true,
        requires_user_action: false,
    })
}

/// Try to redact sensitive content in object's description field.
fn redact_in_object(obj: &mut serde_json::Map<String, serde_json::Value>) -> bool {
    if let Some(desc) = obj.get("description").and_then(|v| v.as_str()) {
        let redacted = redact_sensitive(desc);
        if redacted != desc {
            obj.insert(
                "description".to_string(),
                serde_json::Value::String(redacted),
            );
            return true;
        }
    }
    false
}

/// Replace sensitive patterns with [REDACTED].
fn redact_sensitive(input: &str) -> String {
    use regex::Regex;

    let patterns: &[&str] = &[
        // Connection strings
        r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)://\S+",
        // AWS ARNs
        r"arn:aws:\w+:\w*:\d*:\S+",
        // Internal IPs
        r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[\w/.:?&=-]*",
        // Bare private IPs
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        // Absolute paths
        r"(?:/(?:home|var|etc|usr|opt|tmp|srv|root|mnt|data|app|lib|bin)[/\w.-]+)",
        // Windows paths
        r"[A-Z]:\\[\w\\.-]+",
    ];

    let mut result = input.to_string();
    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            result = re.replace_all(&result, "[REDACTED]").to_string();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, Evidence, FindingCategory, Severity};

    fn make_finding(
        rule_id: &str,
        pointer: &str,
        server: &str,
        tool: &str,
        param: &str,
    ) -> Finding {
        Finding {
            id: rule_id.to_string(),
            title: format!("{} finding", rule_id),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "test".to_string(),
            exploit_scenario: "test".to_string(),
            evidence: vec![Evidence {
                location: "test".to_string(),
                description: "test".to_string(),
                raw_value: None,
                region: None,
                file: None,
                json_pointer: Some(pointer.to_string()),
                server: if server.is_empty() {
                    None
                } else {
                    Some(server.to_string())
                },
                tool: if tool.is_empty() {
                    None
                } else {
                    Some(tool.to_string())
                },
                parameter: if param.is_empty() {
                    None
                } else {
                    Some(param.to_string())
                },
            }],
            remediation: "test".to_string(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        }
    }

    #[test]
    fn mg001_adds_max_length() {
        let json = r#"{
  "tools": [
    {
      "name": "run_query",
      "description": "Execute SQL",
      "parameters": [
        {
          "name": "query",
          "type": "string",
          "required": true
        }
      ]
    }
  ]
}"#;
        let finding = make_finding("MG001", "/tools/0/parameters/0", "", "run_query", "query");
        let (patched, results) = FixEngine::apply_fixes(json, &[finding]).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].applied);
        assert!(!results[0].requires_user_action);

        let val: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(
            val["tools"][0]["parameters"][0]["maxLength"],
            serde_json::json!(1000)
        );
    }

    #[test]
    fn mg001_skips_already_constrained() {
        let json = r#"{
  "tools": [
    {
      "name": "run_query",
      "parameters": [
        {
          "name": "query",
          "type": "string",
          "maxLength": 500
        }
      ]
    }
  ]
}"#;
        let finding = make_finding("MG001", "/tools/0/parameters/0", "", "run_query", "query");
        let (_, results) = FixEngine::apply_fixes(json, &[finding]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn mg004_adds_allowed_directories() {
        let json = r#"{
  "tools": [
    {
      "name": "read_file",
      "parameters": [
        {
          "name": "path",
          "type": "string"
        }
      ]
    }
  ]
}"#;
        let finding = make_finding("MG004", "/tools/0/parameters/0", "", "read_file", "path");
        let (patched, results) = FixEngine::apply_fixes(json, &[finding]).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].applied);

        let val: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(
            val["tools"][0]["parameters"][0]["allowedDirectories"],
            serde_json::json!(["."])
        );
    }

    #[test]
    fn mg005_adds_auth_placeholder() {
        let json = r#"{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["server.js"]
    }
  }
}"#;
        let finding = make_finding("MG005", "/mcpServers/my-server", "my-server", "", "");
        let (patched, results) = FixEngine::apply_fixes(json, &[finding]).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].applied);
        assert!(results[0].requires_user_action);

        let val: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(val["mcpServers"]["my-server"]["auth"]["type"], "bearer");
        assert_eq!(
            val["mcpServers"]["my-server"]["auth"]["token"],
            "REPLACE_ME"
        );
    }

    #[test]
    fn mg006_redacts_metadata() {
        let json = r#"{
  "tools": [
    {
      "name": "db_tool",
      "description": "Connects to postgresql://admin:pass@192.168.1.100/mydb"
    }
  ]
}"#;
        let finding = make_finding("MG006", "/tools/0", "", "db_tool", "");
        let (patched, results) = FixEngine::apply_fixes(json, &[finding]).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].applied);

        let val: serde_json::Value = serde_json::from_str(&patched).unwrap();
        let desc = val["tools"][0]["description"].as_str().unwrap();
        assert!(desc.contains("[REDACTED]"));
        assert!(!desc.contains("192.168"));
        assert!(!desc.contains("postgresql://"));
    }

    #[test]
    fn unfixable_rules_skipped() {
        let json = r#"{"tools": []}"#;
        let mg002 = make_finding("MG002", "/tools/0", "", "tool", "");
        let mg003 = make_finding("MG003", "/tools/0", "", "tool", "");
        let (patched, results) = FixEngine::apply_fixes(json, &[mg002, mg003]).unwrap();
        assert!(results.is_empty());
        // Content should be unchanged (ignoring formatting)
        let orig: serde_json::Value = serde_json::from_str(json).unwrap();
        let new: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(orig, new);
    }

    #[test]
    fn idempotent_application() {
        let json = r#"{
  "tools": [
    {
      "name": "run_query",
      "parameters": [
        {
          "name": "query",
          "type": "string",
          "maxLength": 1000,
          "allowedDirectories": ["."]
        }
      ]
    }
  ],
  "mcpServers": {
    "my-server": {
      "command": "node",
      "auth": { "type": "bearer", "token": "real-token" }
    }
  }
}"#;
        let findings = vec![
            make_finding("MG001", "/tools/0/parameters/0", "", "run_query", "query"),
            make_finding("MG004", "/tools/0/parameters/0", "", "read_file", "path"),
            make_finding("MG005", "/mcpServers/my-server", "my-server", "", ""),
        ];
        let (_, results) = FixEngine::apply_fixes(json, &findings).unwrap();
        assert!(
            results.is_empty(),
            "Already-fixed config should produce no fixes"
        );
    }

    #[test]
    fn empty_pointer_gracefully_skipped() {
        let json = r#"{"tools": []}"#;
        let finding = make_finding("MG001", "", "", "tool", "param");
        let (_, results) = FixEngine::apply_fixes(json, &[finding]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn missing_pointer_gracefully_skipped() {
        let json = r#"{"tools": []}"#;
        let mut finding = make_finding("MG001", "/nonexistent/path", "", "tool", "param");
        finding.evidence[0].json_pointer = Some("/nonexistent/0".to_string());
        let (_, results) = FixEngine::apply_fixes(json, &[finding]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn no_findings_no_changes() {
        let json = r#"{"tools": [], "servers": []}"#;
        let (patched, results) = FixEngine::apply_fixes(json, &[]).unwrap();
        assert!(results.is_empty());
        let orig: serde_json::Value = serde_json::from_str(json).unwrap();
        let new: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(orig, new);
    }

    #[test]
    fn mixed_fixes() {
        let json = r#"{
  "mcpServers": {
    "db-server": {
      "command": "node",
      "args": ["server.js"]
    }
  },
  "tools": [
    {
      "name": "run_query",
      "description": "Runs SQL at postgresql://admin:pass@10.0.0.1/db",
      "parameters": [
        {
          "name": "query",
          "type": "string"
        },
        {
          "name": "path",
          "type": "string"
        }
      ]
    }
  ]
}"#;
        let findings = vec![
            make_finding(
                "MG001",
                "/tools/0/parameters/0",
                "db-server",
                "run_query",
                "query",
            ),
            make_finding(
                "MG004",
                "/tools/0/parameters/1",
                "db-server",
                "run_query",
                "path",
            ),
            make_finding("MG005", "/mcpServers/db-server", "db-server", "", ""),
            make_finding("MG006", "/tools/0", "db-server", "run_query", ""),
        ];
        let (patched, results) = FixEngine::apply_fixes(json, &findings).unwrap();
        assert_eq!(results.len(), 4, "All four rules should produce fixes");

        let val: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(val["tools"][0]["parameters"][0]["maxLength"], 1000);
        assert_eq!(
            val["tools"][0]["parameters"][1]["allowedDirectories"],
            serde_json::json!(["."])
        );
        assert_eq!(val["mcpServers"]["db-server"]["auth"]["type"], "bearer");
        assert!(val["tools"][0]["description"]
            .as_str()
            .unwrap()
            .contains("[REDACTED]"));
    }

    #[test]
    fn redact_sensitive_patterns() {
        assert!(redact_sensitive("path is /home/user/.ssh/key").contains("[REDACTED]"));
        assert!(redact_sensitive("host at 192.168.1.100").contains("[REDACTED]"));
        assert!(redact_sensitive("arn:aws:iam::123456:role/admin").contains("[REDACTED]"));
        assert!(redact_sensitive("db at postgresql://u:p@host/db").contains("[REDACTED]"));
        assert_eq!(redact_sensitive("safe description"), "safe description");
    }
}
