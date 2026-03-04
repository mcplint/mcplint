use crate::ScanSummary;
use mcplint_core::Finding;
use serde::Serialize;

#[derive(Serialize)]
struct JsonReport<'a> {
    source: &'a str,
    summary: JsonSummary,
    findings: Vec<JsonFinding<'a>>,
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    #[serde(flatten)]
    finding: &'a Finding,
    fingerprint: String,
}

#[derive(Serialize)]
struct JsonSummary {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

/// Render findings as JSON for CI and automation.
pub fn render(findings: &[Finding], source_path: &str) -> String {
    let summary = ScanSummary::from_findings(findings);
    let report = JsonReport {
        source: source_path,
        summary: JsonSummary {
            total: summary.total,
            critical: summary.critical,
            high: summary.high,
            medium: summary.medium,
            low: summary.low,
        },
        findings: findings
            .iter()
            .map(|f| JsonFinding {
                fingerprint: f.fingerprint(),
                finding: f,
            })
            .collect(),
    };

    serde_json::to_string_pretty(&report)
        .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcplint_core::*;

    #[test]
    fn json_output_is_valid() {
        let findings = vec![Finding {
            id: "MG001".into(),
            title: "Test".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "Desc".into(),
            exploit_scenario: "Exploit".into(),
            evidence: vec![Evidence {
                location: "test.json > tools[0]".into(),
                description: "Evidence desc".into(),
                raw_value: Some("raw".into()),
                region: None,
                file: None,
                json_pointer: None,
                server: None,
                tool: None,
                parameter: None,
            }],
            remediation: "Fix".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        }];

        let output = render(&findings, "test.json");
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["summary"]["total"], 1);
        assert_eq!(parsed["findings"][0]["id"], "MG001");
    }
}
