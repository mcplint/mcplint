use crate::ScanSummary;
use mcplint_core::{Finding, Severity};

/// Render findings as human-readable terminal output grouped by severity.
pub fn render(findings: &[Finding], source_path: &str) -> String {
    let mut out = String::new();

    let summary = ScanSummary::from_findings(findings);

    out.push_str(&format!("mcplint scan: {}\n", source_path));
    out.push_str(&"═".repeat(60));
    out.push('\n');

    if findings.is_empty() {
        out.push_str("✓ No security findings.\n");
        return out;
    }

    out.push_str(&format!(
        "Found {} issue(s): {} critical, {} high, {} medium, {} low\n\n",
        summary.total, summary.critical, summary.high, summary.medium, summary.low
    ));

    let severity_order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];

    for severity in &severity_order {
        let group: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.severity == *severity)
            .collect();
        if group.is_empty() {
            continue;
        }

        let icon = match severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🔵",
        };

        out.push_str(&format!(
            "── {} {} ({}) ──\n\n",
            icon,
            format!("{}", severity).to_uppercase(),
            group.len()
        ));

        for finding in &group {
            out.push_str(&format!("  [{}] {}\n", finding.id, finding.title));
            out.push_str(&format!(
                "  Category: {} | Confidence: {}\n",
                finding.category, finding.confidence
            ));
            out.push_str(&format!("  {}\n", finding.description));
            out.push_str(&format!("  Exploit: {}\n", finding.exploit_scenario));

            for evidence in &finding.evidence {
                out.push_str(&format!(
                    "  Evidence: {} — {}\n",
                    evidence.location, evidence.description
                ));
                if let Some(raw) = &evidence.raw_value {
                    out.push_str(&format!("    Raw: {}\n", raw));
                }
            }

            out.push_str(&format!("  Remediation: {}\n", finding.remediation));
            if !finding.cwe_ids.is_empty()
                || !finding.owasp_ids.is_empty()
                || !finding.owasp_mcp_ids.is_empty()
            {
                let mut parts = Vec::new();
                if !finding.cwe_ids.is_empty() {
                    parts.push(format!("CWE: {}", finding.cwe_ids.join(", ")));
                }
                if !finding.owasp_ids.is_empty() {
                    parts.push(format!("OWASP: {}", finding.owasp_ids.join(", ")));
                }
                if !finding.owasp_mcp_ids.is_empty() {
                    parts.push(format!("MCP: {}", finding.owasp_mcp_ids.join(", ")));
                }
                out.push_str(&format!("  {}\n", parts.join(" | ")));
            }
            out.push('\n');
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcplint_core::*;

    #[test]
    fn empty_findings_shows_no_issues() {
        let output = render(&[], "test.json");
        assert!(output.contains("No security findings"));
    }

    #[test]
    fn renders_findings_grouped_by_severity() {
        let findings = vec![
            Finding {
                id: "MG001".into(),
                title: "Test high".into(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: FindingCategory::Static,
                description: "Desc".into(),
                exploit_scenario: "Exploit".into(),
                evidence: vec![],
                remediation: "Fix it".into(),
                cwe_ids: vec![],
                owasp_ids: vec![],
                owasp_mcp_ids: vec![],
            },
            Finding {
                id: "MG003".into(),
                title: "Test critical".into(),
                severity: Severity::Critical,
                confidence: Confidence::Medium,
                category: FindingCategory::Compositional,
                description: "Desc".into(),
                exploit_scenario: "Exploit".into(),
                evidence: vec![],
                remediation: "Fix it".into(),
                cwe_ids: vec![],
                owasp_ids: vec![],
                owasp_mcp_ids: vec![],
            },
        ];

        let output = render(&findings, "test.json");
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("HIGH"));
        // Critical should come before High in output
        let crit_pos = output.find("CRITICAL").unwrap();
        let high_pos = output.find("HIGH").unwrap();
        assert!(crit_pos < high_pos);
    }
}
