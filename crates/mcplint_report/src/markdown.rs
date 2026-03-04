use crate::ScanSummary;
use mcplint_core::{Finding, Severity};

/// Render findings as Markdown for PR comments and sharing.
pub fn render(findings: &[Finding], source_path: &str) -> String {
    let mut out = String::new();

    let summary = ScanSummary::from_findings(findings);

    out.push_str("# mcplint Scan Report\n\n");
    out.push_str(&format!("**Source:** `{}`\n\n", source_path));

    if findings.is_empty() {
        out.push_str("✅ **No security findings.**\n");
        return out;
    }

    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "| Severity | Count |\n|----------|-------|\n| 🔴 Critical | {} |\n| 🟠 High | {} |\n| 🟡 Medium | {} |\n| 🔵 Low | {} |\n| **Total** | **{}** |\n\n",
        summary.critical, summary.high, summary.medium, summary.low, summary.total
    ));

    out.push_str("## Findings\n\n");

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

        for finding in &group {
            let icon = match severity {
                Severity::Critical => "🔴",
                Severity::High => "🟠",
                Severity::Medium => "🟡",
                Severity::Low => "🔵",
            };

            out.push_str(&format!(
                "### {} [{}] {}\n\n",
                icon, finding.id, finding.title
            ));
            out.push_str(&format!(
                "**Severity:** {} | **Confidence:** {} | **Category:** {}\n\n",
                finding.severity, finding.confidence, finding.category
            ));
            out.push_str(&format!("{}\n\n", finding.description));
            out.push_str(&format!(
                "**Exploit Scenario:** {}\n\n",
                finding.exploit_scenario
            ));

            if !finding.evidence.is_empty() {
                out.push_str("**Evidence:**\n\n");
                for evidence in &finding.evidence {
                    out.push_str(&format!(
                        "- `{}`: {}\n",
                        evidence.location, evidence.description
                    ));
                    if let Some(raw) = &evidence.raw_value {
                        out.push_str(&format!("  ```\n  {}\n  ```\n", raw));
                    }
                }
                out.push('\n');
            }

            out.push_str(&format!(
                "**Remediation:** {}\n\n---\n\n",
                finding.remediation
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcplint_core::*;

    #[test]
    fn markdown_output_has_headers() {
        let findings = vec![Finding {
            id: "MG001".into(),
            title: "Test".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "Desc".into(),
            exploit_scenario: "Exploit".into(),
            evidence: vec![],
            remediation: "Fix".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        }];

        let output = render(&findings, "test.json");
        assert!(output.contains("# mcplint Scan Report"));
        assert!(output.contains("### 🟠 [MG001]"));
    }
}
