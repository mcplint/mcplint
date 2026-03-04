use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Severity of a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Confidence level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Low => write!(f, "low"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::High => write!(f, "high"),
        }
    }
}

/// Category of a finding based on analysis type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingCategory {
    Static,
    Semantic,
    Compositional,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::Static => write!(f, "static"),
            FindingCategory::Semantic => write!(f, "semantic"),
            FindingCategory::Compositional => write!(f, "compositional"),
        }
    }
}

/// Concrete evidence supporting a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Location in the input (e.g., JSON path, file path).
    pub location: String,
    /// Description of what was found.
    pub description: String,
    /// Raw value from the input that constitutes evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_value: Option<String>,
    /// Precise source region (line/column) if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<crate::json_locator::Region>,

    // ── Structured location fields (optional, backward-compatible) ──
    /// Source file path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// JSON pointer into the source file (RFC 6901).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_pointer: Option<String>,
    /// Server name this evidence relates to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Tool name this evidence relates to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Parameter name this evidence relates to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
}

/// A security finding produced by a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Rule identifier (e.g., "MG001").
    pub id: String,
    /// Short human-readable title.
    pub title: String,
    /// Severity level.
    pub severity: Severity,
    /// Confidence level.
    pub confidence: Confidence,
    /// Analysis category.
    pub category: FindingCategory,
    /// Detailed description of the issue.
    pub description: String,
    /// Concrete exploit scenario.
    pub exploit_scenario: String,
    /// Evidence supporting the finding.
    pub evidence: Vec<Evidence>,
    /// Suggested remediation steps.
    pub remediation: String,
    /// CWE identifiers (e.g., ["CWE-77", "CWE-89"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_ids: Vec<String>,
    /// OWASP Top 10 (2021) identifiers (e.g., ["A03:2021"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp_ids: Vec<String>,
    /// OWASP MCP Top 10 (2025) identifiers (e.g., ["MCP05:2025"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp_mcp_ids: Vec<String>,
}

impl Finding {
    /// Returns true if the finding meets or exceeds the given severity threshold.
    pub fn meets_threshold(&self, threshold: Severity) -> bool {
        self.severity >= threshold
    }

    /// Compute a stable fingerprint (hex SHA-256) for this finding.
    ///
    /// **Contract (v1):**
    /// - Deterministic and offline — same logical finding yields the same fingerprint across runs.
    /// - Canonical input: `"mcplint:finding:v1|{rule_id}|{file}|{json_pointer}|{server}|{tool}|{parameter}"`
    ///   For multi-evidence findings, additional evidence groups are appended:
    ///   `|{file_1}|{pointer_1}|{server_1}|{tool_1}|{param_1}|...`
    /// - All components are lowercased and trimmed before hashing.
    /// - Does NOT include severity, line/col, timestamps, or free-form message text.
    /// - If a component is absent, an empty string is used (structure is preserved).
    /// - Single-evidence fingerprints are identical to the original v1 format.
    /// - Output: lowercase hex SHA-256 (64 chars).
    ///
    /// See `docs/fingerprints.md` for the full contract and versioning policy.
    pub fn fingerprint(&self) -> String {
        fn evidence_fields(ev: Option<&Evidence>) -> (String, String, String, String, String) {
            let file = ev
                .and_then(|e| e.file.as_deref())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            let json_pointer = ev
                .and_then(|e| e.json_pointer.as_deref())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            let server = ev
                .and_then(|e| e.server.as_deref())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            let tool = ev
                .and_then(|e| e.tool.as_deref())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            let parameter = ev
                .and_then(|e| e.parameter.as_deref())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            (file, json_pointer, server, tool, parameter)
        }

        let rule_id = self.id.trim().to_lowercase();

        // First evidence (or empty if no evidence)
        let (file, json_pointer, server, tool, parameter) = evidence_fields(self.evidence.first());

        let mut canonical = format!(
            "mcplint:finding:v1|{}|{}|{}|{}|{}|{}",
            rule_id, file, json_pointer, server, tool, parameter
        );

        // Append additional evidence items (preserves backward compat for single/zero)
        for ev in self.evidence.iter().skip(1) {
            let (f, jp, s, t, p) = evidence_fields(Some(ev));
            canonical.push_str(&format!("|{}|{}|{}|{}|{}", f, jp, s, t, p));
        }

        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn meets_threshold() {
        let finding = Finding {
            id: "TEST001".into(),
            title: "Test".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "Test finding".into(),
            exploit_scenario: "N/A".into(),
            evidence: vec![],
            remediation: "N/A".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        };
        assert!(finding.meets_threshold(Severity::Medium));
        assert!(finding.meets_threshold(Severity::High));
        assert!(!finding.meets_threshold(Severity::Critical));
    }

    fn make_finding(
        id: &str,
        file: Option<&str>,
        ptr: Option<&str>,
        server: Option<&str>,
        tool: Option<&str>,
        param: Option<&str>,
    ) -> Finding {
        Finding {
            id: id.into(),
            title: "T".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "d".into(),
            exploit_scenario: "e".into(),
            evidence: vec![Evidence {
                location: "loc".into(),
                description: "d".into(),
                raw_value: None,
                region: None,
                file: file.map(|s| s.into()),
                json_pointer: ptr.map(|s| s.into()),
                server: server.map(|s| s.into()),
                tool: tool.map(|s| s.into()),
                parameter: param.map(|s| s.into()),
            }],
            remediation: "r".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        }
    }

    #[test]
    fn fingerprint_determinism() {
        let f = make_finding(
            "MG001",
            Some("config.json"),
            Some("/mcpServers/db/tools/0"),
            Some("db"),
            Some("query"),
            None,
        );
        let fp1 = f.fingerprint();
        let fp2 = f.fingerprint();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
    }

    #[test]
    fn fingerprint_stable_across_identical_builds() {
        let f1 = make_finding(
            "MG001",
            Some("config.json"),
            Some("/mcpServers/db/tools/0"),
            Some("db"),
            Some("query"),
            Some("sql"),
        );
        let f2 = make_finding(
            "MG001",
            Some("config.json"),
            Some("/mcpServers/db/tools/0"),
            Some("db"),
            Some("query"),
            Some("sql"),
        );
        assert_eq!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_ignores_line_col_changes() {
        let mut f = make_finding(
            "MG001",
            Some("config.json"),
            Some("/mcpServers/db/tools/0"),
            Some("db"),
            Some("query"),
            None,
        );
        let fp_no_region = f.fingerprint();

        f.evidence[0].region = Some(crate::json_locator::Region {
            start_line: 10,
            start_column: 5,
            end_line: 10,
            end_column: 20,
        });
        let fp_with_region = f.fingerprint();
        assert_eq!(fp_no_region, fp_with_region);

        f.evidence[0].region = Some(crate::json_locator::Region {
            start_line: 99,
            start_column: 1,
            end_line: 99,
            end_column: 50,
        });
        let fp_different_region = f.fingerprint();
        assert_eq!(fp_no_region, fp_different_region);
    }

    #[test]
    fn fingerprint_ignores_severity_changes() {
        let mut f = make_finding(
            "MG001",
            Some("config.json"),
            Some("/a"),
            Some("s"),
            Some("t"),
            None,
        );
        f.severity = Severity::High;
        let fp_high = f.fingerprint();
        f.severity = Severity::Medium;
        let fp_medium = f.fingerprint();
        assert_eq!(fp_high, fp_medium, "severity must not affect fingerprint");
    }

    #[test]
    fn fingerprint_normalization_case_insensitive() {
        let f1 = make_finding(
            "MG001",
            Some("Config.JSON"),
            Some("/McpServers/DB"),
            Some("DB"),
            Some("Query"),
            None,
        );
        let f2 = make_finding(
            "mg001",
            Some("config.json"),
            Some("/mcpservers/db"),
            Some("db"),
            Some("query"),
            None,
        );
        assert_eq!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_normalization_trims_whitespace() {
        let f1 = make_finding(
            "  MG001  ",
            Some(" config.json "),
            Some(" /a "),
            Some(" s "),
            Some(" t "),
            None,
        );
        let f2 = make_finding(
            "MG001",
            Some("config.json"),
            Some("/a"),
            Some("s"),
            Some("t"),
            None,
        );
        assert_eq!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_collision_different_rules() {
        let f1 = make_finding("MG001", Some("f"), Some("/a"), Some("s"), Some("t"), None);
        let f2 = make_finding("MG002", Some("f"), Some("/a"), Some("s"), Some("t"), None);
        assert_ne!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_collision_different_pointers() {
        let f1 = make_finding(
            "MG001",
            Some("f"),
            Some("/servers/0/tools/0"),
            Some("s"),
            Some("t"),
            None,
        );
        let f2 = make_finding(
            "MG001",
            Some("f"),
            Some("/servers/0/tools/1"),
            Some("s"),
            Some("t"),
            None,
        );
        assert_ne!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_collision_different_params() {
        let f1 = make_finding(
            "MG001",
            Some("f"),
            Some("/a"),
            Some("s"),
            Some("t"),
            Some("p1"),
        );
        let f2 = make_finding(
            "MG001",
            Some("f"),
            Some("/a"),
            Some("s"),
            Some("t"),
            Some("p2"),
        );
        assert_ne!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn fingerprint_empty_evidence() {
        let f = Finding {
            id: "MG001".into(),
            title: "T".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "d".into(),
            exploit_scenario: "e".into(),
            evidence: vec![],
            remediation: "r".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        };
        let fp = f.fingerprint();
        assert_eq!(fp.len(), 64);
    }

    #[test]
    fn fingerprint_ignores_message_text() {
        let mut f1 = make_finding("MG001", Some("f"), Some("/a"), Some("s"), Some("t"), None);
        let mut f2 = make_finding("MG001", Some("f"), Some("/a"), Some("s"), Some("t"), None);
        f1.description = "description version 1".into();
        f1.exploit_scenario = "scenario A".into();
        f1.remediation = "fix A".into();
        f2.description = "completely different description".into();
        f2.exploit_scenario = "scenario B".into();
        f2.remediation = "fix B".into();
        assert_eq!(f1.fingerprint(), f2.fingerprint());
    }

    // ── Multi-evidence fingerprint tests ──────────────────────────────────────

    fn make_evidence(
        file: Option<&str>,
        ptr: Option<&str>,
        server: Option<&str>,
        tool: Option<&str>,
        param: Option<&str>,
    ) -> Evidence {
        Evidence {
            location: "loc".into(),
            description: "d".into(),
            raw_value: None,
            region: None,
            file: file.map(|s| s.into()),
            json_pointer: ptr.map(|s| s.into()),
            server: server.map(|s| s.into()),
            tool: tool.map(|s| s.into()),
            parameter: param.map(|s| s.into()),
        }
    }

    #[test]
    fn fingerprint_single_evidence_backward_compat() {
        // Single-evidence must produce identical hash to what old code would produce
        let f = make_finding(
            "MG001",
            Some("config.json"),
            Some("/mcpServers/db/tools/0"),
            Some("db"),
            Some("query"),
            None,
        );
        // The canonical string for single evidence is unchanged:
        // "mcplint:finding:v1|mg001|config.json|/mcpservers/db/tools/0|db|query|"
        let canonical = "mcplint:finding:v1|mg001|config.json|/mcpservers/db/tools/0|db|query|";
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let expected: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(f.fingerprint(), expected);
    }

    #[test]
    fn fingerprint_multi_evidence_different_second() {
        let mut f1 = make_finding("MG003", Some("f"), Some("/a"), Some("s1"), Some("t1"), None);
        f1.evidence.push(make_evidence(
            Some("f"),
            Some("/b"),
            Some("s2"),
            Some("t2"),
            None,
        ));

        let mut f2 = make_finding("MG003", Some("f"), Some("/a"), Some("s1"), Some("t1"), None);
        f2.evidence.push(make_evidence(
            Some("f"),
            Some("/c"),
            Some("s3"),
            Some("t3"),
            None,
        ));

        assert_ne!(
            f1.fingerprint(),
            f2.fingerprint(),
            "different second evidence must produce different fingerprints"
        );
    }

    #[test]
    fn fingerprint_three_evidence_deterministic() {
        let mut f = make_finding("MG003", Some("f"), Some("/a"), Some("s1"), Some("t1"), None);
        f.evidence.push(make_evidence(
            Some("f2"),
            Some("/b"),
            Some("s2"),
            Some("t2"),
            None,
        ));
        f.evidence.push(make_evidence(
            Some("f3"),
            Some("/c"),
            Some("s3"),
            Some("t3"),
            None,
        ));

        let fp1 = f.fingerprint();
        let fp2 = f.fingerprint();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
    }

    #[test]
    fn fingerprint_evidence_order_matters() {
        let ev_a = make_evidence(Some("f"), Some("/a"), Some("s1"), Some("t1"), None);
        let ev_b = make_evidence(Some("f"), Some("/b"), Some("s2"), Some("t2"), None);

        let f1 = Finding {
            id: "MG003".into(),
            title: "T".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "d".into(),
            exploit_scenario: "e".into(),
            evidence: vec![ev_a.clone(), ev_b.clone()],
            remediation: "r".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        };
        let f2 = Finding {
            id: "MG003".into(),
            title: "T".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "d".into(),
            exploit_scenario: "e".into(),
            evidence: vec![ev_b, ev_a],
            remediation: "r".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        };

        assert_ne!(
            f1.fingerprint(),
            f2.fingerprint(),
            "swapping evidence order must change fingerprint"
        );
    }

    #[test]
    fn fingerprint_zero_evidence_still_works() {
        let f = Finding {
            id: "MG001".into(),
            title: "T".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "d".into(),
            exploit_scenario: "e".into(),
            evidence: vec![],
            remediation: "r".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        };
        let fp = f.fingerprint();
        assert_eq!(fp.len(), 64);
        // Should be same as before — backward compat for zero evidence
        let canonical = "mcplint:finding:v1|mg001|||||";
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let expected: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(fp, expected);
    }
}
