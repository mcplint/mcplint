//! Findings-based baseline for incremental security diffing.
//!
//! Snapshots scan findings into a JSON file and compares new scans against
//! that baseline to detect regressions (new findings) and fixes (resolved findings).

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::finding::Finding;

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum FindingsBaselineError {
    #[error("Failed to read baseline file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse baseline JSON: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("Unsupported baseline version: {0} (expected 1)")]
    UnsupportedVersion(u32),
}

// ── Baseline data model ─────────────────────────────────────────────────────

/// A snapshot of security findings from a scan, used for incremental diffing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsBaseline {
    /// Format version (always 1 for now).
    pub version: u32,
    /// When the baseline was created (RFC 3339).
    pub created_at: String,
    /// Source information.
    pub source: BaselineSource,
    /// All findings at baseline time.
    pub findings: Vec<BaselineFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSource {
    /// Adapter that detected the config format.
    pub adapter: String,
    /// Path that was scanned.
    pub path: String,
    /// mcplint version that created this baseline.
    pub mcplint_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFinding {
    /// Stable SHA-256 fingerprint.
    pub fingerprint: String,
    /// Rule ID (e.g., "MG001").
    pub rule_id: String,
    /// Severity at time of baseline creation.
    pub severity: String,
    /// Short finding title.
    pub title: String,
    /// Server name from first evidence (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Tool name from first evidence (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

impl FindingsBaseline {
    /// Create a baseline from scan findings.
    pub fn from_findings(findings: &[Finding], adapter: &str, path: &str, version: &str) -> Self {
        let mut baseline_findings: Vec<BaselineFinding> = findings
            .iter()
            .map(|f| {
                let ev = f.evidence.first();
                BaselineFinding {
                    fingerprint: f.fingerprint(),
                    rule_id: f.id.clone(),
                    severity: f.severity.to_string(),
                    title: f.title.clone(),
                    server: ev.and_then(|e| e.server.clone()),
                    tool: ev.and_then(|e| e.tool.clone()),
                }
            })
            .collect();
        baseline_findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));

        Self {
            version: 1,
            created_at: utc_now_rfc3339(),
            source: BaselineSource {
                adapter: adapter.to_string(),
                path: path.to_string(),
                mcplint_version: version.to_string(),
            },
            findings: baseline_findings,
        }
    }

    /// Load a baseline from a JSON file.
    pub fn load(path: &Path) -> Result<Self, FindingsBaselineError> {
        let data = std::fs::read_to_string(path)?;
        let baseline: Self = serde_json::from_str(&data)?;
        if baseline.version != 1 {
            return Err(FindingsBaselineError::UnsupportedVersion(baseline.version));
        }
        Ok(baseline)
    }

    /// Save baseline to a JSON file (pretty-printed).
    pub fn save(&self, path: &Path) -> Result<(), FindingsBaselineError> {
        let json = serde_json::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Get the set of fingerprints in this baseline.
    pub fn fingerprints(&self) -> HashSet<&str> {
        self.findings
            .iter()
            .map(|f| f.fingerprint.as_str())
            .collect()
    }
}

// ── Diff ────────────────────────────────────────────────────────────────────

/// Result of comparing current findings against a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsDiff {
    /// Findings in current scan but NOT in baseline (regressions).
    pub new_findings: Vec<DiffEntry>,
    /// Findings in baseline but NOT in current scan (fixed).
    pub resolved_findings: Vec<DiffEntry>,
    /// Count of findings present in both.
    pub unchanged_count: usize,
    /// Total findings in current scan.
    pub current_total: usize,
    /// Total findings in baseline.
    pub baseline_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

impl FindingsDiff {
    /// Compare current findings against a baseline.
    pub fn compute(baseline: &FindingsBaseline, current_findings: &[Finding]) -> Self {
        let baseline_fps = baseline.fingerprints();

        // Build current fingerprints + lookup map
        let current_entries: Vec<(String, DiffEntry)> = current_findings
            .iter()
            .map(|f| {
                let ev = f.evidence.first();
                let fp = f.fingerprint();
                let entry = DiffEntry {
                    fingerprint: fp.clone(),
                    rule_id: f.id.clone(),
                    severity: f.severity.to_string(),
                    title: f.title.clone(),
                    server: ev.and_then(|e| e.server.clone()),
                    tool: ev.and_then(|e| e.tool.clone()),
                };
                (fp, entry)
            })
            .collect();

        let current_fps: HashSet<&str> =
            current_entries.iter().map(|(fp, _)| fp.as_str()).collect();

        // New = in current but not in baseline
        let mut new_findings: Vec<DiffEntry> = current_entries
            .iter()
            .filter(|(fp, _)| !baseline_fps.contains(fp.as_str()))
            .map(|(_, e)| e.clone())
            .collect();

        // Resolved = in baseline but not in current
        let mut resolved_findings: Vec<DiffEntry> = baseline
            .findings
            .iter()
            .filter(|bf| !current_fps.contains(bf.fingerprint.as_str()))
            .map(|bf| DiffEntry {
                fingerprint: bf.fingerprint.clone(),
                rule_id: bf.rule_id.clone(),
                severity: bf.severity.clone(),
                title: bf.title.clone(),
                server: bf.server.clone(),
                tool: bf.tool.clone(),
            })
            .collect();

        let unchanged_count = current_fps.intersection(&baseline_fps).count();

        // Sort by severity desc, then rule_id, then title
        let sort_fn = |a: &DiffEntry, b: &DiffEntry| {
            severity_rank(&b.severity)
                .cmp(&severity_rank(&a.severity))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| a.title.cmp(&b.title))
        };
        new_findings.sort_by(sort_fn);
        resolved_findings.sort_by(sort_fn);

        Self {
            new_findings,
            resolved_findings,
            unchanged_count,
            current_total: current_entries.len(),
            baseline_total: baseline.findings.len(),
        }
    }

    /// Returns true if there are new findings (regressions).
    pub fn has_new_findings(&self) -> bool {
        !self.new_findings.is_empty()
    }

    /// Returns true if there are new findings at or above the given severity.
    pub fn has_new_findings_at_severity(&self, min_severity: &str) -> bool {
        let threshold = severity_rank(min_severity);
        self.new_findings
            .iter()
            .any(|f| severity_rank(&f.severity) >= threshold)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn utc_now_rfc3339() -> String {
    // Avoid adding chrono dependency — use std::time
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Simple UTC formatting: YYYY-MM-DDTHH:MM:SSZ
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to Y-M-D (simplified Gregorian)
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    days += 719_468;
    let era = days / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, Evidence, FindingCategory, Severity};

    fn make_finding(
        rule_id: &str,
        sev: Severity,
        title: &str,
        server: &str,
        tool: &str,
    ) -> Finding {
        Finding {
            id: rule_id.to_string(),
            title: title.to_string(),
            severity: sev,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: String::new(),
            exploit_scenario: String::new(),
            evidence: vec![Evidence {
                location: String::new(),
                description: String::new(),
                raw_value: None,
                region: None,
                file: Some("test.json".into()),
                json_pointer: Some("/servers/test".into()),
                server: Some(server.into()),
                tool: if tool.is_empty() {
                    None
                } else {
                    Some(tool.into())
                },
                parameter: None,
            }],
            remediation: String::new(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        }
    }

    fn sample_findings() -> Vec<Finding> {
        vec![
            make_finding(
                "MG001",
                Severity::High,
                "Unbounded string",
                "api",
                "exec_cmd",
            ),
            make_finding("MG005", Severity::High, "Missing auth", "api", ""),
            make_finding("MG006", Severity::Medium, "Metadata leak", "api", "search"),
        ]
    }

    #[test]
    fn test_from_findings_produces_correct_entries() {
        let findings = sample_findings();
        let bl = FindingsBaseline::from_findings(&findings, "generic", "test.json", "0.1.0");
        assert_eq!(bl.version, 1);
        assert_eq!(bl.findings.len(), 3);
        assert_eq!(bl.source.adapter, "generic");
        assert_eq!(bl.source.path, "test.json");
        // Sorted by fingerprint
        for i in 1..bl.findings.len() {
            assert!(bl.findings[i - 1].fingerprint <= bl.findings[i].fingerprint);
        }
    }

    #[test]
    fn test_save_load_roundtrip() {
        let findings = sample_findings();
        let bl = FindingsBaseline::from_findings(&findings, "generic", "test.json", "0.1.0");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        bl.save(&path).unwrap();
        let loaded = FindingsBaseline::load(&path).unwrap();
        assert_eq!(loaded.version, bl.version);
        assert_eq!(loaded.findings.len(), bl.findings.len());
        for (a, b) in loaded.findings.iter().zip(bl.findings.iter()) {
            assert_eq!(a.fingerprint, b.fingerprint);
            assert_eq!(a.rule_id, b.rule_id);
        }
    }

    #[test]
    fn test_load_unsupported_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        std::fs::write(
            &path,
            r#"{"version":99,"created_at":"","source":{"adapter":"","path":"","mcplint_version":""},"findings":[]}"#,
        )
        .unwrap();
        let err = FindingsBaseline::load(&path).unwrap_err();
        assert!(err.to_string().contains("99"));
    }

    #[test]
    fn test_load_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(matches!(
            FindingsBaseline::load(&path),
            Err(FindingsBaselineError::ParseError(_))
        ));
    }

    #[test]
    fn test_fingerprints_set() {
        let findings = sample_findings();
        let bl = FindingsBaseline::from_findings(&findings, "generic", "test.json", "0.1.0");
        let fps = bl.fingerprints();
        assert_eq!(fps.len(), 3);
    }

    #[test]
    fn test_diff_identical() {
        let findings = sample_findings();
        let bl = FindingsBaseline::from_findings(&findings, "generic", "test.json", "0.1.0");
        let diff = FindingsDiff::compute(&bl, &findings);
        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.resolved_findings.len(), 0);
        assert_eq!(diff.unchanged_count, 3);
        assert_eq!(diff.current_total, 3);
        assert_eq!(diff.baseline_total, 3);
        assert!(!diff.has_new_findings());
    }

    #[test]
    fn test_diff_one_removed() {
        let findings = sample_findings();
        let bl = FindingsBaseline::from_findings(&findings, "generic", "test.json", "0.1.0");
        // Remove last finding
        let current = &findings[..2];
        let diff = FindingsDiff::compute(&bl, current);
        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.unchanged_count, 2);
        assert!(!diff.has_new_findings());
    }

    #[test]
    fn test_diff_one_added() {
        let findings = sample_findings();
        let bl = FindingsBaseline::from_findings(&findings, "generic", "test.json", "0.1.0");
        let mut current = findings.clone();
        current.push(make_finding(
            "MG009",
            Severity::Critical,
            "Leaked secret",
            "db",
            "",
        ));
        let diff = FindingsDiff::compute(&bl, &current);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].rule_id, "MG009");
        assert_eq!(diff.resolved_findings.len(), 0);
        assert_eq!(diff.unchanged_count, 3);
        assert!(diff.has_new_findings());
    }

    #[test]
    fn test_diff_mixed() {
        let findings = sample_findings();
        let bl = FindingsBaseline::from_findings(&findings, "generic", "test.json", "0.1.0");
        // Remove one, add two
        let mut current: Vec<Finding> = findings[..2].to_vec();
        current.push(make_finding(
            "MG008",
            Severity::Medium,
            "Insecure transport",
            "api",
            "",
        ));
        current.push(make_finding(
            "MG009",
            Severity::Critical,
            "Leaked secret",
            "db",
            "",
        ));
        let diff = FindingsDiff::compute(&bl, &current);
        assert_eq!(diff.new_findings.len(), 2);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.unchanged_count, 2);
        // New findings sorted by severity desc
        assert_eq!(diff.new_findings[0].severity, "critical");
        assert_eq!(diff.new_findings[1].severity, "medium");
    }

    #[test]
    fn test_diff_empty_baseline() {
        let bl = FindingsBaseline {
            version: 1,
            created_at: String::new(),
            source: BaselineSource {
                adapter: String::new(),
                path: String::new(),
                mcplint_version: String::new(),
            },
            findings: vec![],
        };
        let current = sample_findings();
        let diff = FindingsDiff::compute(&bl, &current);
        assert_eq!(diff.new_findings.len(), 3);
        assert_eq!(diff.resolved_findings.len(), 0);
        assert_eq!(diff.unchanged_count, 0);
    }

    #[test]
    fn test_diff_empty_current() {
        let findings = sample_findings();
        let bl = FindingsBaseline::from_findings(&findings, "generic", "test.json", "0.1.0");
        let diff = FindingsDiff::compute(&bl, &[]);
        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.resolved_findings.len(), 3);
        assert_eq!(diff.unchanged_count, 0);
    }

    #[test]
    fn test_has_new_findings_at_severity() {
        let findings = sample_findings();
        let bl = FindingsBaseline::from_findings(&findings, "generic", "test.json", "0.1.0");
        let mut current = findings;
        current.push(make_finding("MG008", Severity::Medium, "Insecure", "x", ""));
        let diff = FindingsDiff::compute(&bl, &current);
        assert!(diff.has_new_findings_at_severity("low"));
        assert!(diff.has_new_findings_at_severity("medium"));
        assert!(!diff.has_new_findings_at_severity("high"));
        assert!(!diff.has_new_findings_at_severity("critical"));
    }

    #[test]
    fn test_has_new_findings_at_severity_none() {
        let findings = sample_findings();
        let bl = FindingsBaseline::from_findings(&findings, "generic", "test.json", "0.1.0");
        let diff = FindingsDiff::compute(&bl, &findings);
        assert!(!diff.has_new_findings_at_severity("low"));
    }

    #[test]
    fn test_sorting_new_findings() {
        let bl = FindingsBaseline {
            version: 1,
            created_at: String::new(),
            source: BaselineSource {
                adapter: String::new(),
                path: String::new(),
                mcplint_version: String::new(),
            },
            findings: vec![],
        };
        let current = vec![
            make_finding("MG007", Severity::Low, "Broad scope", "a", ""),
            make_finding("MG009", Severity::Critical, "Secret", "b", ""),
            make_finding("MG008", Severity::Medium, "Transport", "c", ""),
            make_finding("MG001", Severity::High, "Injection", "d", "exec"),
        ];
        let diff = FindingsDiff::compute(&bl, &current);
        assert_eq!(diff.new_findings[0].severity, "critical");
        assert_eq!(diff.new_findings[1].severity, "high");
        assert_eq!(diff.new_findings[2].severity, "medium");
        assert_eq!(diff.new_findings[3].severity, "low");
    }
}
