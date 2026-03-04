//! Project configuration file (`.mcplint.toml`) support.
//!
//! Provides parsing, discovery, and policy application for mcplint
//! project configuration. The config controls reporting filters and
//! thresholds — it never changes core analysis logic.

use crate::finding::{Finding, Severity};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The config file name searched for during discovery.
pub const CONFIG_FILE_NAME: &str = ".mcplint.toml";

/// Legacy config file name (backward compatibility).
pub const LEGACY_CONFIG_FILE_NAME: &str = ".mcp-guard.toml";

// ── Config schema ──

/// Top-level project configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GuardConfig {
    /// Minimum severity to trigger a non-zero exit code (e.g., "high").
    #[serde(default)]
    pub fail_on: Option<SeverityString>,

    /// Default output format when `--format` is not specified.
    #[serde(default)]
    pub default_format: Option<String>,

    /// Ignore rules and specific findings.
    #[serde(default)]
    pub ignore: IgnoreConfig,

    /// Per-rule severity overrides (downgrade only).
    #[serde(default)]
    pub severity_overrides: std::collections::HashMap<String, SeverityString>,

    /// Default scan targets.
    #[serde(default)]
    pub scan: Option<ScanConfig>,

    /// Directory of custom rule YAML files.
    #[serde(default)]
    pub rules_dir: Option<String>,
}

/// A severity value parsed from TOML strings.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
pub struct SeverityString(pub Severity);

impl TryFrom<String> for SeverityString {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "low" => Ok(SeverityString(Severity::Low)),
            "medium" => Ok(SeverityString(Severity::Medium)),
            "high" => Ok(SeverityString(Severity::High)),
            "critical" => Ok(SeverityString(Severity::Critical)),
            _ => Err(format!(
                "invalid severity '{}': expected low, medium, high, or critical",
                s
            )),
        }
    }
}

/// Configuration for ignoring rules and findings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreConfig {
    /// Rule IDs to ignore entirely (e.g., ["MG006"]).
    #[serde(default)]
    pub rules: Vec<String>,

    /// Specific findings to ignore, matched by rule + tool/server name.
    #[serde(default)]
    pub findings: Vec<IgnoreFinding>,
}

/// A single finding ignore entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreFinding {
    /// Rule ID (required).
    pub rule: String,
    /// Tool name to match (optional).
    #[serde(default)]
    pub tool: Option<String>,
    /// Server name to match (optional).
    #[serde(default)]
    pub server: Option<String>,
    /// Required reason for the ignore.
    pub reason: String,
}

/// Default scan paths (optional).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    #[serde(default)]
    pub paths: Vec<String>,
}

// ── Parsing ──

impl GuardConfig {
    /// Parse a config from TOML content.
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    /// Load a config from a file path.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.to_path_buf(), e))?;
        Self::from_toml(&content).map_err(|e| ConfigError::Parse(path.to_path_buf(), e))
    }
}

/// Errors during config loading.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file '{}': {}", .0.display(), .1)]
    Io(PathBuf, std::io::Error),
    #[error("failed to parse config file '{}': {}", .0.display(), .1)]
    Parse(PathBuf, toml::de::Error),
}

// ── Discovery ──

/// Search upward from `start` for `.mcplint.toml` (or legacy `.mcp-guard.toml`).
///
/// If `start` is a file, begins searching from its parent directory.
/// Stops at the filesystem root. Returns the path to the config file if found.
///
/// Prefers `.mcplint.toml`. If only `.mcp-guard.toml` is found, it is used with
/// a deprecation warning on stderr. If both exist, `.mcplint.toml` wins and
/// the legacy file is reported as ignored.
pub fn discover_config(start: &Path) -> Option<PathBuf> {
    let start_dir = if start.is_file() {
        start.parent()?
    } else {
        start
    };

    let mut dir = std::fs::canonicalize(start_dir).ok()?;
    loop {
        let new_candidate = dir.join(CONFIG_FILE_NAME);
        let legacy_candidate = dir.join(LEGACY_CONFIG_FILE_NAME);

        let has_new = new_candidate.is_file();
        let has_legacy = legacy_candidate.is_file();

        if has_new && has_legacy {
            eprintln!(
                "warning: both {} and {} found; using {}, ignoring legacy file",
                CONFIG_FILE_NAME, LEGACY_CONFIG_FILE_NAME, CONFIG_FILE_NAME
            );
            return Some(new_candidate);
        }
        if has_new {
            return Some(new_candidate);
        }
        if has_legacy {
            eprintln!(
                "warning: {} is deprecated, rename to {}",
                LEGACY_CONFIG_FILE_NAME, CONFIG_FILE_NAME
            );
            return Some(legacy_candidate);
        }

        if !dir.pop() {
            return None;
        }
    }
}

// ── Policy application ──

/// Apply config-based filtering and severity overrides to findings.
///
/// This is a pure transformation:
/// 1. Drop findings matching ignore.rules
/// 2. Drop findings matching ignore.findings (by rule + tool/server)
/// 3. Apply severity_overrides (downgrade only)
/// 4. Preserve original ordering
pub fn apply_policy(config: &GuardConfig, findings: Vec<Finding>) -> Vec<Finding> {
    let ignored_rules: std::collections::HashSet<&str> =
        config.ignore.rules.iter().map(|s| s.as_str()).collect();

    findings
        .into_iter()
        .filter(|f| {
            // Step 1: filter by ignored rules
            if ignored_rules.contains(f.id.as_str()) {
                return false;
            }

            // Step 2: filter by specific finding ignores
            if config
                .ignore
                .findings
                .iter()
                .any(|ig| matches_ignore(ig, f))
            {
                return false;
            }

            true
        })
        .map(|mut f| {
            // Step 3: apply severity overrides (downgrade only)
            if let Some(override_sev) = config.severity_overrides.get(&f.id) {
                if override_sev.0 < f.severity {
                    f.severity = override_sev.0;
                }
            }
            f
        })
        .collect()
}

/// Check if a finding matches an ignore entry.
///
/// Matching logic:
/// - rule ID must match
/// - if ignore specifies tool: at least one evidence location must contain `tools[{tool}]`
/// - if ignore specifies server: at least one evidence location must contain `servers[{server}]`
/// - if both are specified, both must match (can be in different evidence entries)
fn matches_ignore(ignore: &IgnoreFinding, finding: &Finding) -> bool {
    if finding.id != ignore.rule {
        return false;
    }

    let tool_matches = match &ignore.tool {
        Some(tool) => finding
            .evidence
            .iter()
            .any(|ev| ev.location.contains(&format!("tools[{}]", tool))),
        None => true,
    };

    let server_matches = match &ignore.server {
        Some(server) => finding
            .evidence
            .iter()
            .any(|ev| ev.location.contains(&format!("servers[{}]", server))),
        None => true,
    };

    tool_matches && server_matches
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::*;

    #[test]
    fn parse_minimal_config() {
        let config = GuardConfig::from_toml("").unwrap();
        assert!(config.fail_on.is_none());
        assert!(config.default_format.is_none());
        assert!(config.ignore.rules.is_empty());
        assert!(config.ignore.findings.is_empty());
        assert!(config.severity_overrides.is_empty());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
fail_on = "high"
default_format = "sarif"

[ignore]
rules = ["MG006"]
findings = [
  { rule = "MG001", tool = "run_sql", reason = "wrapped with allowlisted queries" },
  { rule = "MG004", server = "filesystem", reason = "sandboxed container path only" },
  { rule = "MG005", tool = "exec", server = "shell", reason = "internal-only server" },
]

[severity_overrides]
MG002 = "low"

[scan]
paths = ["./", "./.cursor/mcp.json"]
"#;
        let config = GuardConfig::from_toml(toml).unwrap();
        assert_eq!(config.fail_on.as_ref().unwrap().0, Severity::High);
        assert_eq!(config.default_format.as_deref(), Some("sarif"));
        assert_eq!(config.ignore.rules, vec!["MG006"]);
        assert_eq!(config.ignore.findings.len(), 3);
        assert_eq!(config.ignore.findings[0].rule, "MG001");
        assert_eq!(config.ignore.findings[0].tool.as_deref(), Some("run_sql"));
        assert!(config.ignore.findings[0].server.is_none());
        assert_eq!(
            config.ignore.findings[1].server.as_deref(),
            Some("filesystem")
        );
        assert_eq!(config.ignore.findings[2].tool.as_deref(), Some("exec"));
        assert_eq!(config.ignore.findings[2].server.as_deref(), Some("shell"));
        assert_eq!(config.severity_overrides["MG002"].0, Severity::Low);
        assert_eq!(config.scan.as_ref().unwrap().paths.len(), 2);
    }

    #[test]
    fn parse_invalid_severity() {
        let toml = r#"fail_on = "extreme""#;
        assert!(GuardConfig::from_toml(toml).is_err());
    }

    #[test]
    fn parse_unknown_field_accepted() {
        // GuardConfig no longer uses deny_unknown_fields (to support forward compat)
        let toml = r#"unknown_field = true"#;
        assert!(GuardConfig::from_toml(toml).is_ok());
    }

    #[test]
    fn parse_missing_reason_rejected() {
        let toml = r#"
[ignore]
findings = [{ rule = "MG001", tool = "run_sql" }]
"#;
        assert!(GuardConfig::from_toml(toml).is_err());
    }

    fn make_finding(id: &str, severity: Severity, server: &str, tool: &str) -> Finding {
        Finding {
            id: id.to_string(),
            title: format!("Test finding {}", id),
            severity,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "Test".into(),
            exploit_scenario: "Test".into(),
            evidence: vec![Evidence {
                location: format!("test.json > servers[{}] > tools[{}]", server, tool),
                description: "test evidence".into(),
                raw_value: None,
                region: None,
                file: None,
                json_pointer: None,
                server: None,
                tool: None,
                parameter: None,
            }],
            remediation: "Fix it".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        }
    }

    #[test]
    fn policy_ignore_rules() {
        let config = GuardConfig::from_toml(
            r#"
[ignore]
rules = ["MG006"]
"#,
        )
        .unwrap();

        let findings = vec![
            make_finding("MG001", Severity::High, "db", "query"),
            make_finding("MG006", Severity::Medium, "db", "info"),
        ];

        let result = apply_policy(&config, findings);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "MG001");
    }

    #[test]
    fn policy_ignore_finding_by_tool() {
        let config = GuardConfig::from_toml(
            r#"
[ignore]
findings = [
  { rule = "MG001", tool = "run_sql", reason = "safe" },
]
"#,
        )
        .unwrap();

        let findings = vec![
            make_finding("MG001", Severity::High, "db", "run_sql"),
            make_finding("MG001", Severity::High, "db", "run_cmd"),
        ];

        let result = apply_policy(&config, findings);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].evidence[0].location,
            "test.json > servers[db] > tools[run_cmd]"
        );
    }

    #[test]
    fn policy_ignore_finding_by_server() {
        let config = GuardConfig::from_toml(
            r#"
[ignore]
findings = [
  { rule = "MG004", server = "filesystem", reason = "sandboxed" },
]
"#,
        )
        .unwrap();

        let findings = vec![
            make_finding("MG004", Severity::High, "filesystem", "read_file"),
            make_finding("MG004", Severity::High, "database", "read_file"),
        ];

        let result = apply_policy(&config, findings);
        assert_eq!(result.len(), 1);
        assert!(result[0].evidence[0].location.contains("servers[database]"));
    }

    #[test]
    fn policy_ignore_finding_requires_both_tool_and_server() {
        let config = GuardConfig::from_toml(
            r#"
[ignore]
findings = [
  { rule = "MG001", tool = "exec", server = "shell", reason = "internal" },
]
"#,
        )
        .unwrap();

        let findings = vec![
            make_finding("MG001", Severity::High, "shell", "exec"), // match
            make_finding("MG001", Severity::High, "shell", "query"), // no tool match
            make_finding("MG001", Severity::High, "db", "exec"),    // no server match
        ];

        let result = apply_policy(&config, findings);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn policy_severity_override_downgrade() {
        let config = GuardConfig::from_toml(
            r#"
[severity_overrides]
MG001 = "low"
"#,
        )
        .unwrap();

        let findings = vec![make_finding("MG001", Severity::High, "db", "query")];

        let result = apply_policy(&config, findings);
        assert_eq!(result[0].severity, Severity::Low);
    }

    #[test]
    fn policy_severity_override_no_escalation() {
        let config = GuardConfig::from_toml(
            r#"
[severity_overrides]
MG001 = "critical"
"#,
        )
        .unwrap();

        let findings = vec![make_finding("MG001", Severity::Medium, "db", "query")];

        let result = apply_policy(&config, findings);
        // Should remain Medium — escalation not allowed
        assert_eq!(result[0].severity, Severity::Medium);
    }

    #[test]
    fn policy_combined_ignore_and_override() {
        let config = GuardConfig::from_toml(
            r#"
[ignore]
rules = ["MG006"]
findings = [
  { rule = "MG001", tool = "run_sql", reason = "safe" },
]

[severity_overrides]
MG004 = "low"
"#,
        )
        .unwrap();

        let findings = vec![
            make_finding("MG006", Severity::Medium, "db", "info"), // ignored by rule
            make_finding("MG001", Severity::High, "db", "run_sql"), // ignored by finding
            make_finding("MG001", Severity::High, "db", "run_cmd"), // kept, no override
            make_finding("MG004", Severity::High, "fs", "read_file"), // kept, severity → low
        ];

        let result = apply_policy(&config, findings);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "MG001");
        assert_eq!(result[0].severity, Severity::High);
        assert_eq!(result[1].id, "MG004");
        assert_eq!(result[1].severity, Severity::Low);
    }

    #[test]
    fn discovery_finds_config_in_directory() {
        let dir = tempdir();
        let config_path = dir.join(CONFIG_FILE_NAME);
        std::fs::write(&config_path, "fail_on = \"high\"").unwrap();

        let found = discover_config(&dir);
        assert!(found.is_some());
        let found = found.unwrap();
        assert!(found.ends_with(CONFIG_FILE_NAME));
    }

    #[test]
    fn discovery_finds_config_in_parent() {
        let dir = tempdir();
        let config_path = dir.join(CONFIG_FILE_NAME);
        std::fs::write(&config_path, "fail_on = \"high\"").unwrap();

        let child = dir.join("subdir");
        std::fs::create_dir_all(&child).unwrap();

        let found = discover_config(&child);
        assert!(found.is_some());
    }

    #[test]
    fn discovery_returns_none_when_absent() {
        let dir = tempdir();
        let child = dir.join("deep").join("nested");
        std::fs::create_dir_all(&child).unwrap();

        let found = discover_config(&child);
        assert!(found.is_none());
    }

    #[test]
    fn discovery_from_file_path() {
        let dir = tempdir();
        let config_path = dir.join(CONFIG_FILE_NAME);
        std::fs::write(&config_path, "").unwrap();
        let file_in_dir = dir.join("mcp.config.json");
        std::fs::write(&file_in_dir, "{}").unwrap();

        let found = discover_config(&file_in_dir);
        assert!(found.is_some());
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir()
            .join("mcplint-test")
            .join(format!("{}", std::process::id()))
            .join(format!("{:x}", rand_u64()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Simple deterministic-enough random for temp dir uniqueness.
    fn rand_u64() -> u64 {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}
