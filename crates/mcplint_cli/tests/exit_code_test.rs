//! Tests for CI-predictable exit code behavior.
//!
//! Exit 0 = success (no findings above threshold)
//! Exit 1 = operational error (bad input, parse failure)
//! Exit 2 = policy violation (findings above threshold)

use std::path::PathBuf;
use std::process::Command;

fn mcplint_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mcplint"))
}

fn fixture_path(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .display()
        .to_string()
}

// ── Scan exit codes ──

#[test]
fn scan_clean_config_exits_0() {
    let output = mcplint_bin()
        .args(["scan", &fixture_path("rules/all_safe.json")])
        .output()
        .expect("failed to run");

    assert_eq!(output.status.code(), Some(0), "Clean scan should exit 0");
}

#[test]
fn scan_without_fail_on_always_exits_0() {
    let output = mcplint_bin()
        .args(["scan", &fixture_path("vulnerable.tools.json")])
        .output()
        .expect("failed to run");

    assert_eq!(
        output.status.code(),
        Some(0),
        "Scan without --fail-on should exit 0 even with findings"
    );
}

#[test]
fn scan_findings_below_threshold_exits_0() {
    // diff/baseline.tools.json has medium+high but no critical
    let output = mcplint_bin()
        .args([
            "scan",
            &fixture_path("diff/baseline.tools.json"),
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("failed to run");

    assert_eq!(
        output.status.code(),
        Some(0),
        "Findings below threshold should exit 0"
    );
}

#[test]
fn scan_findings_at_threshold_exits_2() {
    // vulnerable.tools.json has high findings
    let output = mcplint_bin()
        .args([
            "scan",
            &fixture_path("vulnerable.tools.json"),
            "--fail-on",
            "high",
        ])
        .output()
        .expect("failed to run");

    assert_eq!(
        output.status.code(),
        Some(2),
        "Findings at threshold should exit 2"
    );
}

#[test]
fn scan_findings_above_threshold_exits_2() {
    // vulnerable.tools.json has critical findings, threshold is high
    let output = mcplint_bin()
        .args([
            "scan",
            &fixture_path("vulnerable.tools.json"),
            "--fail-on",
            "high",
        ])
        .output()
        .expect("failed to run");

    assert_eq!(
        output.status.code(),
        Some(2),
        "Findings above threshold should exit 2"
    );
}

#[test]
fn scan_fail_on_critical_exits_2() {
    // vulnerable.tools.json has critical findings
    let output = mcplint_bin()
        .args([
            "scan",
            &fixture_path("vulnerable.tools.json"),
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("failed to run");

    assert_eq!(
        output.status.code(),
        Some(2),
        "Critical findings with --fail-on critical should exit 2"
    );
}

#[test]
fn scan_fail_on_critical_with_only_high_exits_0() {
    // diff/baseline.tools.json has high+medium but no critical
    let output = mcplint_bin()
        .args([
            "scan",
            &fixture_path("diff/baseline.tools.json"),
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("failed to run");

    assert_eq!(
        output.status.code(),
        Some(0),
        "Only high findings with --fail-on critical should exit 0"
    );
}

#[test]
fn scan_nonexistent_file_exits_1() {
    let output = mcplint_bin()
        .args(["scan", "/nonexistent/path/config.json"])
        .output()
        .expect("failed to run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Nonexistent file should exit 1 (operational error)"
    );
}

#[test]
fn scan_invalid_json_exits_1() {
    let tmp = tempfile::Builder::new()
        .suffix(".tools.json")
        .tempfile()
        .unwrap();
    std::fs::write(tmp.path(), "NOT VALID JSON {{{").unwrap();

    let output = mcplint_bin()
        .args(["scan", tmp.path().to_str().unwrap()])
        .output()
        .expect("failed to run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Invalid JSON should exit 1 (operational error)"
    );
}

#[test]
fn scan_stdin_bad_json_exits_1() {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = mcplint_bin()
        .args(["scan", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"NOT VALID JSON")
        .unwrap();

    let output = child.wait_with_output().expect("failed to wait");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Bad JSON via stdin should exit 1 (operational error)"
    );
}

// ── Diff exit codes ──

#[test]
fn diff_no_new_findings_exits_0() {
    let fixture = fixture_path("diff/baseline.tools.json");
    let dir = tempfile::tempdir().unwrap();
    let bl_path = dir.path().join("baseline.json");

    // Create baseline
    mcplint_bin()
        .args([
            "scan",
            &fixture,
            "--save-baseline",
            bl_path.to_str().unwrap(),
        ])
        .output()
        .expect("save baseline");

    // Diff same file
    let output = mcplint_bin()
        .args(["diff", &fixture, "--baseline", bl_path.to_str().unwrap()])
        .output()
        .expect("diff");

    assert_eq!(
        output.status.code(),
        Some(0),
        "No new findings should exit 0"
    );
}

#[test]
fn diff_new_findings_exits_2() {
    let baseline_fixture = fixture_path("diff/baseline.tools.json");
    let evolved_fixture = fixture_path("diff/evolved.tools.json");
    let dir = tempfile::tempdir().unwrap();
    let bl_path = dir.path().join("baseline.json");

    // Create baseline
    mcplint_bin()
        .args([
            "scan",
            &baseline_fixture,
            "--save-baseline",
            bl_path.to_str().unwrap(),
        ])
        .output()
        .expect("save baseline");

    // Diff evolved file
    let output = mcplint_bin()
        .args([
            "diff",
            &evolved_fixture,
            "--baseline",
            bl_path.to_str().unwrap(),
        ])
        .output()
        .expect("diff");

    assert_eq!(
        output.status.code(),
        Some(2),
        "New findings should exit 2 (policy violation)"
    );
}

#[test]
fn diff_bad_baseline_exits_1() {
    let output = mcplint_bin()
        .args([
            "diff",
            &fixture_path("diff/baseline.tools.json"),
            "--baseline",
            "/nonexistent/baseline.json",
        ])
        .output()
        .expect("diff");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Missing baseline should exit 1 (operational error)"
    );
}

// ── Baseline diff exit codes ──

#[test]
fn baseline_diff_risky_drift_exits_2() {
    let tmp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();

    // Create baseline from base config
    mcplint_bin()
        .args([
            "baseline",
            "create",
            &fixture_path("baseline/base_config.json"),
            "--out",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .expect("create failed");

    // Diff drifted config with --fail-on-drift
    let output = mcplint_bin()
        .args([
            "baseline",
            "diff",
            &fixture_path("baseline/drifted_config.json"),
            "--baseline",
            tmp.path().to_str().unwrap(),
            "--fail-on-drift",
        ])
        .output()
        .expect("diff failed");

    assert_eq!(
        output.status.code(),
        Some(2),
        "Risky drift should exit 2 (policy violation)"
    );
}

// ── Explain exit codes ──

#[test]
fn explain_bad_rule_exits_1() {
    let output = mcplint_bin()
        .args(["explain", "MG999"])
        .output()
        .expect("failed to run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Unknown rule should exit 1 (operational error)"
    );
}

#[test]
fn explain_valid_rule_exits_0() {
    let output = mcplint_bin()
        .args(["explain", "MG001"])
        .output()
        .expect("failed to run");

    assert_eq!(output.status.code(), Some(0), "Valid rule should exit 0");
}
