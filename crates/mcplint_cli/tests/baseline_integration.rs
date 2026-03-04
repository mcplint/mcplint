//! Integration tests for mcplint baseline create + diff.

use assert_cmd::cargo;
use assert_cmd::Command;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn mcplint() -> Command {
    Command::new(cargo::cargo_bin!("mcplint"))
}

// ── baseline create ──

#[test]
fn baseline_create_outputs_valid_json() {
    let output = mcplint()
        .args([
            "baseline",
            "create",
            fixture_path("baseline/base_config.json").to_str().unwrap(),
        ])
        .output()
        .expect("failed to run");

    assert!(output.status.success(), "exit code should be 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(parsed["version"], 1);
    assert!(parsed["servers"].is_array());
}

#[test]
fn baseline_create_deterministic() {
    let run = || {
        let output = mcplint()
            .args([
                "baseline",
                "create",
                fixture_path("baseline/base_config.json").to_str().unwrap(),
            ])
            .output()
            .expect("failed to run");
        // Remove created_at for comparison since it includes timestamps
        let mut v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        v.as_object_mut().unwrap().remove("created_at");
        v.as_object_mut().unwrap().remove("source");
        serde_json::to_string(&v).unwrap()
    };
    assert_eq!(run(), run(), "two runs should produce identical baselines");
}

#[test]
fn baseline_create_writes_to_file() {
    let tmp = std::env::temp_dir().join("mcplint-test-baseline-out.json");
    let _ = std::fs::remove_file(&tmp);

    let output = mcplint()
        .args([
            "baseline",
            "create",
            fixture_path("baseline/base_config.json").to_str().unwrap(),
            "--out",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run");

    assert!(output.status.success());
    assert!(tmp.exists(), "output file should be created");
    let content = std::fs::read_to_string(&tmp).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["version"], 1);

    std::fs::remove_file(&tmp).ok();
}

// ── baseline diff ──

#[test]
fn baseline_diff_no_drift_same_config() {
    let tmp = std::env::temp_dir().join("mcplint-test-no-drift.json");

    // Create baseline
    mcplint()
        .args([
            "baseline",
            "create",
            fixture_path("baseline/base_config.json").to_str().unwrap(),
            "--out",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("create failed");

    // Diff same config against baseline
    let output = mcplint()
        .args([
            "baseline",
            "diff",
            fixture_path("baseline/base_config.json").to_str().unwrap(),
            "--baseline",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("diff failed");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No drift detected"),
        "should report no drift, got: {}",
        stdout
    );

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn baseline_diff_detects_drift() {
    let tmp = std::env::temp_dir().join("mcplint-test-drift.json");

    // Create baseline from base config
    mcplint()
        .args([
            "baseline",
            "create",
            fixture_path("baseline/base_config.json").to_str().unwrap(),
            "--out",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("create failed");

    // Diff drifted config against baseline (text format)
    let output = mcplint()
        .args([
            "baseline",
            "diff",
            fixture_path("baseline/drifted_config.json")
                .to_str()
                .unwrap(),
            "--baseline",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("diff failed");

    assert!(
        output.status.success(),
        "without --fail-on-drift should exit 0"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("shell-executor"),
        "should mention added server"
    );

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn baseline_diff_fail_on_drift_exits_2() {
    let tmp = std::env::temp_dir().join("mcplint-test-fail-drift.json");

    // Create baseline from base config
    mcplint()
        .args([
            "baseline",
            "create",
            fixture_path("baseline/base_config.json").to_str().unwrap(),
            "--out",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("create failed");

    // Diff drifted config with --fail-on-drift
    let output = mcplint()
        .args([
            "baseline",
            "diff",
            fixture_path("baseline/drifted_config.json")
                .to_str()
                .unwrap(),
            "--baseline",
            tmp.to_str().unwrap(),
            "--fail-on-drift",
        ])
        .output()
        .expect("diff failed");

    assert_eq!(
        output.status.code(),
        Some(2),
        "should exit 2 on risky drift (policy violation)"
    );

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn baseline_diff_json_format() {
    let tmp = std::env::temp_dir().join("mcplint-test-json-diff.json");

    mcplint()
        .args([
            "baseline",
            "create",
            fixture_path("baseline/base_config.json").to_str().unwrap(),
            "--out",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("create failed");

    let output = mcplint()
        .args([
            "baseline",
            "diff",
            fixture_path("baseline/drifted_config.json")
                .to_str()
                .unwrap(),
            "--baseline",
            tmp.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("diff failed");

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("diff output should be valid JSON");
    assert!(parsed["added_servers"].is_array());
    assert!(parsed["has_risky_drift"].is_boolean());

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn baseline_diff_markdown_format() {
    let tmp = std::env::temp_dir().join("mcplint-test-md-diff.json");

    mcplint()
        .args([
            "baseline",
            "create",
            fixture_path("baseline/base_config.json").to_str().unwrap(),
            "--out",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("create failed");

    let output = mcplint()
        .args([
            "baseline",
            "diff",
            fixture_path("baseline/drifted_config.json")
                .to_str()
                .unwrap(),
            "--baseline",
            tmp.to_str().unwrap(),
            "--format",
            "markdown",
        ])
        .output()
        .expect("diff failed");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# mcplint Baseline Diff"));

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn baseline_diff_bad_baseline_file_exits_nonzero() {
    let bad_file = std::env::temp_dir().join("mcplint-test-bad.json");
    std::fs::write(&bad_file, "NOT VALID JSON").ok();

    let output = mcplint()
        .args([
            "baseline",
            "diff",
            fixture_path("baseline/base_config.json").to_str().unwrap(),
            "--baseline",
            bad_file.to_str().unwrap(),
        ])
        .output()
        .expect("diff should run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "should exit 1 for operational error (bad baseline JSON)"
    );

    std::fs::remove_file(&bad_file).ok();
}

// ── realistic fixture baselines ──

#[test]
fn baseline_create_works_on_realistic_fixtures() {
    let fixtures = [
        "realistic/claude/developer_typical.json",
        "realistic/claude/large_org_heavy.json",
        "realistic/claude/insecure_common.json",
        "realistic/claude/docker_setup.json",
        "realistic/cursor/typical.json",
    ];

    for fixture in &fixtures {
        let output = mcplint()
            .args([
                "baseline",
                "create",
                fixture_path(fixture).to_str().unwrap(),
            ])
            .output()
            .unwrap_or_else(|e| panic!("failed to run baseline create on {}: {}", fixture, e));

        assert!(
            output.status.success(),
            "baseline create should succeed for {}, stderr: {}",
            fixture,
            String::from_utf8_lossy(&output.stderr)
        );

        let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("invalid baseline JSON for {}: {}", fixture, e));
        assert_eq!(parsed["version"], 1, "version should be 1 for {}", fixture);
        assert!(
            parsed["servers"].is_array(),
            "servers should be array for {}",
            fixture
        );
    }
}
