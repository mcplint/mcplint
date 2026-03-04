use assert_cmd::cargo;
use assert_cmd::Command;

fn fixture_path(name: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../tests/fixtures/{}", manifest_dir, name)
}

fn mcplint_cmd() -> Command {
    Command::new(cargo::cargo_bin!("mcplint"))
}

#[test]
fn scan_with_custom_rules_produces_custom_findings() {
    let mut cmd = mcplint_cmd();
    let output = cmd
        .args([
            "scan",
            &fixture_path("custom_rules/test_config.json"),
            "--rules-dir",
            &fixture_path("custom_rules"),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();

    let ids: Vec<&str> = findings.iter().map(|f| f["id"].as_str().unwrap()).collect();

    // Custom rules fire
    assert!(ids.contains(&"TEST001"), "Expected TEST001 findings");
    assert!(ids.contains(&"TEST005"), "Expected TEST005 findings");

    // Built-in rules also fire
    assert!(
        ids.iter().any(|id| id.starts_with("MG")),
        "Expected MG* findings alongside custom"
    );
}

#[test]
fn scan_custom_rules_json_has_correct_fields() {
    let mut cmd = mcplint_cmd();
    let output = cmd
        .args([
            "scan",
            &fixture_path("custom_rules/test_config.json"),
            "--rules-dir",
            &fixture_path("custom_rules"),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();

    // Find TEST001 finding
    let test001 = findings.iter().find(|f| f["id"] == "TEST001").unwrap();
    assert_eq!(test001["title"], "All servers must have authentication");
    assert_eq!(test001["severity"], "high");
    assert_eq!(test001["confidence"], "high");
    assert_eq!(test001["category"], "static");

    // CWE/OWASP from custom rule
    let cwe = test001["cwe_ids"].as_array().unwrap();
    assert!(cwe.iter().any(|c| c == "CWE-306"));

    let owasp = test001["owasp_ids"].as_array().unwrap();
    assert!(owasp.iter().any(|o| o == "A07:2021"));
}

#[test]
fn list_rules_shows_custom() {
    let mut cmd = mcplint_cmd();
    let output = cmd
        .args(["list-rules", "--rules-dir", &fixture_path("custom_rules")])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Built-in rules present
    assert!(stdout.contains("MG001"), "Expected MG001 in list-rules");

    // Custom rules present
    assert!(stdout.contains("TEST001"), "Expected TEST001 in list-rules");
    assert!(stdout.contains("TEST002"), "Expected TEST002 in list-rules");
    assert!(stdout.contains("TEST005"), "Expected TEST005 in list-rules");
}

#[test]
fn explain_custom_rule() {
    let mut cmd = mcplint_cmd();
    let output = cmd
        .args([
            "explain",
            "TEST001",
            "--rules-dir",
            &fixture_path("custom_rules"),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TEST001"));
    assert!(stdout.contains("static"));
    assert!(stdout.contains("CWE-306"));
    assert!(stdout.contains("A07:2021"));
}

#[test]
fn scan_with_single_rule_file() {
    let mut cmd = mcplint_cmd();
    let output = cmd
        .args([
            "scan",
            &fixture_path("custom_rules/test_config.json"),
            "--rules",
            &fixture_path("custom_rules/require_auth.yaml"),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    let ids: Vec<&str> = findings.iter().map(|f| f["id"].as_str().unwrap()).collect();

    assert!(
        ids.contains(&"TEST001"),
        "Expected TEST001 from single rule file"
    );
    // Other TEST rules should NOT be present (only loaded require_auth.yaml)
    assert!(!ids.contains(&"TEST002"));
    assert!(!ids.contains(&"TEST005"));
}

#[test]
fn list_rules_without_custom_shows_only_builtin() {
    let mut cmd = mcplint_cmd();
    let output = cmd.args(["list-rules"]).output().unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("MG001"));
    assert!(!stdout.contains("TEST001"));
}

#[test]
fn scan_custom_rules_fingerprints_stable() {
    let run = || {
        let mut cmd = mcplint_cmd();
        let output = cmd
            .args([
                "scan",
                &fixture_path("custom_rules/test_config.json"),
                "--rules-dir",
                &fixture_path("custom_rules"),
                "--format",
                "json",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let findings = json["findings"].as_array().unwrap().clone();
        let mut fps: Vec<String> = findings
            .iter()
            .map(|f| f["fingerprint"].as_str().unwrap().to_string())
            .collect();
        fps.sort();
        fps
    };
    assert_eq!(run(), run(), "Fingerprints must be stable across runs");
}
