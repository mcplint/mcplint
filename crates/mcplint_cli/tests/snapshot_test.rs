use assert_cmd::Command;

fn fixture_path(name: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../tests/fixtures/{}", manifest_dir, name)
}

/// Normalize the fixture path out of snapshot output so it's deterministic
/// across machines.
fn normalize_output(output: &str, fixture: &str) -> String {
    output.replace(&fixture_path(fixture), &format!("fixtures/{}", fixture))
}

fn mcplint_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mcplint"))
}

#[test]
fn snapshot_scan_text() {
    let fixture = "vulnerable.tools.json";
    let cmd = mcplint_cmd()
        .args(["scan", &fixture_path(fixture), "--format", "text"])
        .output()
        .expect("failed to run mcplint");

    let stdout = String::from_utf8(cmd.stdout).unwrap();
    let normalized = normalize_output(&stdout, fixture);
    insta::assert_snapshot!("scan_text", normalized);
}

#[test]
fn snapshot_scan_markdown() {
    let fixture = "vulnerable.tools.json";
    let cmd = mcplint_cmd()
        .args(["scan", &fixture_path(fixture), "--format", "markdown"])
        .output()
        .expect("failed to run mcplint");

    let stdout = String::from_utf8(cmd.stdout).unwrap();
    let normalized = normalize_output(&stdout, fixture);
    insta::assert_snapshot!("scan_markdown", normalized);
}

#[test]
fn snapshot_explain_mg003() {
    let cmd = mcplint_cmd()
        .args(["explain", "MG003"])
        .output()
        .expect("failed to run mcplint");

    let stdout = String::from_utf8(cmd.stdout).unwrap();
    insta::assert_snapshot!("explain_mg003", stdout);
}
