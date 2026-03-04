use std::process::Command;

fn fixture_path(name: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../tests/fixtures/{}", manifest_dir, name)
}

fn mcplint() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mcplint"))
}

#[test]
fn fix_dry_run_does_not_modify_file() {
    let src = fixture_path("fix/mg001_before.tools.json");
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let target = tmp_dir.path().join("test.tools.json");
    std::fs::copy(&src, &target).unwrap();

    let original = std::fs::read_to_string(&target).unwrap();

    let output = mcplint()
        .args(["scan", &target.display().to_string(), "--fix-dry-run"])
        .output()
        .expect("Failed to run mcplint");

    assert!(output.status.success());

    let after = std::fs::read_to_string(&target).unwrap();
    assert_eq!(
        original, after,
        "File should NOT be modified in dry-run mode"
    );

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("fixes would be applied"),
        "Should report fixes in dry run: {}",
        stderr
    );
}

#[test]
fn fix_modifies_file() {
    let src = fixture_path("fix/mg001_before.tools.json");
    let tmp = tempfile::NamedTempFile::new_in(std::env::temp_dir())
        .unwrap()
        .into_temp_path();
    let tmp_path = tmp.to_path_buf();
    // Create with .tools.json extension so native adapter detects it
    let target = tmp_path.with_extension("tools.json");
    std::fs::copy(&src, &target).unwrap();

    let original = std::fs::read_to_string(&target).unwrap();

    let output = mcplint()
        .args(["scan", &target.display().to_string(), "--fix"])
        .output()
        .expect("Failed to run mcplint");

    assert!(output.status.success());

    let after = std::fs::read_to_string(&target).unwrap();
    assert_ne!(original, after, "File SHOULD be modified by --fix");

    let val: serde_json::Value = serde_json::from_str(&after).unwrap();
    // MG001 fix should have added maxLength
    assert!(
        after.contains("maxLength"),
        "Fixed file should contain maxLength"
    );
    // Check it's valid JSON
    assert!(val.is_object());

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("Applied"),
        "Should report applied fixes: {}",
        stderr
    );

    let _ = std::fs::remove_file(&target);
}

#[test]
fn fix_on_directory_errors() {
    let fixture_dir = fixture_path("fix");

    let output = mcplint()
        .args(["scan", &fixture_dir, "--fix"])
        .output()
        .expect("Failed to run mcplint");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Should exit 1 for operational error"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("single file target"),
        "Should error about single file: {}",
        stderr
    );
}

#[test]
fn fix_mutual_exclusivity() {
    let src = fixture_path("fix/mg001_before.tools.json");

    let output = mcplint()
        .args(["scan", &src, "--fix", "--fix-dry-run"])
        .output()
        .expect("Failed to run mcplint");

    assert_eq!(
        output.status.code(),
        Some(2),
        "clap conflict exits with code 2"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("cannot be used with"),
        "Should error about mutual exclusivity: {}",
        stderr
    );
}

#[test]
fn fix_already_fixed_no_changes() {
    let src = fixture_path("fix/already_fixed.tools.json");
    let tmp = tempfile::NamedTempFile::new_in(std::env::temp_dir())
        .unwrap()
        .into_temp_path();
    let tmp_path = tmp.to_path_buf();
    let target = tmp_path.with_extension("tools.json");
    std::fs::copy(&src, &target).unwrap();

    let original = std::fs::read_to_string(&target).unwrap();

    let output = mcplint()
        .args(["scan", &target.display().to_string(), "--fix-dry-run"])
        .output()
        .expect("Failed to run mcplint");

    assert!(output.status.success());

    let after = std::fs::read_to_string(&target).unwrap();
    assert_eq!(original, after, "Already-fixed file should not change");

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("No auto-fixable findings found") || stderr.contains("0 fixes"),
        "Should report no fixes needed: {}",
        stderr
    );

    let _ = std::fs::remove_file(&target);
}

#[test]
fn fix_mg005_shows_action_required() {
    let src = fixture_path("fix/mg005_before.json");
    let tmp = tempfile::NamedTempFile::new_in(std::env::temp_dir())
        .unwrap()
        .into_temp_path();
    let target = tmp.to_path_buf().with_extension("json");
    std::fs::copy(&src, &target).unwrap();

    let output = mcplint()
        .args(["scan", &target.display().to_string(), "--fix"])
        .output()
        .expect("Failed to run mcplint");

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("ACTION REQUIRED") || stderr.contains("REPLACE_ME"),
        "MG005 fix should warn about placeholders: {}",
        stderr
    );

    let after = std::fs::read_to_string(&target).unwrap();
    assert!(
        after.contains("REPLACE_ME"),
        "Fixed file should contain REPLACE_ME placeholder"
    );

    let _ = std::fs::remove_file(&target);
}
