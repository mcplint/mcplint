//! Integration tests for realistic fixture scanning.
//!
//! Ensures all realistic fixtures load successfully through the adapter
//! pipeline and produce valid findings across all output formats.

use std::path::Path;

fn fixtures_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/realistic")
}

fn all_realistic_fixtures() -> Vec<std::path::PathBuf> {
    let base = fixtures_dir();
    let mut files = Vec::new();
    collect_json_files(&base, &mut files);
    files.sort();
    files
}

fn collect_json_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                collect_json_files(&path, files);
            } else if path.extension().is_some_and(|e| e == "json") {
                files.push(path);
            }
        }
    }
}

fn scan_fixture(path: &Path) -> mcplint_core::scan_context::ScanResult {
    let adapter_result = mcplint_core::adapters::auto_load(path)
        .unwrap_or_else(|e| panic!("adapter failed for {}: {e}", path.display()));

    let registry = mcplint_rules::default_registry();
    let ctx = mcplint_core::scan_context::ScanContext {
        config: adapter_result.config,
        source_path: path.display().to_string(),
        location_map: adapter_result.location_map,
        server_pointers: adapter_result.server_pointers,
    };
    let findings = registry.run_all(&ctx);
    mcplint_core::scan_context::ScanResult {
        source_path: ctx.source_path,
        findings,
    }
}

#[test]
fn all_realistic_fixtures_load_without_panic() {
    let fixtures = all_realistic_fixtures();
    assert!(
        fixtures.len() >= 5,
        "expected at least 5 realistic fixtures, found {}",
        fixtures.len()
    );

    for fixture in &fixtures {
        let result = scan_fixture(fixture);
        assert!(
            !result.source_path.is_empty(),
            "source_path should not be empty for {}",
            fixture.display()
        );
    }
}

#[test]
fn all_realistic_fixtures_produce_findings() {
    for fixture in &all_realistic_fixtures() {
        let result = scan_fixture(fixture);
        assert!(
            !result.findings.is_empty(),
            "{} should produce at least one finding",
            fixture.display()
        );
    }
}

#[test]
fn insecure_common_has_critical_findings() {
    let path = fixtures_dir().join("claude/insecure_common.json");
    let result = scan_fixture(&path);
    let critical_count = result
        .findings
        .iter()
        .filter(|f| f.severity == mcplint_core::finding::Severity::Critical)
        .count();
    assert!(
        critical_count >= 2,
        "insecure_common.json should have at least 2 critical findings, got {critical_count}"
    );
}

#[test]
fn large_org_heavy_has_many_findings() {
    let path = fixtures_dir().join("claude/large_org_heavy.json");
    let result = scan_fixture(&path);
    assert!(
        result.findings.len() >= 10,
        "large_org_heavy.json should produce at least 10 findings, got {}",
        result.findings.len()
    );
}

#[test]
fn all_output_formats_work_on_realistic_fixtures() {
    use mcplint_report::{render, OutputFormat};

    for fixture in &all_realistic_fixtures() {
        let result = scan_fixture(fixture);

        let text = render(&result.findings, &result.source_path, OutputFormat::Text);
        assert!(
            !text.is_empty(),
            "text output empty for {}",
            fixture.display()
        );

        let json = render(&result.findings, &result.source_path, OutputFormat::Json);
        assert!(
            !json.is_empty(),
            "json output empty for {}",
            fixture.display()
        );
        // Verify JSON is parseable
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("invalid JSON output for {}: {e}", fixture.display()));
        assert!(
            parsed.get("findings").is_some(),
            "JSON missing 'findings' key"
        );

        let md = render(
            &result.findings,
            &result.source_path,
            OutputFormat::Markdown,
        );
        assert!(
            !md.is_empty(),
            "markdown output empty for {}",
            fixture.display()
        );

        let sarif = render(&result.findings, &result.source_path, OutputFormat::Sarif);
        assert!(
            !sarif.is_empty(),
            "sarif output empty for {}",
            fixture.display()
        );
        let sarif_parsed: serde_json::Value = serde_json::from_str(&sarif)
            .unwrap_or_else(|e| panic!("invalid SARIF output for {}: {e}", fixture.display()));
        assert!(
            sarif_parsed.get("runs").is_some(),
            "SARIF missing 'runs' key for {}",
            fixture.display()
        );
    }
}

#[test]
fn docker_fixture_loads_as_claude_format() {
    let path = fixtures_dir().join("claude/docker_setup.json");
    let result = scan_fixture(&path);
    // Docker fixtures should still produce findings (shell/filesystem tools inferred)
    assert!(
        !result.findings.is_empty(),
        "docker_setup.json should produce findings"
    );
}

#[test]
fn cursor_fixture_loads_successfully() {
    let path = fixtures_dir().join("cursor/typical.json");
    let result = scan_fixture(&path);
    assert!(
        !result.findings.is_empty(),
        "cursor/typical.json should produce findings"
    );
}
