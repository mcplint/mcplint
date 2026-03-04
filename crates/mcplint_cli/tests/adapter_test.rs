use mcplint_core::adapters::{self, McpAdapter};
use mcplint_core::*;
use std::path::Path;

fn fixture_path(name: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../tests/fixtures/{}", manifest_dir, name)
}

// ── Claude Desktop adapter tests ──

#[test]
fn claude_desktop_detect() {
    let adapter = adapters::claude_desktop::ClaudeDesktopAdapter;
    let path_str = fixture_path("claude_desktop/claude_desktop_config.json");
    assert!(adapter.detect(Path::new(&path_str)));
}

#[test]
fn claude_desktop_detect_directory() {
    let adapter = adapters::claude_desktop::ClaudeDesktopAdapter;
    let path_str = fixture_path("claude_desktop");
    assert!(adapter.detect(Path::new(&path_str)));
}

#[test]
fn claude_desktop_load_file() {
    let adapter = adapters::claude_desktop::ClaudeDesktopAdapter;
    let path_str = fixture_path("claude_desktop/claude_desktop_config.json");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    assert_eq!(result.adapter_name, "claude-desktop");
    assert_eq!(result.config.servers.len(), 3);

    // Servers should be sorted by name
    let names: Vec<&str> = result
        .config
        .servers
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(names, vec!["custom-api", "filesystem", "postgres-db"]);
}

#[test]
fn claude_desktop_infers_filesystem_tools() {
    let adapter = adapters::claude_desktop::ClaudeDesktopAdapter;
    let path_str = fixture_path("claude_desktop/claude_desktop_config.json");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    let fs_server = result
        .config
        .servers
        .iter()
        .find(|s| s.name == "filesystem")
        .unwrap();
    assert!(!fs_server.tools.is_empty());
    assert!(fs_server.tools.iter().any(|t| t.name == "read_file"));
    assert!(fs_server.tools.iter().any(|t| t.name == "write_file"));
    assert_eq!(fs_server.transport, "stdio");
}

#[test]
fn claude_desktop_infers_postgres_tools() {
    let adapter = adapters::claude_desktop::ClaudeDesktopAdapter;
    let path_str = fixture_path("claude_desktop/claude_desktop_config.json");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    let pg_server = result
        .config
        .servers
        .iter()
        .find(|s| s.name == "postgres-db")
        .unwrap();
    assert!(!pg_server.tools.is_empty());
    assert!(pg_server.tools.iter().any(|t| t.name == "query"));
}

#[test]
fn claude_desktop_infers_auth_from_env() {
    let adapter = adapters::claude_desktop::ClaudeDesktopAdapter;
    let path_str = fixture_path("claude_desktop/claude_desktop_config.json");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    let api_server = result
        .config
        .servers
        .iter()
        .find(|s| s.name == "custom-api")
        .unwrap();
    assert!(matches!(api_server.auth, AuthConfig::ApiKey { .. }));
}

#[test]
fn claude_desktop_unknown_server_has_empty_tools_and_warning() {
    let adapter = adapters::claude_desktop::ClaudeDesktopAdapter;
    let path_str = fixture_path("claude_desktop/claude_desktop_config.json");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    let custom = result
        .config
        .servers
        .iter()
        .find(|s| s.name == "custom-api")
        .unwrap();
    assert!(custom.tools.is_empty());
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains("custom-api") && w.contains("could not infer")));
}

// ── Cursor adapter tests ──

#[test]
fn cursor_detect_directory() {
    let adapter = adapters::cursor::CursorAdapter;
    let path_str = fixture_path("cursor");
    assert!(adapter.detect(Path::new(&path_str)));
}

#[test]
fn cursor_load_directory() {
    let adapter = adapters::cursor::CursorAdapter;
    let path_str = fixture_path("cursor");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    assert_eq!(result.adapter_name, "cursor");
    assert_eq!(result.config.servers.len(), 2);

    let names: Vec<&str> = result
        .config
        .servers
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(names, vec!["fetch-server", "shell-runner"]);
}

#[test]
fn cursor_infers_shell_tools() {
    let adapter = adapters::cursor::CursorAdapter;
    let path_str = fixture_path("cursor");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    let shell = result
        .config
        .servers
        .iter()
        .find(|s| s.name == "shell-runner")
        .unwrap();
    assert!(shell.tools.iter().any(|t| t.name == "run_command"));
}

#[test]
fn cursor_infers_auth_from_token() {
    let adapter = adapters::cursor::CursorAdapter;
    let path_str = fixture_path("cursor");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    let fetch = result
        .config
        .servers
        .iter()
        .find(|s| s.name == "fetch-server")
        .unwrap();
    assert!(matches!(fetch.auth, AuthConfig::Bearer { .. }));
}

// ── Auto-detection tests ──

#[test]
fn auto_load_detects_claude_desktop() {
    let path_str = fixture_path("claude_desktop/claude_desktop_config.json");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "claude-desktop");
}

#[test]
fn auto_load_detects_cursor_directory() {
    let path_str = fixture_path("cursor");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "cursor");
}

#[test]
fn auto_load_falls_back_to_native() {
    let path_str = fixture_path("vulnerable.tools.json");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "native");
}

#[test]
fn auto_load_native_safe() {
    let path_str = fixture_path("safe.tools.json");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "native");
    assert!(result.warnings.is_empty());
}

// ── Integration: scan Claude Desktop fixture triggers rules ──

#[test]
fn scan_claude_desktop_triggers_rules() {
    let path_str = fixture_path("claude_desktop/claude_desktop_config.json");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();

    let ctx = ScanContext::new(result.config, path_str);
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    assert!(
        !findings.is_empty(),
        "Claude Desktop config should trigger findings"
    );

    // MG004: filesystem tools have unconfined paths
    assert!(
        findings.iter().any(|f| f.id == "MG004"),
        "Expected MG004 for unconfined filesystem paths"
    );

    // MG001: SQL query parameter is unbounded
    assert!(
        findings.iter().any(|f| f.id == "MG001"),
        "Expected MG001 for unbounded SQL query parameter"
    );

    // MG005: filesystem server has no auth
    assert!(
        findings.iter().any(|f| f.id == "MG005"),
        "Expected MG005 for missing auth on filesystem server"
    );
}

#[test]
fn scan_cursor_triggers_rules() {
    let path_str = fixture_path("cursor");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();

    let ctx = ScanContext::new(result.config, path_str);
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    assert!(
        !findings.is_empty(),
        "Cursor config should trigger findings"
    );

    // MG001: shell command is unbounded string
    assert!(
        findings.iter().any(|f| f.id == "MG001"),
        "Expected MG001 for unbounded shell command"
    );
}

// ── CLI integration ──

#[test]
fn cli_scan_claude_desktop_file() {
    let fixture = fixture_path("claude_desktop/claude_desktop_config.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mcplint"))
        .args(["scan", &fixture, "--format", "json"])
        .output()
        .expect("Failed to run mcplint");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed["summary"]["total"].as_u64().unwrap() > 0);
}

#[test]
fn cli_scan_cursor_directory() {
    let fixture = fixture_path("cursor");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mcplint"))
        .args(["scan", &fixture, "--format", "json"])
        .output()
        .expect("Failed to run mcplint");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed["summary"]["total"].as_u64().unwrap() > 0);
}

#[test]
fn cli_export_claude_desktop() {
    let fixture = fixture_path("claude_desktop/claude_desktop_config.json");
    let tmp_dir = std::env::temp_dir().join("mcplint-export-test");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mcplint"))
        .args(["export", &fixture, "--out", &tmp_dir.display().to_string()])
        .output()
        .expect("Failed to run mcplint");

    assert!(output.status.success());

    // Check that mcp.config.json was written
    let config_path = tmp_dir.join("mcp.config.json");
    assert!(config_path.exists(), "mcp.config.json should be created");

    let config_content = std::fs::read_to_string(&config_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&config_content).unwrap();
    assert!(!parsed["servers"].as_array().unwrap().is_empty());

    // Check that per-server tools files were written (safe filenames)
    let entries: Vec<_> = std::fs::read_dir(&tmp_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tools.json"))
        .collect();
    assert!(
        !entries.is_empty(),
        "at least one tools.json file should exist"
    );
    // Verify no path traversal in filenames
    for entry in &entries {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(!name.contains(".."), "filename must not contain '..'");
        assert!(!name.contains('/'), "filename must not contain '/'");
        assert!(
            name.starts_with("server-"),
            "filename should use safe prefix"
        );
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ── Minimal Claude Desktop fixture tests ──

#[test]
fn claude_desktop_minimal_loads() {
    let adapter = adapters::claude_desktop::ClaudeDesktopAdapter;
    let path_str = fixture_path("claude_desktop/minimal");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    assert_eq!(result.adapter_name, "claude-desktop");
    assert_eq!(result.config.servers.len(), 1);
    assert_eq!(result.config.servers[0].name, "notes");
    // Unknown server → tools are empty, with a warning
    assert!(result.config.servers[0].tools.is_empty());
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains("could not infer")));
}

#[test]
fn claude_desktop_minimal_has_source_info() {
    let adapter = adapters::claude_desktop::ClaudeDesktopAdapter;
    let path_str = fixture_path("claude_desktop/minimal");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    assert_eq!(result.source_info.len(), result.config.servers.len());
    assert!(result.source_info[0]
        .json_pointer
        .as_ref()
        .unwrap()
        .contains("mcpServers"));
}

#[test]
fn scan_minimal_claude_desktop_no_crash() {
    // Partial model (no tools) must not crash the scan
    let path_str = fixture_path("claude_desktop/minimal");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();

    let ctx = ScanContext::new(result.config, path_str);
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    // MG005 should fire (no auth on the server)
    assert!(
        findings.iter().any(|f| f.id == "MG005"),
        "Expected MG005 for missing auth even on minimal config"
    );
}

// ── Unsafe Claude Desktop fixture tests ──

#[test]
fn claude_desktop_unsafe_triggers_multiple_rules() {
    let path_str = fixture_path("claude_desktop/unsafe");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();

    assert_eq!(result.adapter_name, "claude-desktop");
    assert_eq!(result.config.servers.len(), 4);

    let ctx = ScanContext::new(result.config, path_str);
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    assert!(!findings.is_empty());

    // MG001: unbounded SQL query param in postgres
    assert!(findings.iter().any(|f| f.id == "MG001"), "Expected MG001");
    // MG004: unconfined filesystem access
    assert!(findings.iter().any(|f| f.id == "MG004"), "Expected MG004");
    // MG005: hardcoded DB_PASSWORD or missing auth
    assert!(findings.iter().any(|f| f.id == "MG005"), "Expected MG005");
}

#[test]
fn claude_desktop_unsafe_inferred_tools_have_provenance() {
    let path_str = fixture_path("claude_desktop/unsafe");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();

    for server in &result.config.servers {
        for tool in &server.tools {
            assert_eq!(
                tool.provenance,
                ToolProvenance::Inferred,
                "Tool '{}' in server '{}' should be marked Inferred",
                tool.name,
                server.name
            );
        }
    }
}

// ── Export round-trip test ──

#[test]
fn export_roundtrip_produces_same_findings() {
    let fixture = fixture_path("claude_desktop/unsafe");
    let tmp_dir = std::env::temp_dir().join("mcplint-roundtrip-test");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // Step 1: scan original
    let result_original = adapters::auto_load(Path::new(&fixture)).unwrap();
    let ctx1 = ScanContext::new(result_original.config.clone(), fixture.clone());
    let registry = mcplint_rules::default_registry();
    let findings_original = registry.run_all(&ctx1);

    // Step 2: export
    let export_output = std::process::Command::new(env!("CARGO_BIN_EXE_mcplint"))
        .args(["export", &fixture, "--out", &tmp_dir.display().to_string()])
        .output()
        .expect("Failed to run export");
    assert!(export_output.status.success());

    // Step 3: scan the exported mcp.config.json
    let exported_config_path = tmp_dir.join("mcp.config.json");
    let result_exported = adapters::auto_load(&exported_config_path).unwrap();
    let ctx2 = ScanContext::new(
        result_exported.config,
        exported_config_path.display().to_string(),
    );
    let findings_exported = registry.run_all(&ctx2);

    // Step 4: verify same findings (by id + title)
    assert_eq!(
        findings_original.len(),
        findings_exported.len(),
        "Round-trip should produce same number of findings.\n\
         Original: {:?}\n\
         Exported: {:?}",
        findings_original
            .iter()
            .map(|f| format!("{}: {}", f.id, f.title))
            .collect::<Vec<_>>(),
        findings_exported
            .iter()
            .map(|f| format!("{}: {}", f.id, f.title))
            .collect::<Vec<_>>(),
    );

    for (orig, exported) in findings_original.iter().zip(findings_exported.iter()) {
        assert_eq!(orig.id, exported.id, "Finding IDs should match");
        assert_eq!(
            orig.severity, exported.severity,
            "Severities should match for {}",
            orig.id
        );
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ── Cursor minimal/unsafe fixture tests ──

#[test]
fn cursor_minimal_loads() {
    let adapter = adapters::cursor::CursorAdapter;
    let path_str = fixture_path("cursor/minimal");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    assert_eq!(result.adapter_name, "cursor");
    assert_eq!(result.config.servers.len(), 1);
    assert_eq!(result.config.servers[0].name, "notes");
    assert!(result.config.servers[0].tools.is_empty());
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains("could not infer")));
}

#[test]
fn cursor_minimal_has_source_info() {
    let adapter = adapters::cursor::CursorAdapter;
    let path_str = fixture_path("cursor/minimal");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    assert_eq!(result.source_info.len(), result.config.servers.len());
    assert!(result.source_info[0]
        .json_pointer
        .as_ref()
        .unwrap()
        .contains("mcpServers"));
}

#[test]
fn scan_minimal_cursor_no_crash() {
    let path_str = fixture_path("cursor/minimal");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();

    assert_eq!(result.adapter_name, "cursor");

    let ctx = ScanContext::new(result.config, path_str);
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    // MG005 should fire (no auth)
    assert!(
        findings.iter().any(|f| f.id == "MG005"),
        "Expected MG005 for missing auth on minimal Cursor config"
    );
}

#[test]
fn cursor_unsafe_triggers_multiple_rules() {
    let path_str = fixture_path("cursor/unsafe");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();

    assert_eq!(result.adapter_name, "cursor");
    assert_eq!(result.config.servers.len(), 4);

    let ctx = ScanContext::new(result.config, path_str);
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    assert!(!findings.is_empty());

    // MG001: unbounded SQL query in postgres
    assert!(findings.iter().any(|f| f.id == "MG001"), "Expected MG001");
    // MG004: unconfined filesystem
    assert!(findings.iter().any(|f| f.id == "MG004"), "Expected MG004");
    // MG005: missing auth or hardcoded secrets
    assert!(findings.iter().any(|f| f.id == "MG005"), "Expected MG005");
}

#[test]
fn cursor_unsafe_inferred_tools_have_provenance() {
    let path_str = fixture_path("cursor/unsafe");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();

    for server in &result.config.servers {
        for tool in &server.tools {
            assert_eq!(
                tool.provenance,
                ToolProvenance::Inferred,
                "Tool '{}' in server '{}' should be Inferred",
                tool.name,
                server.name
            );
        }
    }
}

#[test]
fn cli_export_cursor_roundtrip() {
    let fixture = fixture_path("cursor/unsafe");
    let tmp_dir = std::env::temp_dir().join("mcplint-cursor-roundtrip");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // Scan original
    let result_original = adapters::auto_load(Path::new(&fixture)).unwrap();
    let ctx1 = ScanContext::new(result_original.config.clone(), fixture.clone());
    let registry = mcplint_rules::default_registry();
    let findings_original = registry.run_all(&ctx1);

    // Export
    let export_output = std::process::Command::new(env!("CARGO_BIN_EXE_mcplint"))
        .args(["export", &fixture, "--out", &tmp_dir.display().to_string()])
        .output()
        .expect("Failed to run export");
    assert!(export_output.status.success());

    // Scan exported
    let exported_config_path = tmp_dir.join("mcp.config.json");
    let result_exported = adapters::auto_load(&exported_config_path).unwrap();
    let ctx2 = ScanContext::new(
        result_exported.config,
        exported_config_path.display().to_string(),
    );
    let findings_exported = registry.run_all(&ctx2);

    assert_eq!(
        findings_original.len(),
        findings_exported.len(),
        "Cursor round-trip should preserve findings"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ── Generic adapter tests ──

#[test]
fn generic_detect_directory() {
    let adapter = adapters::generic::GenericAdapter;
    let path_str = fixture_path("generic/minimal");
    assert!(adapter.detect(Path::new(&path_str)));
}

#[test]
fn generic_loads_mcp_config_format() {
    let adapter = adapters::generic::GenericAdapter;
    let path_str = fixture_path("generic/minimal");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    assert_eq!(result.adapter_name, "generic");
    assert_eq!(result.config.servers.len(), 1);
    assert_eq!(result.config.servers[0].name, "custom-tools");
    assert_eq!(result.config.servers[0].tools.len(), 2);
}

#[test]
fn generic_has_source_info() {
    let adapter = adapters::generic::GenericAdapter;
    let path_str = fixture_path("generic/minimal");
    let result = adapter.load(Path::new(&path_str)).unwrap();

    assert_eq!(result.source_info.len(), result.config.servers.len());
}

#[test]
fn scan_generic_minimal_produces_findings() {
    let path_str = fixture_path("generic/minimal");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();

    // Generic adapter should pick this up (no .cursor dir, no claude config)
    assert_eq!(result.adapter_name, "generic");

    let ctx = ScanContext::new(result.config, path_str);
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    // run_script has "execute" + "script" → MG001 should fire
    assert!(
        findings.iter().any(|f| f.id == "MG001"),
        "Expected MG001 for unbounded script parameter in generic config"
    );
}

#[test]
fn generic_does_not_crash_on_empty_dir() {
    let tmp_dir = std::env::temp_dir().join("mcplint-generic-empty");
    let _ = std::fs::create_dir_all(&tmp_dir);

    let adapter = adapters::generic::GenericAdapter;
    let result = adapter.load(&tmp_dir).unwrap();

    assert_eq!(result.adapter_name, "generic");
    assert!(result.config.servers.is_empty());
    assert!(!result.warnings.is_empty());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ── Adapter priority tests ──

#[test]
fn adapter_priority_cursor_over_generic() {
    // Cursor fixture has .cursor/mcp.json — cursor adapter should win over generic
    let path_str = fixture_path("cursor");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "cursor");
}

#[test]
fn adapter_priority_claude_over_cursor() {
    // Claude Desktop fixture has claude_desktop_config.json — claude adapter should win
    let path_str = fixture_path("claude_desktop/claude_desktop_config.json");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "claude-desktop");
}

// ── VS Code adapter tests ──

#[test]
fn vscode_detect_file() {
    let adapter = adapters::vscode::VsCodeAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let vscode_dir = dir.path().join(".vscode");
    std::fs::create_dir_all(&vscode_dir).unwrap();
    let mcp_file = vscode_dir.join("mcp.json");
    std::fs::write(&mcp_file, r#"{"servers":{}}"#).unwrap();

    assert!(adapter.detect(&mcp_file));
    assert!(adapter.detect(dir.path()));
}

#[test]
fn vscode_load_servers_object() {
    let adapter = adapters::vscode::VsCodeAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let vscode_dir = dir.path().join(".vscode");
    std::fs::create_dir_all(&vscode_dir).unwrap();
    let mcp_file = vscode_dir.join("mcp.json");
    std::fs::write(
        &mcp_file,
        std::fs::read_to_string(fixture_path("vscode/safe_vscode_mcp.json")).unwrap(),
    )
    .unwrap();

    let result = adapter.load(&mcp_file).unwrap();
    assert_eq!(result.adapter_name, "vscode");
    assert_eq!(result.config.servers.len(), 1);
    assert_eq!(result.config.servers[0].name, "github");
}

#[test]
fn vscode_settings_wrapped_format() {
    let adapter = adapters::vscode::VsCodeAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let vscode_dir = dir.path().join(".vscode");
    std::fs::create_dir_all(&vscode_dir).unwrap();
    let mcp_file = vscode_dir.join("mcp.json");
    std::fs::write(
        &mcp_file,
        std::fs::read_to_string(fixture_path("vscode/settings_wrapped.json")).unwrap(),
    )
    .unwrap();

    let result = adapter.load(&mcp_file).unwrap();
    assert_eq!(result.adapter_name, "vscode");
    assert_eq!(result.config.servers.len(), 1);
    assert_eq!(result.config.servers[0].name, "github");
}

#[test]
fn vscode_unsafe_triggers_rules() {
    let adapter = adapters::vscode::VsCodeAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let vscode_dir = dir.path().join(".vscode");
    std::fs::create_dir_all(&vscode_dir).unwrap();
    let mcp_file = vscode_dir.join("mcp.json");
    std::fs::write(
        &mcp_file,
        std::fs::read_to_string(fixture_path("vscode/unsafe_vscode_mcp.json")).unwrap(),
    )
    .unwrap();

    let result = adapter.load(&mcp_file).unwrap();
    let ctx = ScanContext::new(result.config, mcp_file.display().to_string());
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    assert!(
        !findings.is_empty(),
        "Unsafe VS Code config should trigger findings"
    );
    assert!(
        findings.iter().any(|f| f.id == "MG004"),
        "Expected MG004 for unconfined filesystem"
    );
    assert!(
        findings.iter().any(|f| f.id == "MG005"),
        "Expected MG005 for missing auth"
    );
}

// ── Cline adapter tests ──

#[test]
fn cline_detect_file() {
    let adapter = adapters::cline::ClineAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let cline_dir = dir.path().join(".cline");
    std::fs::create_dir_all(&cline_dir).unwrap();
    let settings_file = cline_dir.join("mcp_settings.json");
    std::fs::write(&settings_file, r#"{"mcpServers":{}}"#).unwrap();

    assert!(adapter.detect(&settings_file));
    assert!(adapter.detect(dir.path()));
}

#[test]
fn cline_load_config() {
    let adapter = adapters::cline::ClineAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let cline_dir = dir.path().join(".cline");
    std::fs::create_dir_all(&cline_dir).unwrap();
    let settings_file = cline_dir.join("mcp_settings.json");
    std::fs::write(
        &settings_file,
        std::fs::read_to_string(fixture_path("cline/safe_mcp_settings.json")).unwrap(),
    )
    .unwrap();

    let result = adapter.load(&settings_file).unwrap();
    assert_eq!(result.adapter_name, "cline");
    assert_eq!(result.config.servers.len(), 1);
    assert_eq!(result.config.servers[0].name, "github");
}

#[test]
fn cline_disabled_server_excluded() {
    let adapter = adapters::cline::ClineAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let cline_dir = dir.path().join(".cline");
    std::fs::create_dir_all(&cline_dir).unwrap();
    let settings_file = cline_dir.join("mcp_settings.json");
    std::fs::write(
        &settings_file,
        std::fs::read_to_string(fixture_path("cline/disabled_server.json")).unwrap(),
    )
    .unwrap();

    let result = adapter.load(&settings_file).unwrap();
    assert_eq!(result.adapter_name, "cline");
    // Only active-server should be included, disabled-server should be skipped
    assert_eq!(result.config.servers.len(), 1);
    assert_eq!(result.config.servers[0].name, "active-server");
    assert!(
        result.warnings.iter().any(|w| w.contains("disabled")),
        "Should warn about disabled server"
    );
}

#[test]
fn cline_always_allow_warning() {
    let adapter = adapters::cline::ClineAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let cline_dir = dir.path().join(".cline");
    std::fs::create_dir_all(&cline_dir).unwrap();
    let settings_file = cline_dir.join("mcp_settings.json");
    std::fs::write(
        &settings_file,
        std::fs::read_to_string(fixture_path("cline/unsafe_mcp_settings.json")).unwrap(),
    )
    .unwrap();

    let result = adapter.load(&settings_file).unwrap();
    assert!(
        result.warnings.iter().any(|w| w.contains("alwaysAllow")),
        "Should warn about alwaysAllow tools"
    );
}

#[test]
fn cline_unsafe_triggers_rules() {
    let adapter = adapters::cline::ClineAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let cline_dir = dir.path().join(".cline");
    std::fs::create_dir_all(&cline_dir).unwrap();
    let settings_file = cline_dir.join("mcp_settings.json");
    std::fs::write(
        &settings_file,
        std::fs::read_to_string(fixture_path("cline/unsafe_mcp_settings.json")).unwrap(),
    )
    .unwrap();

    let result = adapter.load(&settings_file).unwrap();
    let ctx = ScanContext::new(result.config, settings_file.display().to_string());
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    assert!(
        !findings.is_empty(),
        "Unsafe Cline config should trigger findings"
    );
    assert!(
        findings.iter().any(|f| f.id == "MG004"),
        "Expected MG004 for unconfined filesystem"
    );
}

// ── Windsurf adapter tests ──

#[test]
fn windsurf_detect_directory() {
    let adapter = adapters::windsurf::WindsurfAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let windsurf_dir = dir.path().join(".windsurf");
    std::fs::create_dir_all(&windsurf_dir).unwrap();
    let mcp_file = windsurf_dir.join("mcp.json");
    std::fs::write(&mcp_file, r#"{"mcpServers":{}}"#).unwrap();

    assert!(adapter.detect(dir.path()));
}

#[test]
fn windsurf_load_config() {
    let adapter = adapters::windsurf::WindsurfAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let codeium_dir = dir.path().join(".codeium").join("windsurf");
    std::fs::create_dir_all(&codeium_dir).unwrap();
    let mcp_file = codeium_dir.join("mcp_config.json");
    std::fs::write(
        &mcp_file,
        std::fs::read_to_string(fixture_path("windsurf/safe_mcp_config.json")).unwrap(),
    )
    .unwrap();

    let result = adapter.load(&mcp_file).unwrap();
    assert_eq!(result.adapter_name, "windsurf");
    assert_eq!(result.config.servers.len(), 1);
    assert_eq!(result.config.servers[0].name, "github");
}

#[test]
fn windsurf_unsafe_triggers_rules() {
    let adapter = adapters::windsurf::WindsurfAdapter;
    let dir = tempfile::TempDir::new().unwrap();
    let codeium_dir = dir.path().join(".codeium").join("windsurf");
    std::fs::create_dir_all(&codeium_dir).unwrap();
    let mcp_file = codeium_dir.join("mcp_config.json");
    std::fs::write(
        &mcp_file,
        std::fs::read_to_string(fixture_path("windsurf/unsafe_mcp_config.json")).unwrap(),
    )
    .unwrap();

    let result = adapter.load(&mcp_file).unwrap();
    let ctx = ScanContext::new(result.config, mcp_file.display().to_string());
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    assert!(
        !findings.is_empty(),
        "Unsafe Windsurf config should trigger findings"
    );
    assert!(
        findings.iter().any(|f| f.id == "MG004"),
        "Expected MG004 for unconfined filesystem"
    );
}

// ── Auto-detection picks correct adapter ──

#[test]
fn auto_detect_picks_vscode() {
    let dir = tempfile::TempDir::new().unwrap();
    let vscode_dir = dir.path().join(".vscode");
    std::fs::create_dir_all(&vscode_dir).unwrap();
    let mcp_file = vscode_dir.join("mcp.json");
    std::fs::write(
        &mcp_file,
        r#"{"servers":{"s":{"command":"node","args":[]}}}"#,
    )
    .unwrap();

    let result = adapters::auto_load(&mcp_file).unwrap();
    assert_eq!(result.adapter_name, "vscode");
}

#[test]
fn auto_detect_picks_cline() {
    let dir = tempfile::TempDir::new().unwrap();
    let cline_dir = dir.path().join(".cline");
    std::fs::create_dir_all(&cline_dir).unwrap();
    let settings_file = cline_dir.join("mcp_settings.json");
    std::fs::write(
        &settings_file,
        r#"{"mcpServers":{"s":{"command":"node","args":[]}}}"#,
    )
    .unwrap();

    let result = adapters::auto_load(&settings_file).unwrap();
    assert_eq!(result.adapter_name, "cline");
}

#[test]
fn auto_detect_picks_windsurf() {
    let dir = tempfile::TempDir::new().unwrap();
    let windsurf_dir = dir.path().join(".windsurf");
    std::fs::create_dir_all(&windsurf_dir).unwrap();
    let mcp_file = windsurf_dir.join("mcp.json");
    std::fs::write(
        &mcp_file,
        r#"{"mcpServers":{"s":{"command":"node","args":[]}}}"#,
    )
    .unwrap();

    // Detect via directory
    let result = adapters::auto_load(dir.path()).unwrap();
    assert_eq!(result.adapter_name, "windsurf");
}

// ── Continue.dev adapter tests ──

#[test]
fn continue_detect_directory() {
    let adapter = adapters::continue_dev::ContinueDevAdapter;
    let path_str = fixture_path("continue_dev");
    assert!(adapter.detect(Path::new(&path_str)));
}

#[test]
fn continue_load_directory() {
    let adapter = adapters::continue_dev::ContinueDevAdapter;
    let path_str = fixture_path("continue_dev");
    let result = adapter.load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "continue");
    // mcpServers/ directory has sqlite.yaml, github.json, secrets.yaml
    assert!(result.config.servers.len() >= 3);
    let names: Vec<&str> = result
        .config
        .servers
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert!(names.contains(&"sqlite-server"));
    assert!(names.contains(&"github-server"));
    assert!(names.contains(&"secret-server"));
}

#[test]
fn continue_yaml_scan_unsafe() {
    let path_str = fixture_path("continue_dev_unsafe/.continue/config.yaml");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "continue");

    let ctx = ScanContext::new(result.config, path_str);
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    // config.yaml has hardcoded secrets — should trigger MG009
    assert!(
        findings.iter().any(|f| f.id == "MG009"),
        "Should detect hardcoded secrets in Continue YAML"
    );
}

#[test]
fn continue_json_scan() {
    let path_str = fixture_path("continue_dev/.continue/mcpServers/github.json");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "continue");
    assert_eq!(result.config.servers.len(), 1);
    assert_eq!(result.config.servers[0].name, "github-server");
}

#[test]
fn continue_secrets_not_flagged_as_hardcoded() {
    let path_str = fixture_path("continue_dev/.continue/mcpServers/secrets.yaml");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "continue");

    let ctx = ScanContext::new(result.config, path_str);
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    // ${{ secrets.* }} values should NOT be flagged as Critical hardcoded secrets
    let critical_mg009: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "MG009" && f.severity == mcplint_core::Severity::Critical)
        .collect();
    assert!(
        critical_mg009.is_empty(),
        "Continue.dev secret templates should not be flagged as hardcoded: {:?}",
        critical_mg009.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[test]
fn continue_auto_detect() {
    let path_str = fixture_path("continue_dev");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "continue");
}

// ── Zed adapter tests ──

#[test]
fn zed_detect_settings() {
    let adapter = adapters::zed::ZedAdapter;
    let path_str = fixture_path("zed/settings.json");
    assert!(adapter.detect(Path::new(&path_str)));
}

#[test]
fn zed_load_settings() {
    let adapter = adapters::zed::ZedAdapter;
    let path_str = fixture_path("zed/settings.json");
    let result = adapter.load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "zed");
    assert_eq!(result.config.servers.len(), 2);
    let names: Vec<&str> = result
        .config
        .servers
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert!(names.contains(&"filesystem"));
    assert!(names.contains(&"github"));
}

#[test]
fn zed_scan_unsafe() {
    let path_str = fixture_path("zed_unsafe/settings.json");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "zed");

    let ctx = ScanContext::new(result.config, path_str);
    let registry = mcplint_rules::default_registry();
    let findings = registry.run_all(&ctx);

    // Should detect hardcoded secrets (MG009)
    assert!(
        findings.iter().any(|f| f.id == "MG009"),
        "Should detect secrets in Zed config"
    );
}

#[test]
fn zed_scan_with_comments() {
    let path_str = fixture_path("zed_comments/settings.json");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "zed");
    assert_eq!(result.config.servers.len(), 1);
    assert_eq!(result.config.servers[0].name, "filesystem");
}

#[test]
fn zed_no_mcp_detected() {
    let adapter = adapters::zed::ZedAdapter;
    let path_str = fixture_path("zed_no_mcp/settings.json");
    // detect returns true (file has right name), but load should fail
    // because there are no context_servers
    let result = adapter.load(Path::new(&path_str));
    assert!(result.is_err());
}

#[test]
fn zed_auto_detect() {
    let path_str = fixture_path("zed/settings.json");
    let result = adapters::auto_load(Path::new(&path_str)).unwrap();
    assert_eq!(result.adapter_name, "zed");
}
