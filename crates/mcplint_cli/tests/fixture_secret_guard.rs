//! Secret-leak guard: ensures no fixture file contains real credentials.
//!
//! This test recursively scans all files under tests/fixtures/ and fails
//! if any file contains patterns that look like real secrets.

use std::path::Path;

/// Patterns that match real secrets — must never appear in fixtures.
const SECRET_PATTERNS: &[(&str, &str)] = &[
    (r"ghp_[A-Za-z0-9]{20,}", "GitHub personal access token"),
    (r"gho_[A-Za-z0-9]{20,}", "GitHub OAuth token"),
    (r"ghu_[A-Za-z0-9]{20,}", "GitHub user-to-server token"),
    (r"ghs_[A-Za-z0-9]{20,}", "GitHub server-to-server token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained PAT"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI / Stripe secret key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (
        r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*",
        "Bearer token in header",
    ),
    (
        r#"(?i)(password|secret|token|api_key|private_key)\s*[:=]\s*["'][^"'\$\{]{8,}["']"#,
        "Hardcoded secret value",
    ),
    (r"xox[bpsa]-[A-Za-z0-9\-]{10,}", "Slack token"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private key PEM"),
];

/// Safe placeholder values that are allowed even if they match a pattern.
const SAFE_PLACEHOLDERS: &[&str] = &[
    "REDACTED",
    "example.com",
    "localhost",
    "127.0.0.1",
    "${",
    "$(",
];

fn collect_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                collect_files(&path, files);
            } else if path.extension().is_some_and(|e| e == "json" || e == "toml") {
                files.push(path);
            }
        }
    }
}

fn line_has_safe_placeholder(line: &str) -> bool {
    // If the line's value portion only contains safe placeholders, allow it
    SAFE_PLACEHOLDERS.iter().any(|p| line.contains(p))
}

#[test]
fn no_real_secrets_in_fixtures() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures");

    assert!(
        fixtures_dir.exists(),
        "fixtures dir not found: {fixtures_dir:?}"
    );

    let mut files = Vec::new();
    collect_files(&fixtures_dir, &mut files);
    assert!(!files.is_empty(), "no fixture files found");

    let mut violations = Vec::new();

    for file in &files {
        let content = std::fs::read_to_string(file).unwrap();
        for (line_num, line) in content.lines().enumerate() {
            if line_has_safe_placeholder(line) {
                continue;
            }
            for (pattern, description) in SECRET_PATTERNS {
                let re = regex::Regex::new(pattern).unwrap();
                if let Some(m) = re.find(line) {
                    violations.push(format!(
                        "  {}:{}: {} — matched '{}' ({})",
                        file.display(),
                        line_num + 1,
                        description,
                        m.as_str(),
                        pattern,
                    ));
                }
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "\n\nSECRET LEAK DETECTED in fixture files!\n\n{}\n\n\
             Fix: replace real secrets with REDACTED or use ${{ENV_VAR}} references.\n",
            violations.join("\n")
        );
    }
}
