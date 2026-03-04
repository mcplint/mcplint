//! Output formatters for mcplint findings.
//!
//! Provides four output formats for rendering [`mcplint_core::Finding`] diagnostics:
//!
//! - **[`text`]** — Human-readable terminal output with ANSI colors
//! - **[`json`]** — Machine-readable JSON array
//! - **[`markdown`]** — Markdown tables for documentation or PR comments
//! - **[`sarif`]** — [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) for GitHub Code Scanning integration
//!
//! Use [`render()`] for text/json/markdown or [`sarif::render_sarif()`] for SARIF output.

use mcplint_core::{Finding, Severity};

pub mod json;
pub mod markdown;
pub mod sarif;
pub mod text;

/// Output format for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Markdown,
    Sarif,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "sarif" => Ok(OutputFormat::Sarif),
            _ => Err(format!("Unknown output format: '{}'", s)),
        }
    }
}

/// Render findings in the specified format.
///
/// For SARIF output, use `render_sarif` instead (requires additional metadata).
pub fn render(findings: &[Finding], source_path: &str, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => text::render(findings, source_path),
        OutputFormat::Json => json::render(findings, source_path),
        OutputFormat::Markdown => markdown::render(findings, source_path),
        OutputFormat::Sarif => {
            // Fallback: render SARIF with minimal metadata.
            // Callers should prefer render_sarif() for full SARIF output.
            sarif::render(findings, source_path, env!("CARGO_PKG_VERSION"), &[])
        }
    }
}

/// Render findings as SARIF 2.1.0 with full tool and rule metadata.
pub fn render_sarif(
    findings: &[Finding],
    source_path: &str,
    version: &str,
    rules_meta: &[(String, String, String, String)],
) -> String {
    sarif::render(findings, source_path, version, rules_meta)
}

/// Summary statistics for a scan.
pub struct ScanSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl ScanSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self {
            total: findings.len(),
            critical: findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            high: findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
            medium: findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
            low: findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .count(),
        }
    }
}
