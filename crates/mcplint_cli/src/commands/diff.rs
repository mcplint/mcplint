use anyhow::{Context, Result};
use mcplint_core::adapters;
use mcplint_core::findings_baseline::{FindingsBaseline, FindingsDiff};
use mcplint_core::rule::RuleRegistry;
use mcplint_core::{apply_policy, GuardConfig, ScanContext, Severity};
use std::path::PathBuf;
use std::process;

use crate::exit_codes;
use crate::FormatArg;

pub fn cmd_diff(
    path: PathBuf,
    baseline_path: PathBuf,
    format_arg: Option<FormatArg>,
    fail_on_new: Option<Severity>,
    guard_config: &GuardConfig,
    registry: &RuleRegistry,
) -> Result<()> {
    // Load baseline
    let baseline = FindingsBaseline::load(&baseline_path).map_err(|e| {
        anyhow::anyhow!(
            "{}\nCreate one with: mcplint scan <PATH> --save-baseline {}",
            e,
            baseline_path.display()
        )
    })?;

    // Run scan
    let path_str = path.display().to_string();
    let result = adapters::auto_load(&path)
        .with_context(|| format!("Failed to load MCP configuration: {}", path_str))?;

    eprintln!("adapter: {}", result.adapter_name);
    for warning in &result.warnings {
        eprintln!("warning: {}", warning);
    }

    let ctx = if let Some(map) = result.location_map {
        ScanContext::with_location_map(result.config, path_str.clone(), map, result.server_pointers)
    } else {
        ScanContext::new(result.config, path_str.clone())
    };

    let findings = registry.run_all(&ctx);
    let findings = apply_policy(guard_config, findings);

    // Compute diff
    let diff = FindingsDiff::compute(&baseline, &findings);

    // Format output
    let format = format_arg
        .map(|f| match f {
            FormatArg::Text => DiffFormat::Text,
            FormatArg::Json => DiffFormat::Json,
            FormatArg::Markdown => DiffFormat::Markdown,
            FormatArg::Sarif => DiffFormat::Text, // sarif not supported for diff
        })
        .unwrap_or(DiffFormat::Text);

    match format {
        DiffFormat::Text => print!("{}", render_diff_text(&diff)),
        DiffFormat::Json => print!(
            "{}",
            render_diff_json(&diff, &baseline_path, &baseline.created_at)
        ),
        DiffFormat::Markdown => print!("{}", render_diff_markdown(&diff)),
    }

    // Exit code
    let threshold = fail_on_new.unwrap_or(Severity::Low);
    let sev_str = threshold.to_string();
    if diff.has_new_findings_at_severity(&sev_str) {
        process::exit(exit_codes::EXIT_VIOLATION);
    }

    Ok(())
}

enum DiffFormat {
    Text,
    Json,
    Markdown,
}

// ── Text formatter ──────────────────────────────────────────────────────────

fn render_diff_text(diff: &FindingsDiff) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "mcplint diff: {} new | {} resolved | {} unchanged\n\n",
        diff.new_findings.len(),
        diff.resolved_findings.len(),
        diff.unchanged_count
    ));

    if !diff.new_findings.is_empty() {
        out.push_str(&format!("NEW FINDINGS ({}):\n", diff.new_findings.len()));
        for f in &diff.new_findings {
            out.push_str(&format!(
                "  [{:<8}] {:<5}  {}\n",
                f.severity, f.rule_id, f.title
            ));
            out.push_str(&format!("  {:>17}Fingerprint: {}\n", "", f.fingerprint));
        }
        out.push('\n');
    }

    if !diff.resolved_findings.is_empty() {
        out.push_str(&format!(
            "RESOLVED FINDINGS ({}):\n",
            diff.resolved_findings.len()
        ));
        for f in &diff.resolved_findings {
            out.push_str(&format!(
                "  [{:<8}] {:<5}  {}\n",
                f.severity, f.rule_id, f.title
            ));
            out.push_str(&format!("  {:>17}Fingerprint: {}\n", "", f.fingerprint));
        }
        out.push('\n');
    }

    if diff.new_findings.is_empty() {
        out.push_str("No new findings since baseline.\n\n");
    }

    out.push_str(&format!(
        "Summary: {} current findings (was {} in baseline)\n",
        diff.current_total, diff.baseline_total
    ));

    out
}

// ── JSON formatter ──────────────────────────────────────────────────────────

fn render_diff_json(
    diff: &FindingsDiff,
    baseline_path: &std::path::Path,
    baseline_created_at: &str,
) -> String {
    // FindingsDiff already derives Serialize via mcplint_core, so we can
    // build the output by serializing it and adding extra fields.
    let mut map = serde_json::Map::new();
    map.insert(
        "new_findings".into(),
        serde_json::to_value(&diff.new_findings).unwrap_or_default(),
    );
    map.insert(
        "resolved_findings".into(),
        serde_json::to_value(&diff.resolved_findings).unwrap_or_default(),
    );
    map.insert(
        "unchanged_count".into(),
        serde_json::Value::Number(diff.unchanged_count.into()),
    );
    map.insert(
        "current_total".into(),
        serde_json::Value::Number(diff.current_total.into()),
    );
    map.insert(
        "baseline_total".into(),
        serde_json::Value::Number(diff.baseline_total.into()),
    );
    map.insert(
        "baseline_file".into(),
        serde_json::Value::String(baseline_path.display().to_string()),
    );
    map.insert(
        "baseline_created_at".into(),
        serde_json::Value::String(baseline_created_at.to_string()),
    );
    map.insert(
        "has_regressions".into(),
        serde_json::Value::Bool(diff.has_new_findings()),
    );
    serde_json::to_string_pretty(&map).unwrap_or_default()
}

// ── Markdown formatter ──────────────────────────────────────────────────────

fn render_diff_markdown(diff: &FindingsDiff) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "## mcplint diff: {} new | {} resolved | {} unchanged\n\n",
        diff.new_findings.len(),
        diff.resolved_findings.len(),
        diff.unchanged_count
    ));

    if !diff.new_findings.is_empty() {
        out.push_str("### New findings\n\n");
        out.push_str("| Severity | Rule | Title | Server | Tool |\n");
        out.push_str("|----------|------|-------|--------|------|\n");
        for f in &diff.new_findings {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                f.severity,
                f.rule_id,
                f.title,
                f.server.as_deref().unwrap_or("—"),
                f.tool.as_deref().unwrap_or("—"),
            ));
        }
        out.push('\n');
    }

    if !diff.resolved_findings.is_empty() {
        out.push_str("### Resolved findings\n\n");
        out.push_str("| Severity | Rule | Title | Server | Tool |\n");
        out.push_str("|----------|------|-------|--------|------|\n");
        for f in &diff.resolved_findings {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                f.severity,
                f.rule_id,
                f.title,
                f.server.as_deref().unwrap_or("—"),
                f.tool.as_deref().unwrap_or("—"),
            ));
        }
        out.push('\n');
    }

    if diff.new_findings.is_empty() {
        out.push_str("No new findings since baseline.\n\n");
    }

    out.push_str(&format!(
        "**Summary:** {} current findings (was {} in baseline)\n",
        diff.current_total, diff.baseline_total
    ));

    out
}
