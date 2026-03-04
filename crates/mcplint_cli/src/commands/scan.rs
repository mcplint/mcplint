use anyhow::{bail, Context, Result};
use mcplint_core::adapters;
use mcplint_core::findings_baseline::FindingsBaseline;
use mcplint_core::fix::FixEngine;
use mcplint_core::{apply_policy, GuardConfig, ScanContext, Severity};
use mcplint_report::OutputFormat;
use std::path::PathBuf;
use std::process;

use crate::exit_codes;
use crate::FormatArg;

/// Scan from stdin content (no file path).
pub fn cmd_scan_content(
    content: &str,
    filename_hint: &str,
    format_arg: Option<FormatArg>,
    fail_on_arg: Option<Severity>,
    guard_config: &GuardConfig,
    registry: &mcplint_core::rule::RuleRegistry,
) -> Result<()> {
    let result = adapters::auto_load_content(content, filename_hint)
        .with_context(|| "Failed to load MCP configuration from stdin")?;

    eprintln!("adapter: {}", result.adapter_name);
    for warning in &result.warnings {
        eprintln!("warning: {}", warning);
    }

    let source = "<stdin>".to_string();
    let ctx = if let Some(map) = result.location_map {
        ScanContext::with_location_map(result.config, source.clone(), map, result.server_pointers)
    } else {
        ScanContext::new(result.config, source.clone())
    };
    let findings = registry.run_all(&ctx);
    let findings = apply_policy(guard_config, findings);

    let format = resolve_format(format_arg, guard_config);
    let fail_on = fail_on_arg.or_else(|| guard_config.fail_on.as_ref().map(|s| s.0));

    let output = if format == OutputFormat::Sarif {
        let rules_meta = rules_metadata(registry);
        mcplint_report::render_sarif(&findings, &source, env!("CARGO_PKG_VERSION"), &rules_meta)
    } else {
        mcplint_report::render(&findings, &source, format)
    };
    print!("{}", output);

    if let Some(threshold) = fail_on {
        if findings.iter().any(|f| f.meets_threshold(threshold)) {
            process::exit(exit_codes::EXIT_VIOLATION);
        }
    }

    Ok(())
}

/// Scan multiple file paths, aggregating findings.
pub fn cmd_scan_multi(
    paths: &[PathBuf],
    format_arg: Option<FormatArg>,
    fail_on_arg: Option<Severity>,
    guard_config: &GuardConfig,
    registry: &mcplint_core::rule::RuleRegistry,
) -> Result<()> {
    let mut all_findings = Vec::new();
    let mut all_source_paths = Vec::new();

    for path in paths {
        let path_str = path.display().to_string();
        let result = adapters::auto_load(path)
            .with_context(|| format!("Failed to load MCP configuration: {}", path_str))?;

        eprintln!("adapter: {} ({})", result.adapter_name, path_str);
        for warning in &result.warnings {
            eprintln!("warning: {}", warning);
        }

        let ctx = if let Some(map) = result.location_map {
            ScanContext::with_location_map(
                result.config,
                path_str.clone(),
                map,
                result.server_pointers,
            )
        } else {
            ScanContext::new(result.config, path_str.clone())
        };
        let findings = registry.run_all(&ctx);
        let findings = apply_policy(guard_config, findings);
        all_findings.extend(findings);
        all_source_paths.push(path_str);
    }

    // Sort deterministically
    all_findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.title.cmp(&b.title))
    });

    let combined_source = all_source_paths.join(", ");
    let format = resolve_format(format_arg, guard_config);
    let fail_on = fail_on_arg.or_else(|| guard_config.fail_on.as_ref().map(|s| s.0));

    let output = if format == OutputFormat::Sarif {
        let rules_meta = rules_metadata(registry);
        mcplint_report::render_sarif(
            &all_findings,
            &combined_source,
            env!("CARGO_PKG_VERSION"),
            &rules_meta,
        )
    } else {
        mcplint_report::render(&all_findings, &combined_source, format)
    };
    print!("{}", output);

    if let Some(threshold) = fail_on {
        if all_findings.iter().any(|f| f.meets_threshold(threshold)) {
            process::exit(exit_codes::EXIT_VIOLATION);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_scan(
    path: PathBuf,
    format_arg: Option<FormatArg>,
    fail_on_arg: Option<Severity>,
    guard_config: &GuardConfig,
    fix: bool,
    fix_dry_run: bool,
    save_baseline: Option<PathBuf>,
    registry: &mcplint_core::rule::RuleRegistry,
) -> Result<()> {
    // --fix requires a single file target
    if (fix || fix_dry_run) && path.is_dir() {
        bail!("Auto-fix requires a single file target. Specify the file directly.");
    }

    let path_str = path.display().to_string();

    let result = adapters::auto_load(&path)
        .with_context(|| format!("Failed to load MCP configuration: {}", path_str))?;

    // Print adapter info and warnings to stderr
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

    // Apply config-based policy (filtering + severity overrides)
    let findings = apply_policy(guard_config, findings);

    // Handle --fix-dry-run
    if fix_dry_run {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read file for fix: {}", path_str))?;
        let (patched, fix_results) =
            FixEngine::apply_fixes(&content, &findings).with_context(|| "Failed to apply fixes")?;

        if fix_results.is_empty() {
            eprintln!("No auto-fixable findings found.");
        } else {
            eprintln!("Dry run — {} fixes would be applied:", fix_results.len());
            for fr in &fix_results {
                let action = if fr.requires_user_action {
                    " [ACTION REQUIRED]"
                } else {
                    ""
                };
                eprintln!("  [{}] {}{}", fr.rule_id, fr.description, action);
            }
            eprintln!();
            // Print simple diff
            eprintln!("--- {}", path_str);
            eprintln!("+++ {} (fixed)", path_str);
            for line in simple_diff(&content, &patched) {
                eprintln!("{}", line);
            }
        }
        return Ok(());
    }

    // Handle --fix
    if fix {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read file for fix: {}", path_str))?;
        let (patched, fix_results) =
            FixEngine::apply_fixes(&content, &findings).with_context(|| "Failed to apply fixes")?;

        let fix_count = fix_results.len();
        let has_user_action = fix_results.iter().any(|r| r.requires_user_action);

        if fix_count > 0 {
            std::fs::write(&path, &patched)
                .with_context(|| format!("Failed to write fixed file: {}", path_str))?;
        }

        // Re-scan the patched file to get remaining findings
        let result2 = adapters::auto_load(&path)
            .with_context(|| format!("Failed to re-load after fix: {}", path_str))?;
        let ctx2 = if let Some(map) = result2.location_map {
            ScanContext::with_location_map(
                result2.config,
                path_str.clone(),
                map,
                result2.server_pointers,
            )
        } else {
            ScanContext::new(result2.config, path_str.clone())
        };
        let remaining = registry.run_all(&ctx2);
        let remaining = apply_policy(guard_config, remaining);

        // Save baseline from post-fix findings if requested
        if let Some(ref bl_path) = save_baseline {
            save_findings_baseline(&remaining, result2.adapter_name, &path_str, bl_path)?;
        }

        // Output remaining findings
        let format = resolve_format(format_arg, guard_config);
        let fail_on = fail_on_arg.or_else(|| guard_config.fail_on.as_ref().map(|s| s.0));

        let output = if format == OutputFormat::Sarif {
            let rules_meta = rules_metadata(registry);
            mcplint_report::render_sarif(
                &remaining,
                &path_str,
                env!("CARGO_PKG_VERSION"),
                &rules_meta,
            )
        } else {
            mcplint_report::render(&remaining, &path_str, format)
        };
        print!("{}", output);

        eprintln!(
            "Applied {} fixes. {} findings remain (not auto-fixable).",
            fix_count,
            remaining.len()
        );

        if has_user_action {
            eprintln!(
                "ACTION REQUIRED: Some fixes inserted placeholders. Search for REPLACE_ME in your config."
            );
        }

        if let Some(threshold) = fail_on {
            if remaining.iter().any(|f| f.meets_threshold(threshold)) {
                process::exit(exit_codes::EXIT_VIOLATION);
            }
        }
        return Ok(());
    }

    // Normal scan flow (no fix)
    let format = resolve_format(format_arg, guard_config);
    let fail_on = fail_on_arg.or_else(|| guard_config.fail_on.as_ref().map(|s| s.0));

    // Save baseline if requested
    if let Some(ref bl_path) = save_baseline {
        save_findings_baseline(&findings, result.adapter_name, &path_str, bl_path)?;
    }

    let output = if format == OutputFormat::Sarif {
        let rules_meta = rules_metadata(registry);
        mcplint_report::render_sarif(&findings, &path_str, env!("CARGO_PKG_VERSION"), &rules_meta)
    } else {
        mcplint_report::render(&findings, &path_str, format)
    };
    print!("{}", output);

    // Exit with failure if findings meet the threshold
    if let Some(threshold) = fail_on {
        if findings.iter().any(|f| f.meets_threshold(threshold)) {
            process::exit(exit_codes::EXIT_VIOLATION);
        }
    }

    Ok(())
}

fn resolve_format(format_arg: Option<FormatArg>, guard_config: &GuardConfig) -> OutputFormat {
    match format_arg {
        Some(f) => f.into(),
        None => match guard_config.default_format.as_deref() {
            Some(f) => match f.parse::<OutputFormat>() {
                Ok(fmt) => fmt,
                Err(_) => {
                    eprintln!(
                        "warning: invalid default_format '{}' in config, falling back to text",
                        f
                    );
                    OutputFormat::Text
                }
            },
            None => OutputFormat::Text,
        },
    }
}

pub fn rules_metadata(
    registry: &mcplint_core::rule::RuleRegistry,
) -> Vec<(String, String, String, String)> {
    registry
        .rules()
        .iter()
        .map(|r| {
            (
                r.id().to_string(),
                r.description().to_string(),
                r.category().to_string(),
                r.explain().to_string(),
            )
        })
        .collect()
}

/// Produce a simple unified-diff-style output for two strings.
fn simple_diff(old: &str, new: &str) -> Vec<String> {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut result = Vec::new();

    let max = old_lines.len().max(new_lines.len());
    for i in 0..max {
        let old_line = old_lines.get(i).copied();
        let new_line = new_lines.get(i).copied();
        match (old_line, new_line) {
            (Some(o), Some(n)) if o != n => {
                result.push(format!("-{}", o));
                result.push(format!("+{}", n));
            }
            (Some(o), None) => {
                result.push(format!("-{}", o));
            }
            (None, Some(n)) => {
                result.push(format!("+{}", n));
            }
            _ => {} // identical lines — skip for brevity
        }
    }
    result
}

/// Save findings to a baseline JSON file.
fn save_findings_baseline(
    findings: &[mcplint_core::finding::Finding],
    adapter: &str,
    path: &str,
    bl_path: &std::path::Path,
) -> Result<()> {
    let baseline =
        FindingsBaseline::from_findings(findings, adapter, path, env!("CARGO_PKG_VERSION"));
    baseline
        .save(bl_path)
        .with_context(|| format!("Failed to save baseline to {}", bl_path.display()))?;
    eprintln!(
        "Saved baseline with {} findings to {}",
        findings.len(),
        bl_path.display()
    );
    Ok(())
}
