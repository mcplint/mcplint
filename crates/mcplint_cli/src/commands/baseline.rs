use anyhow::{Context, Result};
use mcplint_core::adapters;
use mcplint_core::baseline;
use std::path::PathBuf;
use std::process;

use crate::exit_codes;
use crate::DiffFormatArg;

pub fn cmd_baseline_create(path: PathBuf, out: Option<PathBuf>) -> Result<()> {
    let path_str = path.display().to_string();
    let result = adapters::auto_load(&path)
        .with_context(|| format!("Failed to load MCP configuration: {}", path_str))?;

    eprintln!("adapter: {}", result.adapter_name);
    for warning in &result.warnings {
        eprintln!("warning: {}", warning);
    }

    let source = baseline::BaselineSource {
        adapter: result.adapter_name.to_string(),
        path: path_str,
    };
    let mut bl = baseline::create_baseline(&result.config, Some(source));
    bl.created_at = Some(chrono_now_iso());

    let json = serde_json::to_string_pretty(&bl).context("Failed to serialize baseline")?;

    if let Some(out_path) = out {
        std::fs::write(&out_path, &json)
            .with_context(|| format!("Failed to write baseline: {}", out_path.display()))?;
        eprintln!("baseline written: {}", out_path.display());
    } else {
        println!("{}", json);
    }
    Ok(())
}

pub fn cmd_baseline_diff(
    path: PathBuf,
    baseline_path: PathBuf,
    format: DiffFormatArg,
    fail_on_drift: bool,
) -> Result<()> {
    // Load saved baseline
    let baseline_json = std::fs::read_to_string(&baseline_path)
        .with_context(|| format!("Failed to read baseline: {}", baseline_path.display()))?;
    let old_baseline: baseline::Baseline = serde_json::from_str(&baseline_json)
        .with_context(|| format!("Failed to parse baseline JSON: {}", baseline_path.display()))?;

    // Build current baseline
    let path_str = path.display().to_string();
    let result = adapters::auto_load(&path)
        .with_context(|| format!("Failed to load MCP configuration: {}", path_str))?;

    eprintln!("adapter: {}", result.adapter_name);
    for warning in &result.warnings {
        eprintln!("warning: {}", warning);
    }

    let new_baseline = baseline::create_baseline(&result.config, None);
    let diff = baseline::diff_baselines(&old_baseline, &new_baseline);

    match format {
        DiffFormatArg::Text => {
            if diff.is_empty() {
                println!("No drift detected.");
            } else {
                println!("mcplint baseline diff:");
                println!("{}", "─".repeat(50));
                print!("{}", diff);
            }
        }
        DiffFormatArg::Json => {
            let json = serde_json::to_string_pretty(&diff).context("Failed to serialize diff")?;
            println!("{}", json);
        }
        DiffFormatArg::Markdown => {
            println!("# mcplint Baseline Diff\n");
            if diff.is_empty() {
                println!("No drift detected.");
            } else {
                if !diff.added_servers.is_empty() {
                    println!("## Added Servers\n");
                    for s in &diff.added_servers {
                        println!("- **{}** ({}, {} tools)", s.name, s.transport, s.tool_count);
                    }
                    println!();
                }
                if !diff.removed_servers.is_empty() {
                    println!("## Removed Servers\n");
                    for s in &diff.removed_servers {
                        println!("- **{}** ({}, {} tools)", s.name, s.transport, s.tool_count);
                    }
                    println!();
                }
                if !diff.changed_servers.is_empty() {
                    println!("## Changed Servers\n");
                    for s in &diff.changed_servers {
                        println!("### {}\n", s.name);
                        if let Some(tc) = &s.transport_changed {
                            println!("- Transport: `{}` → `{}`", tc.from, tc.to);
                        }
                        for t in &s.added_tools {
                            println!("- ➕ tool `{}` [{}]", t.name, t.capability_flags.join(", "));
                        }
                        for t in &s.removed_tools {
                            println!("- ➖ tool `{}`", t.name);
                        }
                        for t in &s.changed_tools {
                            let mut changes = Vec::new();
                            if t.description_changed {
                                changes.push("description".to_string());
                            }
                            if t.schema_changed {
                                changes.push("schema".to_string());
                            }
                            if !t.capability_flags_added.is_empty() {
                                changes.push(format!(
                                    "+flags[{}]",
                                    t.capability_flags_added.join(",")
                                ));
                            }
                            if !t.capability_flags_removed.is_empty() {
                                changes.push(format!(
                                    "-flags[{}]",
                                    t.capability_flags_removed.join(",")
                                ));
                            }
                            println!("- 🔄 tool `{}`: {}", t.name, changes.join(", "));
                        }
                        println!();
                    }
                }
                if diff.has_risky_drift {
                    println!("---\n\n⚠️ **Risky drift detected.**");
                }
            }
        }
    }

    if fail_on_drift && diff.has_risky_drift {
        process::exit(exit_codes::EXIT_VIOLATION);
    }

    Ok(())
}

/// Simple ISO 8601 timestamp without pulling in chrono.
fn chrono_now_iso() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, mins, seconds
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}
