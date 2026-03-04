//! mcplint CLI — static security analyzer for MCP configurations.
//!
//! Provides subcommands: `scan`, `export`, `list-rules`, `explain`, and `baseline`.

mod commands;
pub mod exit_codes;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use mcplint_core::custom_rule::{load_custom_rules, load_custom_rules_from_dir};
use mcplint_core::{discover_config, GuardConfig, Rule, RuleRegistry, Severity};
use mcplint_report::OutputFormat;
use mcplint_rules::default_registry;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "mcplint",
    about = "Static security analyzer for MCP (Model Context Protocol) configurations",
    version,
    long_about = "mcplint is a compiler-style security analyzer that finds exploitable MCP \
                   security issues, explains why they are dangerous, and fails builds with evidence.\n\n\
                   Think: clang-tidy / semgrep for MCP — not a firewall, gateway, or dashboard."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan an MCP configuration file or directory for security issues
    Scan {
        /// Path(s) to MCP configuration file(s) or directory (auto-detects format)
        path: Vec<PathBuf>,

        /// Output format
        #[arg(long, value_enum)]
        format: Option<FormatArg>,

        /// Fail with exit code 1 if findings at or above this severity are found
        #[arg(long, value_enum)]
        fail_on: Option<SeverityArg>,

        /// Path to a .mcplint.toml config file (overrides auto-discovery)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Disable auto-discovery of .mcplint.toml
        #[arg(long)]
        no_config: bool,

        /// Apply auto-fixes and write patched config back to the file
        #[arg(long, conflicts_with = "fix_dry_run")]
        fix: bool,

        /// Show what auto-fixes would be applied without modifying the file
        #[arg(long, conflicts_with = "fix")]
        fix_dry_run: bool,

        /// Read configuration from stdin instead of a file
        #[arg(long)]
        stdin: bool,

        /// Save findings to a baseline JSON file after scanning
        #[arg(long = "save-baseline")]
        save_baseline: Option<PathBuf>,

        /// Load custom rules from a YAML file or directory (can be repeated)
        #[arg(long = "rules")]
        rules: Vec<PathBuf>,

        /// Load all custom rules from a directory
        #[arg(long = "rules-dir")]
        rules_dir: Option<PathBuf>,

        /// Scan a live MCP server instead of a config file.
        /// Formats: stdio:<command>:<args...> or http[s]://url
        #[arg(long, conflicts_with_all = ["stdin", "fix", "fix_dry_run", "save_baseline"])]
        server: Option<String>,
    },
    /// Export a detected MCP configuration to canonical mcplint format
    Export {
        /// Path to MCP configuration file or directory (auto-detects format)
        path: PathBuf,

        /// Output directory for exported files
        #[arg(long, default_value = ".")]
        out: PathBuf,

        /// Path to a .mcplint.toml config file (overrides auto-discovery)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Disable auto-discovery of .mcplint.toml
        #[arg(long)]
        no_config: bool,
    },
    /// List all available security rules
    ListRules {
        /// Load custom rules from a YAML file or directory (can be repeated)
        #[arg(long = "rules")]
        rules: Vec<PathBuf>,

        /// Load all custom rules from a directory
        #[arg(long = "rules-dir")]
        rules_dir: Option<PathBuf>,
    },
    /// Explain a specific rule in detail
    Explain {
        /// Rule ID (e.g., MG001)
        rule_id: String,

        /// Load custom rules from a YAML file or directory (can be repeated)
        #[arg(long = "rules")]
        rules: Vec<PathBuf>,

        /// Load all custom rules from a directory
        #[arg(long = "rules-dir")]
        rules_dir: Option<PathBuf>,
    },
    /// Compare current scan findings against a saved baseline
    Diff {
        /// Path to MCP configuration file or directory (auto-detects format)
        path: PathBuf,

        /// Path to a previously saved findings baseline JSON
        #[arg(long)]
        baseline: PathBuf,

        /// Output format
        #[arg(long, value_enum)]
        format: Option<FormatArg>,

        /// Minimum severity of new findings that triggers exit code 2
        #[arg(long = "fail-on-new", value_enum)]
        fail_on_new: Option<SeverityArg>,

        /// Path to a .mcplint.toml config file (overrides auto-discovery)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Disable auto-discovery of .mcplint.toml
        #[arg(long)]
        no_config: bool,

        /// Load custom rules from a YAML file or directory (can be repeated)
        #[arg(long = "rules")]
        rules: Vec<PathBuf>,

        /// Load all custom rules from a directory
        #[arg(long = "rules-dir")]
        rules_dir: Option<PathBuf>,
    },
    /// Create or compare configuration baselines for drift detection
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Start an MCP server exposing mcplint tools for AI agents
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Create a baseline snapshot from an MCP configuration
    Create {
        /// Path to MCP configuration file or directory
        path: PathBuf,
        /// Write baseline JSON to file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Compare current config against a saved baseline
    Diff {
        /// Path to MCP configuration file or directory
        path: PathBuf,
        /// Path to the baseline JSON file to compare against
        #[arg(long)]
        baseline: PathBuf,
        /// Output format for diff results
        #[arg(long, value_enum, default_value = "text")]
        format: DiffFormatArg,
        /// Exit with code 1 if risky drift is detected
        #[arg(long)]
        fail_on_drift: bool,
    },
}

#[derive(Subcommand)]
enum McpAction {
    /// Start the MCP server on stdio transport
    Serve,
}

#[derive(Clone, ValueEnum)]
enum FormatArg {
    Text,
    Json,
    Markdown,
    Sarif,
}

#[derive(Clone, ValueEnum)]
enum DiffFormatArg {
    Text,
    Json,
    Markdown,
}

impl From<FormatArg> for OutputFormat {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Text => OutputFormat::Text,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Markdown => OutputFormat::Markdown,
            FormatArg::Sarif => OutputFormat::Sarif,
        }
    }
}

#[derive(Clone, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

/// Exit codes:
///   0 — Success (no findings above threshold)
///   1 — Operational error (bad input, parse failure, misconfiguration)
///   2 — Policy violation (findings/drift above threshold)
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            fail_on,
            config,
            no_config,
            fix,
            fix_dry_run,
            stdin,
            save_baseline,
            rules,
            rules_dir,
            server,
        } => {
            // Validate --stdin constraints
            if stdin && !path.is_empty() {
                anyhow::bail!("Cannot use both --stdin and a file path.");
            }
            if stdin && (fix || fix_dry_run) {
                anyhow::bail!("Cannot use --fix with --stdin. Provide a file path instead.");
            }
            if stdin && save_baseline.is_some() {
                anyhow::bail!("Cannot use --save-baseline with --stdin.");
            }
            if server.is_some() && !path.is_empty() {
                anyhow::bail!("Cannot use both --server and a file path.");
            }
            if server.is_some() && stdin {
                anyhow::bail!("Cannot use both --server and --stdin.");
            }

            if let Some(ref target) = server {
                let guard_config = if no_config {
                    GuardConfig::default()
                } else if let Some(ref cp) = config {
                    GuardConfig::from_file(cp)
                        .with_context(|| format!("Failed to load config: {}", cp.display()))?
                } else {
                    GuardConfig::default()
                };
                let registry = build_registry(&rules, rules_dir.as_deref(), &guard_config)?;
                let rt =
                    tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
                let result = rt
                    .block_on(mcplint_mcp_server::scan_live_server(target))
                    .with_context(|| format!("Failed to scan live server: {}", target))?;

                eprintln!("adapter: {} ({})", result.adapter_name, target);
                for warning in &result.warnings {
                    eprintln!("warning: {}", warning);
                }

                let ctx = mcplint_core::ScanContext::new(result.config, target.to_string());
                let findings = registry.run_all(&ctx);
                let findings = mcplint_core::apply_policy(&guard_config, findings);

                let format = format.map(OutputFormat::from).unwrap_or(OutputFormat::Text);
                let fail_on = fail_on.map(Severity::from);

                let output = if format == OutputFormat::Sarif {
                    let rules_meta = commands::scan::rules_metadata(&registry);
                    mcplint_report::render_sarif(
                        &findings,
                        target,
                        env!("CARGO_PKG_VERSION"),
                        &rules_meta,
                    )
                } else {
                    mcplint_report::render(&findings, target, format)
                };
                print!("{}", output);

                if let Some(threshold) = fail_on {
                    if findings.iter().any(|f| f.meets_threshold(threshold)) {
                        std::process::exit(exit_codes::EXIT_VIOLATION);
                    }
                }

                return Ok(());
            }

            if stdin {
                let mut content = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut content)
                    .context("Failed to read from stdin")?;
                let guard_config = if no_config {
                    GuardConfig::default()
                } else if let Some(ref cp) = config {
                    GuardConfig::from_file(cp)
                        .with_context(|| format!("Failed to load config: {}", cp.display()))?
                } else {
                    GuardConfig::default()
                };
                let registry = build_registry(&rules, rules_dir.as_deref(), &guard_config)?;
                commands::scan::cmd_scan_content(
                    &content,
                    "stdin.json",
                    format,
                    fail_on.map(Severity::from),
                    &guard_config,
                    &registry,
                )
            } else if path.is_empty() {
                anyhow::bail!("No input specified. Provide a file path or use --stdin.");
            } else if path.len() == 1 {
                let p = &path[0];
                let guard_config = load_config(p, config.as_deref(), no_config)?;
                let registry = build_registry(&rules, rules_dir.as_deref(), &guard_config)?;
                commands::scan::cmd_scan(
                    p.clone(),
                    format,
                    fail_on.map(Severity::from),
                    &guard_config,
                    fix,
                    fix_dry_run,
                    save_baseline,
                    &registry,
                )
            } else {
                // Multiple paths
                if fix || fix_dry_run {
                    anyhow::bail!(
                        "Auto-fix requires a single file target. Specify the file directly."
                    );
                }
                if save_baseline.is_some() {
                    anyhow::bail!(
                        "--save-baseline requires a single file target. Specify the file directly."
                    );
                }
                let guard_config = load_config(&path[0], config.as_deref(), no_config)?;
                let registry = build_registry(&rules, rules_dir.as_deref(), &guard_config)?;
                commands::scan::cmd_scan_multi(
                    &path,
                    format,
                    fail_on.map(Severity::from),
                    &guard_config,
                    &registry,
                )
            }
        }
        Commands::Export {
            path,
            out,
            config,
            no_config,
        } => {
            let _guard_config = load_config(&path, config.as_deref(), no_config)?;
            commands::export::cmd_export(path, out)
        }
        Commands::ListRules { rules, rules_dir } => {
            let guard_config = GuardConfig::default();
            let registry = build_registry(&rules, rules_dir.as_deref(), &guard_config)?;
            commands::rules::cmd_list_rules(&registry)
        }
        Commands::Explain {
            rule_id,
            rules,
            rules_dir,
        } => {
            let guard_config = GuardConfig::default();
            let registry = build_registry(&rules, rules_dir.as_deref(), &guard_config)?;
            commands::rules::cmd_explain(&rule_id, &registry)
        }
        Commands::Diff {
            path,
            baseline,
            format,
            fail_on_new,
            config,
            no_config,
            rules,
            rules_dir,
        } => {
            let guard_config = load_config(&path, config.as_deref(), no_config)?;
            let registry = build_registry(&rules, rules_dir.as_deref(), &guard_config)?;
            commands::diff::cmd_diff(
                path,
                baseline,
                format,
                fail_on_new.map(Severity::from),
                &guard_config,
                &registry,
            )
        }
        Commands::Baseline { action } => match action {
            BaselineAction::Create { path, out } => {
                commands::baseline::cmd_baseline_create(path, out)
            }
            BaselineAction::Diff {
                path,
                baseline: baseline_path,
                format,
                fail_on_drift,
            } => commands::baseline::cmd_baseline_diff(path, baseline_path, format, fail_on_drift),
        },
        Commands::Mcp { action } => match action {
            McpAction::Serve => {
                let rt =
                    tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
                rt.block_on(async {
                    mcplint_mcp_server::run_stdio()
                        .await
                        .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))
                })
            }
        },
    }
}

/// Load the project config, respecting --config / --no-config flags.
fn load_config(
    scan_path: &std::path::Path,
    explicit_config: Option<&std::path::Path>,
    no_config: bool,
) -> Result<GuardConfig> {
    if no_config {
        return Ok(GuardConfig::default());
    }

    if let Some(config_path) = explicit_config {
        let config = GuardConfig::from_file(config_path)
            .with_context(|| format!("Failed to load config: {}", config_path.display()))?;
        eprintln!("config: {}", config_path.display());
        return Ok(config);
    }

    // Auto-discover
    if let Some(config_path) = discover_config(scan_path) {
        match GuardConfig::from_file(&config_path) {
            Ok(config) => {
                eprintln!("config: {}", config_path.display());
                return Ok(config);
            }
            Err(e) => {
                eprintln!(
                    "warning: found {} but failed to load: {}",
                    config_path.display(),
                    e
                );
            }
        }
    }

    Ok(GuardConfig::default())
}

/// Build a rule registry with built-in rules + any custom rules from CLI flags or config.
fn build_registry(
    rules_paths: &[PathBuf],
    rules_dir: Option<&std::path::Path>,
    guard_config: &GuardConfig,
) -> Result<RuleRegistry> {
    let mut registry = default_registry();

    // Determine custom rules source: CLI flags take precedence over config
    let has_cli_rules = !rules_paths.is_empty() || rules_dir.is_some();

    if has_cli_rules {
        // Load from CLI flags
        for path in rules_paths {
            let (custom_rules, warnings) = load_custom_rules(path)
                .with_context(|| format!("Failed to load custom rules from {}", path.display()))?;
            for w in &warnings {
                eprintln!("warning: {}", w);
            }
            for rule in custom_rules {
                if rule.id().starts_with("MG") {
                    anyhow::bail!(
                        "Custom rule ID '{}' conflicts with built-in rule prefix 'MG'",
                        rule.id()
                    );
                }
                registry.register(Box::new(rule));
            }
        }
        if let Some(dir) = rules_dir {
            let (custom_rules, warnings) = load_custom_rules_from_dir(dir)
                .with_context(|| format!("Failed to load custom rules from {}", dir.display()))?;
            for w in &warnings {
                eprintln!("warning: {}", w);
            }
            for rule in custom_rules {
                registry.register(Box::new(rule));
            }
        }
    } else if let Some(ref config_rules_dir) = guard_config.rules_dir {
        // Fall back to config rules_dir
        let dir = std::path::Path::new(config_rules_dir);
        if dir.is_dir() {
            let (custom_rules, warnings) = load_custom_rules_from_dir(dir).with_context(|| {
                format!(
                    "Failed to load custom rules from rules_dir '{}'",
                    config_rules_dir
                )
            })?;
            for w in &warnings {
                eprintln!("warning: {}", w);
            }
            for rule in custom_rules {
                registry.register(Box::new(rule));
            }
        }
    }

    Ok(registry)
}
