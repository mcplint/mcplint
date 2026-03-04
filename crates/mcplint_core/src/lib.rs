//! Core data models, adapters, and infrastructure for mcplint.
//!
//! This crate provides the foundational types used across the mcplint workspace:
//!
//! - **[`mcp_schema`]** — Canonical MCP configuration model ([`McpConfig`], [`McpServer`], [`ToolDefinition`])
//! - **[`adapters`]** — Format-specific loaders (Claude Desktop, Cursor, native, generic) that
//!   normalize input JSON into [`McpConfig`]
//! - **[`finding`]** — Diagnostic types ([`Finding`], [`Severity`], [`Evidence`]) emitted by rules
//! - **[`rule`]** — The [`Rule`] trait and [`RuleRegistry`] for rule registration and execution
//! - **[`scan_context`]** — [`ScanContext`] that carries config + JSON location mapping for evidence attribution
//! - **[`config`]** — Policy configuration ([`GuardConfig`]) loaded from `.mcplint.toml`
//! - **[`baseline`]** — Baseline snapshots for drift detection
//! - **[`json_locator`]** — JSON pointer → line/column mapping

pub mod adapters;
pub mod baseline;
pub mod config;
pub mod custom_rule;
pub mod finding;
pub mod findings_baseline;
pub mod fix;
pub mod json_locator;
pub mod mcp_schema;
pub mod rule;
pub mod scan_context;

pub use config::{apply_policy, discover_config, GuardConfig};
pub use finding::*;
pub use json_locator::{escape_pointer, JsonLocationMap, Region};
pub use mcp_schema::*;
pub use rule::*;
pub use scan_context::*;
