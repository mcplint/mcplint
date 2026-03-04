//! mcplint MCP server — exposes mcplint scanning as MCP tools for AI agents,
//! and provides a live MCP server scanner that connects to running servers.
//!
//! Server tools:
//! - `mcplint_scan`: Scan an MCP configuration file or content for security issues
//! - `mcplint_list_rules`: List all available security rules
//! - `mcplint_explain`: Explain a specific rule with remediation guidance
//!
//! Live scanner:
//! - `scan_live_server`: Connect to a running MCP server, discover tools, produce `AdapterResult`

pub mod live_scanner;
mod server;

pub use live_scanner::{scan_live_server, LiveScanError};
pub use server::run_stdio;
pub use server::McplintServer;
