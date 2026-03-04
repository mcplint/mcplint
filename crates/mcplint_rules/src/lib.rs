//! Security rules for mcplint.
//!
//! Each rule implements the [`mcplint_core::Rule`] trait and detects a specific class of
//! security issue in MCP tool configurations:
//!
//! | Rule  | Module | What it detects |
//! |-------|--------|-----------------|
//! | MG001 | [`mg001_unbounded_string`] | Unbounded string parameters flowing to dangerous sinks |
//! | MG002 | [`mg002_over_permissioning`] | Tool descriptions that understate actual capabilities |
//! | MG003 | [`mg003_escalation_chains`] | Cross-tool/cross-server escalation chains |
//! | MG004 | [`mg004_filesystem_scope`] | Filesystem access without path confinement |
//! | MG005 | [`mg005_weak_auth`] | Missing or weak authentication |
//! | MG006 | [`mg006_metadata_leakage`] | Internal metadata leakage in descriptions |
//! | MG007 | [`mg007_broad_scope`] | Overly broad tool parameter scopes |
//! | MG008 | [`mg008_transport_security`] | Insecure transport (HTTP/WS without TLS) |
//! | MG009 | [`mg009_env_leakage`] | Sensitive environment variables passed to servers |
//!
//! Use [`default_registry()`] to get a [`mcplint_core::RuleRegistry`] with all rules registered.

pub mod mg001_unbounded_string;
pub mod mg002_over_permissioning;
pub mod mg003_escalation_chains;
pub mod mg004_filesystem_scope;
pub mod mg005_weak_auth;
pub mod mg006_metadata_leakage;
pub mod mg007_broad_scope;
pub mod mg008_transport_security;
pub mod mg009_env_leakage;

use mcplint_core::RuleRegistry;

/// Create a registry populated with all rules.
pub fn default_registry() -> RuleRegistry {
    let mut registry = RuleRegistry::new();
    registry.register(Box::new(mg001_unbounded_string::Mg001UnboundedString));
    registry.register(Box::new(mg002_over_permissioning::Mg002OverPermissioning));
    registry.register(Box::new(mg003_escalation_chains::Mg003EscalationChains));
    registry.register(Box::new(mg004_filesystem_scope::Mg004FilesystemScope));
    registry.register(Box::new(mg005_weak_auth::Mg005WeakAuth));
    registry.register(Box::new(mg006_metadata_leakage::Mg006MetadataLeakage));
    registry.register(Box::new(mg007_broad_scope::Mg007BroadScope));
    registry.register(Box::new(mg008_transport_security::Mg008TransportSecurity));
    registry.register(Box::new(mg009_env_leakage::Mg009EnvLeakage));
    registry
}
