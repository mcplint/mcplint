use crate::finding::Finding;
use crate::finding::FindingCategory;
use crate::scan_context::ScanContext;

/// Trait that all security rules must implement.
pub trait Rule: Send + Sync {
    /// Unique identifier (e.g., "MG001").
    fn id(&self) -> &'static str;
    /// Human-readable description.
    fn description(&self) -> &'static str;
    /// The category of analysis this rule performs.
    fn category(&self) -> FindingCategory;
    /// Run the rule against the scan context and return any findings.
    fn check(&self, ctx: &ScanContext) -> Vec<Finding>;
    /// Detailed explanation of the rule, its rationale, and what it detects.
    fn explain(&self) -> &'static str;

    /// CWE identifiers this rule maps to.
    fn cwe_ids(&self) -> Vec<&'static str> {
        vec![]
    }

    /// OWASP Top 10 (2021) identifiers this rule maps to.
    fn owasp_ids(&self) -> Vec<&'static str> {
        vec![]
    }

    /// OWASP MCP Top 10 (2025) identifiers this rule maps to.
    fn owasp_mcp_ids(&self) -> Vec<&'static str> {
        vec![]
    }

    /// Short one-line rationale for why this rule exists.
    fn rationale(&self) -> &'static str {
        ""
    }

    /// References — URLs to relevant documentation or standards.
    fn references(&self) -> Vec<&'static str> {
        vec![]
    }
}

/// Registry of all available rules.
pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn register(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    pub fn find_rule(&self, id: &str) -> Option<&dyn Rule> {
        self.rules.iter().find(|r| r.id() == id).map(|r| r.as_ref())
    }

    /// Run all rules against the given context.
    pub fn run_all(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings: Vec<Finding> = self
            .rules
            .iter()
            .flat_map(|rule| {
                let mut rule_findings = rule.check(ctx);
                // Enrich findings with CWE/OWASP metadata from the rule
                let cwe = rule.cwe_ids();
                let owasp = rule.owasp_ids();
                let owasp_mcp = rule.owasp_mcp_ids();
                if !cwe.is_empty() || !owasp.is_empty() || !owasp_mcp.is_empty() {
                    for f in &mut rule_findings {
                        if f.cwe_ids.is_empty() {
                            f.cwe_ids = cwe.iter().map(|s| s.to_string()).collect();
                        }
                        if f.owasp_ids.is_empty() {
                            f.owasp_ids = owasp.iter().map(|s| s.to_string()).collect();
                        }
                        if f.owasp_mcp_ids.is_empty() {
                            f.owasp_mcp_ids = owasp_mcp.iter().map(|s| s.to_string()).collect();
                        }
                    }
                }
                rule_findings
            })
            .collect();
        // Deterministic ordering: by severity (desc), then by id, then by title.
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.id.cmp(&b.id))
                .then_with(|| a.title.cmp(&b.title))
        });
        findings
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}
