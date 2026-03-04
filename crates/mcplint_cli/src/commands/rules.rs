use anyhow::Result;
use mcplint_core::rule::RuleRegistry;
use std::process;

use crate::exit_codes;

pub fn cmd_list_rules(registry: &RuleRegistry) -> Result<()> {
    println!("mcplint security rules:");
    println!("{}", "═".repeat(60));
    println!();

    for rule in registry.rules() {
        let cwe = rule.cwe_ids();
        let owasp = rule.owasp_ids();
        let owasp_mcp = rule.owasp_mcp_ids();
        let mut meta = String::new();
        if !cwe.is_empty() {
            meta.push_str(&format!(" | CWE: {}", cwe.join(", ")));
        }
        if !owasp.is_empty() {
            meta.push_str(&format!(" | OWASP: {}", owasp.join(", ")));
        }
        if !owasp_mcp.is_empty() {
            meta.push_str(&format!(" | MCP: {}", owasp_mcp.join(", ")));
        }
        println!(
            "  {} [{}] {}{}",
            rule.id(),
            rule.category(),
            rule.description(),
            meta
        );
    }

    println!();
    println!(
        "Total: {} rules. Use 'mcplint explain <rule-id>' for details.",
        registry.rules().len()
    );

    Ok(())
}

pub fn cmd_explain(rule_id: &str, registry: &RuleRegistry) -> Result<()> {
    let rule_id_upper = rule_id.to_uppercase();

    match registry.find_rule(&rule_id_upper) {
        Some(rule) => {
            println!("Rule: {}", rule.id());
            println!("Category: {}", rule.category());
            println!("Description: {}", rule.description());
            let cwe = rule.cwe_ids();
            if !cwe.is_empty() {
                println!("CWE: {}", cwe.join(", "));
            }
            let owasp = rule.owasp_ids();
            if !owasp.is_empty() {
                println!("OWASP: {}", owasp.join(", "));
            }
            let owasp_mcp = rule.owasp_mcp_ids();
            if !owasp_mcp.is_empty() {
                println!("OWASP MCP: {}", owasp_mcp.join(", "));
            }
            let rationale = rule.rationale();
            if !rationale.is_empty() {
                println!("Rationale: {}", rationale);
            }
            let refs = rule.references();
            if !refs.is_empty() {
                println!("References: {}", refs.join(", "));
            }
            println!();
            println!("{}", rule.explain());
            Ok(())
        }
        None => {
            eprintln!(
                "Unknown rule: '{}'. Use 'mcplint list-rules' to see available rules.",
                rule_id
            );
            process::exit(exit_codes::EXIT_ERROR);
        }
    }
}
