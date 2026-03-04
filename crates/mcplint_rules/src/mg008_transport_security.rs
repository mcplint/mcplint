use mcplint_core::{Confidence, Evidence, Finding, FindingCategory, Rule, ScanContext, Severity};
use regex::Regex;

/// MG008: Transport security.
/// Detects MCP servers configured with insecure transport — unencrypted HTTP,
/// insecure WebSocket, or missing TLS.
pub struct Mg008TransportSecurity;

/// Returns true if the host portion of a URL is localhost or a loopback address.
fn is_localhost(url: &str) -> bool {
    let lower = url.to_lowercase();
    // Strip scheme
    let host_part = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .or_else(|| lower.strip_prefix("ws://"))
        .or_else(|| lower.strip_prefix("wss://"))
        .unwrap_or(&lower);

    // Extract host (before port or path)
    let host = host_part
        .split('/')
        .next()
        .unwrap_or(host_part)
        .split(':')
        .next()
        .unwrap_or(host_part);

    matches!(
        host,
        "localhost" | "127.0.0.1" | "[::1]" | "::1" | "0.0.0.0"
    ) || host.ends_with(".localhost")
}

/// Returns true if the URL looks like a production endpoint.
fn is_production_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    let host_part = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("ws://"))
        .unwrap_or(&lower);

    let host = host_part
        .split('/')
        .next()
        .unwrap_or(host_part)
        .split(':')
        .next()
        .unwrap_or(host_part);

    if host.contains("prod") || host.starts_with("api.") || host.starts_with("internal.") {
        return true;
    }

    // Public domain: has a dot, not an IP, no port or port 443/8443
    if host.contains('.') && !host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let port_part = host_part.split('/').next().unwrap_or("").split(':').nth(1);
        return match port_part {
            None => true, // no port = default (likely 80) on public domain
            Some("443") | Some("8443") => true,
            _ => false,
        };
    }

    false
}

/// URL-like pattern for scanning env values and args.
fn find_insecure_url(text: &str) -> Option<String> {
    let re = Regex::new(r"https?://\S+|wss?://\S+").ok()?;
    for m in re.find_iter(text) {
        let url = m.as_str();
        if (url.starts_with("http://") || url.starts_with("ws://")) && !is_localhost(url) {
            return Some(url.to_string());
        }
    }
    None
}

impl Rule for Mg008TransportSecurity {
    fn id(&self) -> &'static str {
        "MG008"
    }

    fn description(&self) -> &'static str {
        "Insecure transport: MCP servers configured with unencrypted HTTP or WebSocket \
         connections, exposing tool calls and responses to network interception."
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Static
    }

    fn explain(&self) -> &'static str {
        "MG008 detects MCP servers using insecure transport protocols. Servers communicating \
         over plain HTTP or WS (without TLS) transmit tool calls, responses, and potentially \
         credentials in cleartext. An attacker on the network can intercept, read, and modify \
         this traffic (man-in-the-middle). Localhost connections are exempt since they don't \
         traverse the network. Remediation: change HTTP URLs to HTTPS and WS URLs to WSS."
    }

    fn cwe_ids(&self) -> Vec<&'static str> {
        vec!["CWE-319"]
    }

    fn owasp_ids(&self) -> Vec<&'static str> {
        vec!["A02:2021"]
    }

    fn owasp_mcp_ids(&self) -> Vec<&'static str> {
        vec!["MCP01:2025", "MCP07:2025"]
    }

    fn rationale(&self) -> &'static str {
        "Unencrypted transport exposes tool calls and responses to network interception."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://cwe.mitre.org/data/definitions/319.html"]
    }

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for server in &ctx.config.servers {
            let server_ptr = ctx.server_pointer(&server.name, "");

            // Collect all URL-bearing fields
            let url_fields: Vec<(&str, Option<&str>)> = vec![("url", server.url.as_deref())];

            for (field_name, maybe_url) in &url_fields {
                if let Some(url) = maybe_url {
                    if let Some(insecure_url) = check_url(url) {
                        let severity = if is_production_url(&insecure_url) {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        let field_ptr = ctx
                            .server_pointer(&server.name, field_name)
                            .or(server_ptr.clone());
                        let field_region = field_ptr
                            .as_ref()
                            .and_then(|ptr| ctx.region_for(ptr).cloned());

                        findings.push(make_finding(
                            &server.name,
                            &insecure_url,
                            severity,
                            &ctx.source_path,
                            field_ptr,
                            field_region,
                            field_name,
                        ));
                    }
                }
            }

            // Scan args array for URLs
            for (i, arg) in server.args.iter().enumerate() {
                if let Some(insecure_url) = find_insecure_url(arg) {
                    let severity = if is_production_url(&insecure_url) {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    let arg_ptr = ctx
                        .server_pointer(&server.name, &format!("args/{}", i))
                        .or(server_ptr.clone());
                    let arg_region = arg_ptr
                        .as_ref()
                        .and_then(|ptr| ctx.region_for(ptr).cloned());

                    findings.push(make_finding(
                        &server.name,
                        &insecure_url,
                        severity,
                        &ctx.source_path,
                        arg_ptr,
                        arg_region,
                        &format!("args[{}]", i),
                    ));
                }
            }

            // Scan env values for URLs
            for (key, value) in &server.env {
                if let Some(insecure_url) = find_insecure_url(value) {
                    let severity = if is_production_url(&insecure_url) {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    let env_ptr = ctx
                        .server_pointer(
                            &server.name,
                            &format!("env/{}", mcplint_core::escape_pointer(key)),
                        )
                        .or(server_ptr.clone());
                    let env_region = env_ptr
                        .as_ref()
                        .and_then(|ptr| ctx.region_for(ptr).cloned());

                    findings.push(Finding {
                        id: "MG008".to_string(),
                        title: format!("Insecure transport on server '{}'", server.name),
                        severity,
                        confidence: Confidence::High,
                        category: FindingCategory::Static,
                        description: format!(
                            "Environment variable '{}' on server '{}' contains an insecure \
                             URL '{}'. Data in transit is unencrypted and vulnerable to \
                             interception.",
                            key, server.name, insecure_url
                        ),
                        exploit_scenario: format!(
                            "Network traffic between the MCP client and server '{}' at {} \
                             is unencrypted. An attacker on the same network can intercept \
                             tool calls and responses, potentially capturing credentials, \
                             PII, or injecting malicious responses.",
                            server.name, insecure_url
                        ),
                        evidence: vec![Evidence {
                            location: format!(
                                "{} > servers[{}].env[{}]",
                                ctx.source_path, server.name, key
                            ),
                            description: format!("Insecure URL in environment variable '{}'", key),
                            raw_value: Some(insecure_url.clone()),
                            region: env_region,
                            file: Some(ctx.source_path.clone()),
                            json_pointer: env_ptr,
                            server: Some(server.name.clone()),
                            tool: None,
                            parameter: None,
                        }],
                        cwe_ids: vec!["CWE-319".to_string()],
                        owasp_ids: vec!["A02:2021".to_string()],
                        owasp_mcp_ids: vec![],
                        remediation: format!(
                            "Change {} to use HTTPS (or WSS for WebSocket). If this is a \
                             development-only server, consider adding it to .mcplint.toml \
                             ignore list.",
                            insecure_url
                        ),
                    });
                }
            }

            // Check transport type with URL
            let transport_lower = server.transport.to_lowercase();
            if (transport_lower == "sse" || transport_lower == "streamable-http")
                && server.url.is_some()
            {
                if let Some(url) = &server.url {
                    if url.starts_with("http://") && !is_localhost(url) {
                        // Already covered by url field check above, skip duplicate
                    }
                }
            }
        }

        findings
    }
}

/// Check if a URL is insecure (http:// or ws:// and not localhost).
fn check_url(url: &str) -> Option<String> {
    if (url.starts_with("http://") || url.starts_with("ws://")) && !is_localhost(url) {
        Some(url.to_string())
    } else {
        None
    }
}

fn make_finding(
    server_name: &str,
    url: &str,
    severity: Severity,
    source_path: &str,
    json_pointer: Option<String>,
    region: Option<mcplint_core::json_locator::Region>,
    field_name: &str,
) -> Finding {
    let scheme = if url.starts_with("ws://") {
        "WSS"
    } else {
        "HTTPS"
    };
    Finding {
        id: "MG008".to_string(),
        title: format!("Insecure transport on server '{}'", server_name),
        severity,
        confidence: Confidence::High,
        category: FindingCategory::Static,
        description: format!(
            "Server '{}' uses insecure URL '{}'. Data in transit is unencrypted \
             and vulnerable to interception/MITM attacks.",
            server_name, url
        ),
        exploit_scenario: format!(
            "Network traffic between the MCP client and server '{}' at {} is \
             unencrypted. An attacker on the same network can intercept tool calls \
             and responses, potentially capturing credentials, PII, or injecting \
             malicious responses.",
            server_name, url
        ),
        evidence: vec![Evidence {
            location: format!("{} > servers[{}].{}", source_path, server_name, field_name),
            description: format!("Insecure URL in field '{}'", field_name),
            raw_value: Some(url.to_string()),
            region,
            file: Some(source_path.to_string()),
            json_pointer,
            server: Some(server_name.to_string()),
            tool: None,
            parameter: None,
        }],
        cwe_ids: vec!["CWE-319".to_string()],
        owasp_ids: vec!["A02:2021".to_string()],
        owasp_mcp_ids: vec![],
        remediation: format!(
            "Change {} to use {} (or WSS for WebSocket). If this is a \
             development-only server, consider adding it to .mcplint.toml \
             ignore list.",
            url, scheme
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcplint_core::*;
    use std::collections::BTreeMap;

    fn make_server_with_url(name: &str, url: Option<&str>, transport: &str) -> McpServer {
        McpServer {
            name: name.into(),
            description: "".into(),
            tools: vec![ToolDefinition {
                name: "some_tool".into(),
                description: "A tool".into(),
                parameters: vec![],
                tags: vec![],
                provenance: ToolProvenance::default(),
            }],
            auth: AuthConfig::None,
            transport: transport.into(),
            url: url.map(|s| s.to_string()),
            command: None,
            args: vec![],
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn detects_http_url() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_url(
                    "api",
                    Some("http://api.example.com/mcp"),
                    "http",
                )],
            },
            "test.json".into(),
        );

        let rule = Mg008TransportSecurity;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High); // production URL
    }

    #[test]
    fn skips_localhost() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_url(
                    "local",
                    Some("http://localhost:8080/mcp"),
                    "http",
                )],
            },
            "test.json".into(),
        );

        let rule = Mg008TransportSecurity;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty(), "localhost should be exempt");
    }

    #[test]
    fn skips_127001() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_url(
                    "local",
                    Some("http://127.0.0.1:3000"),
                    "http",
                )],
            },
            "test.json".into(),
        );

        let rule = Mg008TransportSecurity;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_ws_url() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_url(
                    "stream",
                    Some("ws://streaming.example.com/ws"),
                    "websocket",
                )],
            },
            "test.json".into(),
        );

        let rule = Mg008TransportSecurity;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn no_finding_for_https() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_url(
                    "secure",
                    Some("https://api.example.com/mcp"),
                    "https",
                )],
            },
            "test.json".into(),
        );

        let rule = Mg008TransportSecurity;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_http_in_args() {
        let mut server = make_server_with_url("proxy", None, "stdio");
        server.args = vec![
            "--url".to_string(),
            "http://internal.corp.com:8080/api".to_string(),
        ];

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![server],
            },
            "test.json".into(),
        );

        let rule = Mg008TransportSecurity;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detects_http_in_env() {
        let mut server = make_server_with_url("api", None, "stdio");
        server.env.insert(
            "API_URL".to_string(),
            "http://prod.example.com/v1".to_string(),
        );

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![server],
            },
            "test.json".into(),
        );

        let rule = Mg008TransportSecurity;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn production_url_gets_high_severity() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_url(
                    "prod",
                    Some("http://api.production.example.com/mcp"),
                    "http",
                )],
            },
            "test.json".into(),
        );

        let rule = Mg008TransportSecurity;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn non_production_url_gets_medium_severity() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_url(
                    "dev",
                    Some("http://192.168.1.100:8080/mcp"),
                    "http",
                )],
            },
            "test.json".into(),
        );

        let rule = Mg008TransportSecurity;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }
}
