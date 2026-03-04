use mcplint_core::{
    escape_pointer, AuthConfig, Confidence, Evidence, Finding, FindingCategory, Rule, ScanContext,
    Severity,
};

/// MG005: Missing or weak authentication model.
/// Detects unauthenticated access, shared secrets, or environment-wide trust.
pub struct Mg005WeakAuth;

/// Returns true if the value looks like an environment variable reference
/// rather than a hardcoded secret. Requires valid env-var syntax after the `$`.
fn is_env_reference(value: &str) -> bool {
    // ${VAR_NAME} or $VAR_NAME with valid env var chars
    if let Some(rest) = value.strip_prefix("${") {
        // Must contain closing brace and valid var name inside
        if let Some(var) = rest.strip_suffix('}') {
            return !var.is_empty() && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        }
        return false;
    }
    if let Some(rest) = value.strip_prefix('$') {
        // $VAR_NAME — must be entirely valid env var chars, and non-empty
        return !rest.is_empty()
            && rest
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    }
    // env:VAR_NAME style
    if value.starts_with("env:") {
        return true;
    }
    false
}

impl Rule for Mg005WeakAuth {
    fn id(&self) -> &'static str {
        "MG005"
    }

    fn description(&self) -> &'static str {
        "Missing or weak authentication model: unauthenticated access, shared secrets, \
         or environment-wide trust."
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Static
    }

    fn explain(&self) -> &'static str {
        "MG005 checks the authentication configuration of each MCP server. Servers without \
         authentication, or with weak authentication (e.g., API keys without specific headers, \
         shared secrets in environment variables), are flagged. Network-accessible servers \
         (HTTP/SSE transport) without authentication are critical findings, as any network \
         peer can invoke tools. Remediation: implement proper authentication (OAuth, mutual \
         TLS, or scoped API keys), avoid embedding secrets in environment variables, and \
         use per-client credentials."
    }

    fn cwe_ids(&self) -> Vec<&'static str> {
        vec!["CWE-306", "CWE-287"]
    }

    fn owasp_ids(&self) -> Vec<&'static str> {
        vec!["A07:2021"]
    }

    fn owasp_mcp_ids(&self) -> Vec<&'static str> {
        vec!["MCP01:2025", "MCP07:2025"]
    }

    fn rationale(&self) -> &'static str {
        "MCP servers without authentication allow unauthorized access to tool capabilities."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://cwe.mitre.org/data/definitions/306.html"]
    }

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for server in &ctx.config.servers {
            let is_network = matches!(
                server.transport.to_lowercase().as_str(),
                "http" | "https" | "sse" | "websocket" | "ws" | "wss"
            );

            // Resolve server-level pointer and region once
            let server_ptr = ctx.server_pointer(&server.name, "");
            let server_region = server_ptr
                .as_ref()
                .and_then(|ptr| ctx.region_for(ptr).cloned());

            match &server.auth {
                AuthConfig::None => {
                    findings.push(Finding {
                        id: "MG005".to_string(),
                        title: format!("No authentication configured for server '{}'", server.name),
                        severity: if is_network {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        confidence: Confidence::High,
                        category: FindingCategory::Static,
                        description: format!(
                            "Server '{}' has no authentication configured (transport: {}). \
                             {} can invoke any of its {} tool(s) without credentials.",
                            server.name,
                            server.transport,
                            if is_network {
                                "Any network peer"
                            } else {
                                "Any local process"
                            },
                            server.tools.len()
                        ),
                        exploit_scenario: format!(
                            "An attacker {} gains direct access to server '{}' and invokes \
                             sensitive tools without authentication, potentially reading data, \
                             executing commands, or modifying state.",
                            if is_network {
                                "on the same network"
                            } else {
                                "with local access"
                            },
                            server.name
                        ),
                        evidence: vec![Evidence {
                            location: format!(
                                "{} > servers[{}].auth",
                                ctx.source_path, server.name
                            ),
                            description: "Authentication is set to 'none' or not configured"
                                .to_string(),
                            raw_value: Some(r#"{"type": "none"}"#.to_string()),
                            region: server_region.clone(),
                            file: Some(ctx.source_path.clone()),
                            json_pointer: server_ptr.clone(),
                            server: Some(server.name.clone()),
                            tool: None,
                            parameter: None,
                        }],
                        cwe_ids: vec!["CWE-306".to_string(), "CWE-287".to_string()],
                        owasp_ids: vec!["A07:2021".to_string()],
                        owasp_mcp_ids: vec![],
                        remediation: format!(
                            "Configure authentication for server '{}'. For network-accessible \
                             servers, use OAuth or mutual TLS. For local servers, use API keys \
                             with per-client scoping. Avoid shared secrets.",
                            server.name
                        ),
                    });
                }
                AuthConfig::ApiKey { header } => {
                    if header.is_none() {
                        findings.push(Finding {
                            id: "MG005".to_string(),
                            title: format!(
                                "API key without specified header for server '{}'",
                                server.name
                            ),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: FindingCategory::Static,
                            description: format!(
                                "Server '{}' uses API key authentication but does not specify \
                                 which header carries the key. This may indicate a default or \
                                 shared key configuration.",
                                server.name
                            ),
                            exploit_scenario: format!(
                                "The API key for server '{}' is sent via a default header, \
                                 making it easier for an attacker to intercept or guess the \
                                 authentication mechanism.",
                                server.name
                            ),
                            evidence: vec![Evidence {
                                location: format!(
                                    "{} > servers[{}].auth",
                                    ctx.source_path, server.name
                                ),
                                description: "API key auth without explicit header specification"
                                    .to_string(),
                                raw_value: Some(
                                    r#"{"type": "api_key", "header": null}"#.to_string(),
                                ),
                                region: server_region.clone(),
                                file: Some(ctx.source_path.clone()),
                                json_pointer: server_ptr.clone(),
                                server: Some(server.name.clone()),
                                tool: None,
                                parameter: None,
                            }],
                            cwe_ids: vec!["CWE-306".to_string(), "CWE-287".to_string()],
                            owasp_ids: vec!["A07:2021".to_string()],
                            owasp_mcp_ids: vec![],
                            remediation: format!(
                                "Specify a custom header for the API key in server '{}'. \
                                 Use a unique, non-standard header name. Consider rotating \
                                 to per-client API keys.",
                                server.name
                            ),
                        });
                    }
                }
                _ => {}
            }

            // Check for secrets in environment variables
            for (key, value) in &server.env {
                let key_lower = key.to_lowercase();
                let is_secret_key = key_lower.contains("secret")
                    || key_lower.contains("password")
                    || key_lower.contains("passwd")
                    || key_lower.contains("token")
                    || key_lower.contains("api_key")
                    || key_lower.contains("apikey")
                    || key_lower.contains("private_key")
                    || key_lower.contains("credential")
                    || key_lower.contains("passphrase")
                    || key_lower.contains("signing_key")
                    || key_lower.contains("encryption_key")
                    || key_lower.contains("master_key")
                    || key_lower.contains("service_key")
                    || key_lower.contains("hmac_key");

                let looks_like_hardcoded = !value.is_empty()
                    && !is_env_reference(value)
                    && !value.contains("vault:")
                    && !value.contains("ssm:")
                    && !value.contains("secretsmanager:");

                if is_secret_key && looks_like_hardcoded {
                    findings.push(Finding {
                        id: "MG005".to_string(),
                        title: format!(
                            "Hardcoded secret in environment variable '{}' for server '{}'",
                            key, server.name
                        ),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: FindingCategory::Static,
                        description: format!(
                            "Server '{}' has environment variable '{}' that appears to contain \
                             a hardcoded secret value. Secrets should be referenced from secure \
                             stores, not embedded in configuration.",
                            server.name, key
                        ),
                        exploit_scenario: format!(
                            "An attacker gains access to the configuration file and extracts \
                             the hardcoded secret from environment variable '{}', gaining \
                             unauthorized access to the service backing server '{}'.",
                            key, server.name
                        ),
                        evidence: vec![{
                            let env_pointer = ctx
                                .server_pointer(
                                    &server.name,
                                    &format!("env/{}", escape_pointer(key)),
                                )
                                .or_else(|| ctx.server_pointer(&server.name, ""));
                            let env_region = env_pointer
                                .as_ref()
                                .and_then(|ptr| ctx.region_for(ptr).cloned());
                            Evidence {
                                location: format!(
                                    "{} > servers[{}].env[{}]",
                                    ctx.source_path, server.name, key
                                ),
                                description: format!(
                                    "Environment variable '{}' contains what appears to be a \
                                     hardcoded secret",
                                    key
                                ),
                                raw_value: Some(format!(
                                    "\"{}\" = \"{}\"",
                                    key,
                                    "*".repeat(value.len().min(8))
                                )),
                                region: env_region,
                                file: Some(ctx.source_path.clone()),
                                json_pointer: env_pointer,
                                server: Some(server.name.clone()),
                                tool: None,
                                parameter: None,
                            }
                        }],
                        cwe_ids: vec!["CWE-306".to_string(), "CWE-287".to_string()],
                        owasp_ids: vec!["A07:2021".to_string()],
                        owasp_mcp_ids: vec![],
                        remediation: format!(
                            "Move the secret in '{}' to a secure secret store (e.g., \
                             Vault, AWS Secrets Manager, or OS keychain). Reference it \
                             via '${{ENV_VAR}}' or 'vault:path/to/secret' syntax.",
                            key
                        ),
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcplint_core::*;
    use std::collections::BTreeMap;

    fn make_server(name: &str, auth: AuthConfig, transport: &str) -> McpServer {
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
            auth,
            transport: transport.into(),
            url: None,
            command: None,
            args: vec![],
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn detects_no_auth_on_network_server() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server("api", AuthConfig::None, "http")],
            },
            "test.json".into(),
        );

        let rule = Mg005WeakAuth;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_no_auth_on_local_server() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server("local", AuthConfig::None, "stdio")],
            },
            "test.json".into(),
        );

        let rule = Mg005WeakAuth;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn detects_hardcoded_secret() {
        let mut env = BTreeMap::new();
        env.insert("DB_PASSWORD".to_string(), "super_secret_123".to_string());

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![McpServer {
                    name: "db".into(),
                    description: "".into(),
                    tools: vec![],
                    auth: AuthConfig::Bearer {
                        token_source: Some("env".into()),
                    },
                    transport: "stdio".into(),
                    url: None,
                    command: None,
                    args: vec![],
                    env,
                }],
            },
            "test.json".into(),
        );

        let rule = Mg005WeakAuth;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Hardcoded secret"));
    }

    #[test]
    fn no_finding_for_oauth() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server(
                    "secure",
                    AuthConfig::OAuth {
                        scopes: vec!["read".into()],
                    },
                    "http",
                )],
            },
            "test.json".into(),
        );

        let rule = Mg005WeakAuth;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_dollar_prefixed_fake_secret() {
        // "$my_actual_secret" is NOT a valid env var reference — should be flagged
        let mut env = BTreeMap::new();
        env.insert("API_TOKEN".to_string(), "$my actual secret".to_string());

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![McpServer {
                    name: "api".into(),
                    description: "".into(),
                    tools: vec![],
                    auth: AuthConfig::None,
                    transport: "stdio".into(),
                    url: None,
                    command: None,
                    args: vec![],
                    env,
                }],
            },
            "test.json".into(),
        );

        let rule = Mg005WeakAuth;
        let findings = rule.check(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Hardcoded secret")),
            "should detect '$my actual secret' as hardcoded (space makes it invalid env ref)"
        );
    }

    #[test]
    fn no_finding_for_valid_env_reference() {
        let mut env = BTreeMap::new();
        env.insert("DB_PASSWORD".to_string(), "${DB_PASSWORD}".to_string());

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![McpServer {
                    name: "db".into(),
                    description: "".into(),
                    tools: vec![],
                    auth: AuthConfig::Bearer {
                        token_source: Some("env".into()),
                    },
                    transport: "stdio".into(),
                    url: None,
                    command: None,
                    args: vec![],
                    env,
                }],
            },
            "test.json".into(),
        );

        let rule = Mg005WeakAuth;
        let findings = rule.check(&ctx);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("Hardcoded secret")),
            "${{DB_PASSWORD}} is a valid env reference"
        );
    }

    #[test]
    fn detects_client_secret_hardcoded() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![McpServer {
                    name: "test-server".into(),
                    description: "".into(),
                    tools: vec![],
                    auth: AuthConfig::None,
                    transport: "stdio".into(),
                    url: None,
                    command: None,
                    args: vec![],
                    env: BTreeMap::from([("CLIENT_SECRET".into(), "abc123hardcodedvalue".into())]),
                }],
            },
            "test.json".into(),
        );

        let rule = Mg005WeakAuth;
        let findings = rule.check(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Hardcoded secret")),
            "CLIENT_SECRET with hardcoded value should trigger MG005"
        );
    }

    #[test]
    fn detects_jwt_secret_hardcoded() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![McpServer {
                    name: "test-server".into(),
                    description: "".into(),
                    tools: vec![],
                    auth: AuthConfig::None,
                    transport: "stdio".into(),
                    url: None,
                    command: None,
                    args: vec![],
                    env: BTreeMap::from([("JWT_SECRET".into(), "supersecretjwtkey123".into())]),
                }],
            },
            "test.json".into(),
        );

        let rule = Mg005WeakAuth;
        let findings = rule.check(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Hardcoded secret")),
            "JWT_SECRET with hardcoded value should trigger MG005"
        );
    }

    #[test]
    fn cookie_secret_with_env_ref() {
        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![McpServer {
                    name: "test-server".into(),
                    description: "".into(),
                    tools: vec![],
                    auth: AuthConfig::None,
                    transport: "stdio".into(),
                    url: None,
                    command: None,
                    args: vec![],
                    env: BTreeMap::from([("COOKIE_SECRET".into(), "$COOKIE_VALUE".into())]),
                }],
            },
            "test.json".into(),
        );

        let rule = Mg005WeakAuth;
        let findings = rule.check(&ctx);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("Hardcoded secret")),
            "COOKIE_SECRET with $COOKIE_VALUE env ref should not flag as hardcoded"
        );
    }
}
