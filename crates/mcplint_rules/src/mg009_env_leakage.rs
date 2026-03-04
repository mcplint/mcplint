use mcplint_core::{
    escape_pointer, Confidence, Evidence, Finding, FindingCategory, Rule, ScanContext, Severity,
};
use regex::Regex;

/// MG009: Environment variable leakage.
/// Detects when MCP server configurations pass environment variables that likely
/// contain secrets directly through to the server process.
pub struct Mg009EnvLeakage;

/// Environment variable names that are known safe and should never be flagged.
const SAFE_ENV_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "NODE_ENV",
    "RUST_LOG",
    "DEBUG",
    "LANG",
    "TERM",
    "SHELL",
    "USER",
    "HOSTNAME",
    "PORT",
    "HOST",
    "TZ",
    "EDITOR",
    "CI",
    "NODE_OPTIONS",
    "DISPLAY",
    "XDG_RUNTIME_DIR",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LC_ALL",
    "LC_CTYPE",
    "PYTHONPATH",
    "GOPATH",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "NPM_CONFIG_PREFIX",
];

/// Substrings in env var names that suggest secrets (case-insensitive).
const SECRET_NAME_PATTERNS: &[&str] = &[
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "AUTH",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "SIGNING_KEY",
    "ENCRYPTION_KEY",
    "MASTER_KEY",
    "SERVICE_KEY",
    "HMAC_KEY",
    "DATABASE_URL",
    "DB_URL",
    "CONNECTION_STRING",
    "CONN_STR",
    "DSN",
];

/// Suffixes that indicate secret env vars.
const SECRET_SUFFIXES: &[&str] = &["_SECRET", "_PASSWORD", "_TOKEN", "_KEY"];

/// Suffixes that are safe even if they end in _KEY.
const SAFE_KEY_SUFFIXES: &[&str] = &["_PUBLIC_KEY", "_PUB_KEY"];

/// Known API key prefixes indicating hardcoded credentials.
const KNOWN_KEY_PREFIXES: &[&str] = &[
    "sk-",
    "pk-",
    "xox",
    "ghp_",
    "gho_",
    "github_pat_",
    "glpat-",
    "AKIA",
];

/// Returns true if the env var name is in the safe list.
fn is_safe_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    SAFE_ENV_NAMES.iter().any(|safe| upper == *safe)
}

/// Returns true if the env var name matches secret patterns.
fn matches_secret_pattern(name: &str) -> bool {
    let upper = name.to_uppercase();

    // Check safe key suffixes first
    if SAFE_KEY_SUFFIXES.iter().any(|s| upper.ends_with(s)) {
        return false;
    }

    // Check substrings
    if SECRET_NAME_PATTERNS
        .iter()
        .any(|pattern| upper.contains(pattern))
    {
        return true;
    }

    // Check suffixes
    SECRET_SUFFIXES.iter().any(|suffix| upper.ends_with(suffix))
}

/// Returns true if the value looks like a variable reference.
fn is_variable_reference(value: &str) -> bool {
    value.starts_with('$') || value.starts_with("${")
}

/// Returns true if the value looks like a hardcoded secret.
fn is_hardcoded_secret(value: &str) -> bool {
    if value.len() < 8 {
        return false;
    }
    if is_variable_reference(value) {
        return false;
    }

    // Check known key prefixes
    if KNOWN_KEY_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
    {
        return true;
    }

    // Check for mix of alphanumeric and special chars suggesting a key
    // At least 20 chars, contains both letters and digits
    if value.len() >= 20 {
        let has_letters = value.chars().any(|c| c.is_ascii_alphabetic());
        let has_digits = value.chars().any(|c| c.is_ascii_digit());
        if has_letters && has_digits {
            return true;
        }
    }

    // Check for connection strings
    let re = Regex::new(r"^(?:mysql|postgres|postgresql|mongodb|redis|amqp)://").ok();
    if let Some(re) = re {
        if re.is_match(value) {
            return true;
        }
    }

    false
}

impl Rule for Mg009EnvLeakage {
    fn id(&self) -> &'static str {
        "MG009"
    }

    fn description(&self) -> &'static str {
        "Sensitive environment variables passed to MCP servers: API keys, database \
         passwords, tokens, and other secrets exposed to potentially untrusted server code."
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Static
    }

    fn explain(&self) -> &'static str {
        "MG009 detects when MCP server configurations forward environment variables that \
         likely contain secrets. This includes API keys, database passwords, tokens, and \
         connection strings passed via the env map. If the MCP server is compromised or \
         its code is modified (supply chain attack), these secrets are captured. Hardcoded \
         secrets in config files are especially dangerous since anyone with file access has \
         the credential. Remediation: use secret managers, minimize env var exposure, and \
         never hardcode secrets in configuration files."
    }

    fn cwe_ids(&self) -> Vec<&'static str> {
        vec!["CWE-798", "CWE-522"]
    }

    fn owasp_ids(&self) -> Vec<&'static str> {
        vec!["A07:2021"]
    }

    fn owasp_mcp_ids(&self) -> Vec<&'static str> {
        vec!["MCP01:2025", "MCP09:2025"]
    }

    fn rationale(&self) -> &'static str {
        "Secrets in environment variables are exposed to MCP server processes and may leak via logs or compromise."
    }

    fn references(&self) -> Vec<&'static str> {
        vec!["https://cwe.mitre.org/data/definitions/798.html"]
    }

    fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for server in &ctx.config.servers {
            let server_ptr = ctx.server_pointer(&server.name, "");

            for (key, value) in &server.env {
                // Skip known safe names
                if is_safe_name(key) {
                    continue;
                }

                let name_is_secret = matches_secret_pattern(key);
                let value_is_hardcoded = is_hardcoded_secret(value);

                if !name_is_secret && !value_is_hardcoded {
                    continue;
                }

                let env_ptr = ctx
                    .server_pointer(&server.name, &format!("env/{}", escape_pointer(key)))
                    .or(server_ptr.clone());
                let env_region = env_ptr
                    .as_ref()
                    .and_then(|ptr| ctx.region_for(ptr).cloned());

                let (severity, confidence, title, description, exploit, remediation) =
                    if value_is_hardcoded {
                        // Critical: hardcoded secret
                        let has_known_prefix = KNOWN_KEY_PREFIXES
                            .iter()
                            .any(|prefix| value.starts_with(prefix));
                        let conf = if has_known_prefix {
                            Confidence::High
                        } else {
                            Confidence::Medium
                        };

                        (
                            Severity::Critical,
                            conf,
                            format!(
                                "Sensitive environment variable '{}' passed to server '{}'",
                                key, server.name
                            ),
                            format!(
                                "Environment variable '{}' on server '{}' contains what appears \
                                 to be a hardcoded secret. Anyone with read access to this \
                                 configuration file has the credential, and the MCP server \
                                 process receives it in its environment.",
                                key, server.name
                            ),
                            format!(
                                "The hardcoded secret in '{}' is embedded in the configuration \
                                 file. Anyone with read access to this file has the credential. \
                                 Additionally, the MCP server process receives it in its \
                                 environment.",
                                key
                            ),
                            format!(
                                "Never hardcode secrets in configuration files. Use a secret \
                                 manager or environment variable reference (${{{}}} ) instead.",
                                key
                            ),
                        )
                    } else if name_is_secret && !is_variable_reference(value) {
                        // High: name matches secret pattern, value is not a variable ref
                        (
                            Severity::High,
                            Confidence::Medium,
                            format!(
                                "Sensitive environment variable '{}' passed to server '{}'",
                                key, server.name
                            ),
                            format!(
                                "Environment variable '{}' likely contains a secret that is \
                                 forwarded to MCP server '{}'. If this server is compromised \
                                 or its code is modified (supply chain attack), the secret \
                                 is captured.",
                                key, server.name
                            ),
                            format!(
                                "The environment variable '{}' contains a secret that is \
                                 forwarded to the MCP server '{}'. If this server is \
                                 compromised or its code is modified (supply chain attack), \
                                 the secret is captured.",
                                key, server.name
                            ),
                            format!(
                                "Consider whether server '{}' actually needs access to '{}'. \
                                 Apply least-privilege: only pass the env vars each server \
                                 requires.",
                                server.name, key
                            ),
                        )
                    } else if name_is_secret {
                        // High: name matches but value is a variable reference
                        (
                            Severity::High,
                            Confidence::Medium,
                            format!(
                                "Sensitive environment variable '{}' passed to server '{}'",
                                key, server.name
                            ),
                            format!(
                                "Environment variable '{}' is forwarded to MCP server '{}'. \
                                 Even though the value references another variable, the \
                                 secret is still exposed to the server process at runtime.",
                                key, server.name
                            ),
                            format!(
                                "The environment variable '{}' contains a secret that is \
                                 forwarded to the MCP server '{}'. If this server is \
                                 compromised or its code is modified (supply chain attack), \
                                 the secret is captured.",
                                key, server.name
                            ),
                            format!(
                                "Consider whether server '{}' actually needs access to '{}'. \
                                 Apply least-privilege: only pass the env vars each server \
                                 requires.",
                                server.name, key
                            ),
                        )
                    } else {
                        continue;
                    };

                // Mask the value for display
                let masked_value = if value.len() > 4 {
                    format!("{}****", &value[..4])
                } else {
                    "****".to_string()
                };

                findings.push(Finding {
                    id: "MG009".to_string(),
                    title,
                    severity,
                    confidence,
                    category: FindingCategory::Static,
                    description,
                    exploit_scenario: exploit,
                    evidence: vec![Evidence {
                        location: format!(
                            "{} > servers[{}].env[{}]",
                            ctx.source_path, server.name, key
                        ),
                        description: format!(
                            "Environment variable '{}' with value '{}'",
                            key, masked_value
                        ),
                        raw_value: Some(format!("\"{}\" = \"{}\"", key, masked_value)),
                        region: env_region,
                        file: Some(ctx.source_path.clone()),
                        json_pointer: env_ptr,
                        server: Some(server.name.clone()),
                        tool: None,
                        parameter: None,
                    }],
                    cwe_ids: vec!["CWE-798".to_string(), "CWE-522".to_string()],
                    owasp_ids: vec!["A07:2021".to_string()],
                    owasp_mcp_ids: vec![],
                    remediation,
                });
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

    fn make_server_with_env(name: &str, env: BTreeMap<String, String>) -> McpServer {
        McpServer {
            name: name.into(),
            description: "".into(),
            tools: vec![],
            auth: AuthConfig::None,
            transport: "stdio".into(),
            url: None,
            command: None,
            args: vec![],
            env,
        }
    }

    #[test]
    fn detects_hardcoded_api_key() {
        let mut env = BTreeMap::new();
        env.insert(
            "OPENAI_KEY".to_string(),
            "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234".to_string(),
        );

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_env("api", env)],
            },
            "test.json".into(),
        );

        let rule = Mg009EnvLeakage;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn detects_secret_name_with_value() {
        let mut env = BTreeMap::new();
        env.insert("SECRET_TOKEN".to_string(), "my-token".to_string());

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_env("api", env)],
            },
            "test.json".into(),
        );

        let rule = Mg009EnvLeakage;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn detects_variable_reference_still_high() {
        let mut env = BTreeMap::new();
        env.insert("DB_PASSWORD".to_string(), "${DB_PASSWORD}".to_string());

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_env("db", env)],
            },
            "test.json".into(),
        );

        let rule = Mg009EnvLeakage;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn skips_safe_env_names() {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        env.insert("NODE_ENV".to_string(), "production".to_string());
        env.insert("HOME".to_string(), "/home/user".to_string());

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_env("safe", env)],
            },
            "test.json".into(),
        );

        let rule = Mg009EnvLeakage;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty(), "Safe env names should be skipped");
    }

    #[test]
    fn skips_public_key() {
        let mut env = BTreeMap::new();
        env.insert("SSH_PUBLIC_KEY".to_string(), "ssh-rsa AAAA...".to_string());
        env.insert("GPG_PUB_KEY".to_string(), "-----BEGIN...".to_string());

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_env("safe", env)],
            },
            "test.json".into(),
        );

        let rule = Mg009EnvLeakage;
        let findings = rule.check(&ctx);
        assert!(findings.is_empty(), "Public keys should be skipped");
    }

    #[test]
    fn detects_aws_key() {
        let mut env = BTreeMap::new();
        env.insert(
            "AWS_ACCESS_KEY".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
        );

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_env("aws", env)],
            },
            "test.json".into(),
        );

        let rule = Mg009EnvLeakage;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_connection_string_in_value() {
        let mut env = BTreeMap::new();
        env.insert(
            "DB_CONN".to_string(),
            "postgres://admin:pass@db.internal:5432/prod".to_string(),
        );

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_env("db", env)],
            },
            "test.json".into(),
        );

        let rule = Mg009EnvLeakage;
        let findings = rule.check(&ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn detects_github_pat() {
        let mut env = BTreeMap::new();
        env.insert(
            "GITHUB_TOKEN".to_string(),
            "ghp_ABCDEFghijklmnop1234567890".to_string(),
        );

        let ctx = ScanContext::new(
            McpConfig {
                servers: vec![make_server_with_env("gh", env)],
            },
            "test.json".into(),
        );

        let rule = Mg009EnvLeakage;
        let findings = rule.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
