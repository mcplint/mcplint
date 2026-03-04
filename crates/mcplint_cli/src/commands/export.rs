use anyhow::{Context, Result};
use mcplint_core::adapters;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

pub fn cmd_export(path: PathBuf, out: PathBuf) -> Result<()> {
    let path_str = path.display().to_string();

    let result = adapters::auto_load(&path)
        .with_context(|| format!("Failed to load MCP configuration: {}", path_str))?;

    eprintln!("adapter: {}", result.adapter_name);
    for warning in &result.warnings {
        eprintln!("warning: {}", warning);
    }

    std::fs::create_dir_all(&out)
        .with_context(|| format!("Failed to create output directory: {}", out.display()))?;

    // Write mcp.config.json
    let config_path = out.join("mcp.config.json");
    let config_json =
        serde_json::to_string_pretty(&result.config).context("Failed to serialize config")?;
    std::fs::write(&config_path, &config_json)
        .with_context(|| format!("Failed to write {}", config_path.display()))?;
    eprintln!("wrote: {}", config_path.display());

    // Write per-server tools.json files
    for (i, server) in result.config.servers.iter().enumerate() {
        let tools_file = mcplint_core::McpToolsFile {
            server_name: Some(server.name.clone()),
            tools: server.tools.clone(),
            auth: server.auth.clone(),
        };
        let filename = safe_server_filename(i, &server.name, "tools.json");
        let tools_path = out.join(&filename);
        let tools_json =
            serde_json::to_string_pretty(&tools_file).context("Failed to serialize tools")?;
        std::fs::write(&tools_path, &tools_json)
            .with_context(|| format!("Failed to write {}", tools_path.display()))?;
        eprintln!("wrote: {}", tools_path.display());
    }

    Ok(())
}

/// Sanitize a server name into a safe filename component.
/// Removes path separators, `..`, and maps non-alphanumerics to `_`. Trims to 64 chars.
pub(crate) fn sanitize_filename(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // Collapse consecutive underscores and trim leading/trailing underscores
    let mut result = String::new();
    let mut prev_underscore = true; // treat start as underscore to trim leading
    for c in sanitized.chars() {
        if c == '_' {
            if !prev_underscore {
                result.push('_');
            }
            prev_underscore = true;
        } else {
            result.push(c);
            prev_underscore = false;
        }
    }
    let result = result.trim_end_matches('_').to_string();
    let result = if result.len() > 64 {
        result[..64].to_string()
    } else {
        result
    };
    if result.is_empty() {
        "unnamed".to_string()
    } else {
        result
    }
}

/// Build a safe export filename: server-{index}-{sanitized}-{hash8}.{suffix}
pub(crate) fn safe_server_filename(index: usize, name: &str, suffix: &str) -> String {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    let hash8 = format!("{:016x}", hasher.finish());
    let hash8 = &hash8[..8];
    format!(
        "server-{}-{}-{}.{}",
        index,
        sanitize_filename(name),
        hash8,
        suffix
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_removes_path_separators() {
        assert_eq!(sanitize_filename("../../pwn"), "pwn");
    }

    #[test]
    fn sanitize_normal_name() {
        assert_eq!(sanitize_filename("my-server"), "my-server");
    }

    #[test]
    fn sanitize_complex_traversal() {
        assert_eq!(sanitize_filename("../../../etc/passwd"), "etc_passwd");
    }

    #[test]
    fn sanitize_empty_name() {
        assert_eq!(sanitize_filename(""), "unnamed");
    }

    #[test]
    fn sanitize_only_dots_and_slashes() {
        assert_eq!(sanitize_filename("../.."), "unnamed");
    }

    #[test]
    fn sanitize_long_name_truncated() {
        let long = "a".repeat(100);
        assert!(sanitize_filename(&long).len() <= 64);
    }

    #[test]
    fn safe_filename_no_traversal() {
        let fname = safe_server_filename(0, "../../pwn", "tools.json");
        assert!(!fname.contains('/'));
        assert!(!fname.contains('\\'));
        assert!(!fname.contains(".."));
        assert!(fname.starts_with("server-0-"));
        assert!(fname.ends_with(".tools.json"));
    }

    #[test]
    fn safe_filename_stays_inside_out_dir() {
        let out_dir = std::env::temp_dir().join("mcplint-test-export");
        let fname = safe_server_filename(0, "../../pwn", "tools.json");
        let full_path = out_dir.join(&fname);
        assert!(full_path.starts_with(&out_dir));
    }

    #[test]
    fn safe_filename_deterministic() {
        let a = safe_server_filename(1, "my-server", "tools.json");
        let b = safe_server_filename(1, "my-server", "tools.json");
        assert_eq!(a, b);
    }
}
