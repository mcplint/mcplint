use mcplint_core::{Confidence, Finding, FindingCategory, Severity};
use serde::Serialize;
use std::collections::BTreeMap;

/// SARIF 2.1.0 schema URI.
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

// ── SARIF types ──

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    artifacts: Vec<SarifArtifact>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool<'a> {
    driver: SarifToolComponent<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifToolComponent<'a> {
    name: &'static str,
    version: &'a str,
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    full_description: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    help: Option<SarifMessage>,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRuleProperties {
    category: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage {
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    markdown: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    rule_index: usize,
    level: &'static str,
    message: SarifMessage,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    related_locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    fingerprints: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    partial_fingerprints: BTreeMap<String, String>,
    properties: SarifResultProperties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResultProperties {
    confidence: String,
    category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exploit_scenario: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    owasp_mcp_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<SarifMessage>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_base_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifact {
    location: SarifArtifactLocation,
}

// ── Mapping helpers ──

fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn confidence_str(confidence: Confidence) -> String {
    match confidence {
        Confidence::High => "high".into(),
        Confidence::Medium => "medium".into(),
        Confidence::Low => "low".into(),
    }
}

fn category_str(category: FindingCategory) -> String {
    match category {
        FindingCategory::Static => "static".into(),
        FindingCategory::Semantic => "semantic".into(),
        FindingCategory::Compositional => "compositional".into(),
    }
}

/// Extract a file path from an evidence location string.
///
/// Evidence locations use the format: `path/to/file > jsonpath`
/// Returns the file portion if present.
fn extract_file_from_location(location: &str) -> Option<String> {
    let path_part = if location.contains(" > ") {
        location.split(" > ").next().unwrap_or(location).trim()
    } else {
        location.trim()
    };

    if path_part.is_empty() {
        return None;
    }

    Some(path_part.to_string())
}

// ── Public render function ──

/// Render findings as SARIF 2.1.0 JSON.
///
/// `source_path` is used as the artifact URI for findings that reference it.
/// `version` is the tool version string (from Cargo package).
/// `rules` provides rule metadata for the tool.driver.rules section.
pub fn render(
    findings: &[Finding],
    source_path: &str,
    version: &str,
    rules_meta: &[(String, String, String, String)], // (id, description, category, explain)
) -> String {
    // Build rule index: id -> index for results to reference
    let mut rule_index_map = std::collections::HashMap::new();
    let sarif_rules: Vec<SarifRule> = rules_meta
        .iter()
        .enumerate()
        .map(|(i, (id, description, category, explain))| {
            rule_index_map.insert(id.clone(), i);
            SarifRule {
                id: id.clone(),
                name: id.clone(),
                short_description: SarifMessage {
                    text: description.clone(),
                    markdown: None,
                },
                full_description: SarifMessage {
                    text: description.clone(),
                    markdown: None,
                },
                help: if explain.is_empty() {
                    None
                } else {
                    Some(SarifMessage {
                        text: explain.clone(),
                        markdown: None,
                    })
                },
                properties: SarifRuleProperties {
                    category: category.clone(),
                },
            }
        })
        .collect();

    // Build results
    let sarif_results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let rule_index = rule_index_map.get(&f.id).copied().unwrap_or(0);

            // Build locations from evidence
            let locations: Vec<SarifLocation> = f
                .evidence
                .iter()
                .filter_map(|ev| {
                    let file = extract_file_from_location(&ev.location)?;
                    // Only emit region when we have real line/column data.
                    // Do not fabricate a region — it misleads PR annotations.
                    let region = ev.region.as_ref().map(|r| SarifRegion {
                        start_line: r.start_line,
                        start_column: Some(r.start_column),
                        end_line: Some(r.end_line),
                        end_column: Some(r.end_column),
                    });
                    Some(SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation {
                                uri: file,
                                uri_base_id: None,
                            },
                            region,
                        },
                        message: Some(SarifMessage {
                            text: ev.description.clone(),
                            markdown: None,
                        }),
                    })
                })
                .collect();

            // If no evidence-based locations, use source_path
            let locations = if locations.is_empty() {
                vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: source_path.to_string(),
                            uri_base_id: None,
                        },
                        region: None,
                    },
                    message: None,
                }]
            } else {
                locations
            };

            // Build message with description + remediation
            let message_text = format!("{}\n\n**Remediation:** {}", f.description, f.remediation);
            let message_markdown = format!(
                "{}\n\n**Exploit scenario:** {}\n\n**Remediation:** {}",
                f.description, f.exploit_scenario, f.remediation
            );

            // Build relatedLocations from evidence[1..] (additional evidence beyond the primary)
            let related_locations: Vec<SarifLocation> = if f.evidence.len() > 1 {
                f.evidence[1..]
                    .iter()
                    .filter_map(|ev| {
                        let file = ev
                            .file
                            .as_deref()
                            .or_else(|| {
                                extract_file_from_location(&ev.location)
                                    .as_deref()
                                    .map(|_| "")
                            })
                            .and_then(|_| {
                                ev.file
                                    .clone()
                                    .or_else(|| extract_file_from_location(&ev.location))
                            })?;
                        let region = ev.region.as_ref().map(|r| SarifRegion {
                            start_line: r.start_line,
                            start_column: Some(r.start_column),
                            end_line: Some(r.end_line),
                            end_column: Some(r.end_column),
                        });
                        Some(SarifLocation {
                            physical_location: SarifPhysicalLocation {
                                artifact_location: SarifArtifactLocation {
                                    uri: file,
                                    uri_base_id: None,
                                },
                                region,
                            },
                            message: Some(SarifMessage {
                                text: ev.description.clone(),
                                markdown: None,
                            }),
                        })
                    })
                    .collect()
            } else {
                vec![]
            };

            // Build fingerprints using the stable v1 fingerprint
            let fp = f.fingerprint();
            let mut fingerprints = BTreeMap::new();
            fingerprints.insert("mcplint/finding".to_string(), fp.clone());
            let mut partial_fingerprints = BTreeMap::new();
            partial_fingerprints.insert("mcplint/v1".to_string(), fp);

            SarifResult {
                rule_id: f.id.clone(),
                rule_index,
                level: severity_to_level(f.severity),
                message: SarifMessage {
                    text: message_text,
                    markdown: Some(message_markdown),
                },
                locations,
                related_locations,
                fingerprints,
                partial_fingerprints,
                properties: SarifResultProperties {
                    confidence: confidence_str(f.confidence),
                    category: category_str(f.category),
                    exploit_scenario: Some(f.exploit_scenario.clone()),
                    owasp_mcp_ids: f.owasp_mcp_ids.clone(),
                },
            }
        })
        .collect();

    // Collect unique artifacts
    let mut artifact_uris: Vec<String> = Vec::new();
    for result in &sarif_results {
        for loc in &result.locations {
            let uri = &loc.physical_location.artifact_location.uri;
            if !artifact_uris.contains(uri) {
                artifact_uris.push(uri.clone());
            }
        }
    }
    let artifacts: Vec<SarifArtifact> = artifact_uris
        .into_iter()
        .map(|uri| SarifArtifact {
            location: SarifArtifactLocation {
                uri,
                uri_base_id: None,
            },
        })
        .collect();

    let log = SarifLog {
        schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolComponent {
                    name: "mcplint",
                    version,
                    information_uri: "https://github.com/mcplint/mcplint",
                    rules: sarif_rules,
                },
            },
            results: sarif_results,
            artifacts,
        }],
    };

    serde_json::to_string_pretty(&log)
        .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize SARIF: {}\"}}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcplint_core::*;

    fn sample_rules_meta() -> Vec<(String, String, String, String)> {
        vec![
            ("MG001".into(), "Unbounded string to dangerous sink".into(), "static".into(), "MG001 detects unconstrained string parameters flowing to dangerous sinks.".into()),
            ("MG002".into(), "Semantic over-permissioning".into(), "static".into(), "MG002 identifies tools where description suggests limited access but capabilities are broader.".into()),
        ]
    }

    fn sample_finding() -> Finding {
        Finding {
            id: "MG001".into(),
            title: "Unbounded string 'query' flows to dangerous sink".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "Parameter 'query' is unconstrained".into(),
            exploit_scenario: "Attacker injects SQL".into(),
            evidence: vec![Evidence {
                location: "config.json > servers[db] > tools[query] > parameters[sql]".into(),
                description: "Unconstrained string parameter".into(),
                raw_value: Some("{ \"name\": \"sql\" }".into()),
                region: None,
                file: None,
                json_pointer: None,
                server: None,
                tool: None,
                parameter: None,
            }],
            remediation: "Add input constraints".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        }
    }

    #[test]
    fn sarif_output_is_valid_json() {
        let findings = vec![sample_finding()];
        let output = render(&findings, "test.json", "0.1.0", &sample_rules_meta());
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(
            parsed["$schema"],
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        );
    }

    #[test]
    fn sarif_has_tool_metadata() {
        let findings = vec![sample_finding()];
        let output = render(&findings, "test.json", "0.1.0", &sample_rules_meta());
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let driver = &parsed["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "mcplint");
        assert_eq!(driver["version"], "0.1.0");
        assert!(driver["informationUri"]
            .as_str()
            .unwrap()
            .contains("mcplint"));
    }

    #[test]
    fn sarif_has_rules_section() {
        let findings = vec![sample_finding()];
        let output = render(&findings, "test.json", "0.1.0", &sample_rules_meta());
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "MG001");
        assert_eq!(rules[1]["id"], "MG002");
    }

    #[test]
    fn sarif_severity_mapping() {
        assert_eq!(severity_to_level(Severity::Critical), "error");
        assert_eq!(severity_to_level(Severity::High), "error");
        assert_eq!(severity_to_level(Severity::Medium), "warning");
        assert_eq!(severity_to_level(Severity::Low), "note");
    }

    #[test]
    fn sarif_result_has_locations() {
        let findings = vec![sample_finding()];
        let output = render(&findings, "test.json", "0.1.0", &sample_rules_meta());
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let result = &parsed["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "MG001");
        assert_eq!(result["level"], "error");

        let locations = result["locations"].as_array().unwrap();
        assert!(!locations.is_empty());
        assert!(locations[0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .contains("config.json"));
    }

    #[test]
    fn sarif_result_has_properties() {
        let findings = vec![sample_finding()];
        let output = render(&findings, "test.json", "0.1.0", &sample_rules_meta());
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let props = &parsed["runs"][0]["results"][0]["properties"];
        assert_eq!(props["confidence"], "high");
        assert_eq!(props["category"], "static");
        assert!(props["exploitScenario"].as_str().is_some());
    }

    #[test]
    fn sarif_empty_findings_produces_valid_output() {
        let output = render(&[], "test.json", "0.1.0", &sample_rules_meta());
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 0);
        // Rules should still be present
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn sarif_message_includes_remediation() {
        let findings = vec![sample_finding()];
        let output = render(&findings, "test.json", "0.1.0", &sample_rules_meta());
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let msg = &parsed["runs"][0]["results"][0]["message"];
        assert!(msg["text"].as_str().unwrap().contains("Remediation"));
        assert!(msg["markdown"]
            .as_str()
            .unwrap()
            .contains("Exploit scenario"));
    }

    #[test]
    fn extract_file_from_evidence_location() {
        assert_eq!(
            extract_file_from_location("config.json > servers[0]"),
            Some("config.json".into())
        );
        assert_eq!(
            extract_file_from_location("path/to/file.json > tools[test]"),
            Some("path/to/file.json".into())
        );
        assert_eq!(extract_file_from_location(""), None);
        assert_eq!(
            extract_file_from_location("simple.json"),
            Some("simple.json".into())
        );
    }

    #[test]
    fn sarif_no_region_when_evidence_region_is_none() {
        let finding = Finding {
            id: "MG001".into(),
            title: "Test finding".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "desc".into(),
            exploit_scenario: "scenario".into(),
            evidence: vec![Evidence {
                location: "config.json > servers[0]".into(),
                description: "test evidence".into(),
                raw_value: None,
                region: None,
                file: None,
                json_pointer: None,
                server: None,
                tool: None,
                parameter: None,
            }],
            remediation: "fix it".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        };
        let output = render(&[finding], "test.json", "0.1.0", &sample_rules_meta());
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let loc = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        // artifactLocation must be present
        assert!(loc["artifactLocation"]["uri"].as_str().is_some());
        // region must be absent (null in JSON means the field was omitted via skip_serializing_if)
        assert!(
            loc.get("region").is_none() || loc["region"].is_null(),
            "region must not be present when evidence.region is None"
        );
    }

    #[test]
    fn sarif_region_present_when_evidence_has_region() {
        let finding = Finding {
            id: "MG001".into(),
            title: "Test finding".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: FindingCategory::Static,
            description: "desc".into(),
            exploit_scenario: "scenario".into(),
            evidence: vec![Evidence {
                location: "config.json > servers[0]".into(),
                description: "test evidence".into(),
                raw_value: None,
                region: Some(Region {
                    start_line: 10,
                    start_column: 5,
                    end_line: 10,
                    end_column: 20,
                }),
                file: None,
                json_pointer: None,
                server: None,
                tool: None,
                parameter: None,
            }],
            remediation: "fix it".into(),
            cwe_ids: vec![],
            owasp_ids: vec![],
            owasp_mcp_ids: vec![],
        };
        let output = render(&[finding], "test.json", "0.1.0", &sample_rules_meta());
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let region = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 10);
        assert_eq!(region["startColumn"], 5);
        assert_eq!(region["endLine"], 10);
        assert_eq!(region["endColumn"], 20);
    }
}
