# Finding Fingerprints

mcplint assigns a **stable fingerprint** to every finding. Fingerprints are the identity primitive that enables baseline diffing, drift detection, and deduplication across runs.

## Contract (v1)

| Property | Guarantee |
|----------|-----------|
| **Deterministic** | Same logical finding → same fingerprint, every run |
| **Offline** | No network calls; pure hash computation |
| **Location-stable** | Changing line/column numbers does NOT change the fingerprint |
| **Severity-independent** | Policy-downgraded severity does NOT change the fingerprint |
| **Message-independent** | Changes to description/remediation text do NOT change the fingerprint |
| **Normalized** | All components are lowercased and trimmed before hashing |

## Canonical String Format

```
mcplint:finding:v1|{rule_id}|{file}|{json_pointer}|{server}|{tool}|{parameter}
```

Each component:

| Component | Source | Example |
|-----------|--------|---------|
| `rule_id` | `Finding.id` | `mg001` |
| `file` | `Evidence.file` | `config.json` |
| `json_pointer` | `Evidence.json_pointer` (RFC 6901) | `/mcpservers/db/tools/0` |
| `server` | `Evidence.server` | `db` |
| `tool` | `Evidence.tool` | `query` |
| `parameter` | `Evidence.parameter` | `sql` |

If any component is absent, an empty string is used. The pipe-delimited structure is always preserved (6 pipes, 7 segments).

## Algorithm

1. Build the canonical string from the first evidence item.
2. For multi-evidence findings, append additional evidence groups separated by `|`.
3. Lowercase and trim every component.
4. SHA-256 hash the canonical string (UTF-8 bytes).
5. Output as 64-character lowercase hex.

## Multi-evidence Findings

Some rules (e.g., MG003 cross-server escalation) produce findings with multiple evidence items
representing an attack chain. All evidence items contribute to the fingerprint to avoid collisions
between findings that share the same first evidence but differ in subsequent chain steps.

For multi-evidence findings, the canonical string extends the base format:

```
mcplint:finding:v1|{rule_id}|{ev0_file}|{ev0_pointer}|{ev0_server}|{ev0_tool}|{ev0_param}|{ev1_file}|{ev1_pointer}|{ev1_server}|{ev1_tool}|{ev1_param}|...
```

Each additional evidence item appends 5 pipe-separated fields. The format for **single-evidence
findings is unchanged** — existing fingerprints, baselines, and risk acceptances remain valid.

## Output Locations

- **JSON output**: `fingerprint` field on each finding object.
- **SARIF output**: `result.fingerprints["mcplint/finding"]` and `result.partialFingerprints["mcplint/v1"]`.

## Versioning

The version prefix (`v1`) is embedded in the canonical string. If the fingerprint algorithm ever changes:

1. The prefix bumps to `v2` (or higher).
2. The SARIF `partialFingerprints` key updates to `mcplint/v2`.
3. Baseline diff will handle version migration by comparing within the same version.

The `fingerprints["mcplint/finding"]` key always contains the latest version's output.

## What Is NOT in the Fingerprint

- Severity (can be policy-downgraded)
- Confidence
- Line/column numbers (change on any edit)
- Description, title, remediation text (can be reworded)
- Raw evidence values
- Timestamps
