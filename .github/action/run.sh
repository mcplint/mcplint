#!/usr/bin/env bash
set -uo pipefail
# Note: NOT set -e because we need to capture the exit code

# ── Inputs ──────────────────────────────────────────────────────────
MODE="${INPUT_MODE:-scan}"
SCAN_PATH="${INPUT_PATH:-.}"
FORMAT="${INPUT_FORMAT:-sarif}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
FAIL_ON_NEW="${INPUT_FAIL_ON_NEW:-low}"
BASELINE="${INPUT_BASELINE:-}"
SAVE_BASELINE="${INPUT_SAVE_BASELINE:-}"
CONFIG_FLAG=""

if [ -n "${INPUT_CONFIG:-}" ]; then
  CONFIG_FLAG="--config ${INPUT_CONFIG}"
fi

# ── Validate inputs ────────────────────────────────────────────────
if [ "$MODE" = "diff" ] && [ -z "$BASELINE" ]; then
  echo "::error::mode=diff requires the 'baseline' input to be set"
  exit 1
fi

if [ -n "$SAVE_BASELINE" ] && [ "$MODE" = "diff" ]; then
  echo "::error::save-baseline is only supported in scan mode, not diff mode"
  exit 1
fi

# ── Functions ───────────────────────────────────────────────────────
extract_sarif_counts() {
  local sarif_file="$1"
  if command -v jq &> /dev/null && [ -f "$sarif_file" ]; then
    TOTAL=$(jq '[.runs[].results[]] | length' "$sarif_file" 2>/dev/null || echo "0")
    CRITICAL=$(jq '[.runs[].results[] | select(.level == "error" and .properties.severity == "critical")] | length' "$sarif_file" 2>/dev/null || echo "0")
    HIGH=$(jq '[.runs[].results[] | select(.level == "error" and .properties.severity == "high")] | length' "$sarif_file" 2>/dev/null || echo "0")
  else
    TOTAL="unknown"
    CRITICAL="unknown"
    HIGH="unknown"
  fi
}

# ── Run: scan mode ─────────────────────────────────────────────────
if [ "$MODE" = "scan" ]; then

  SAVE_FLAG=""
  if [ -n "$SAVE_BASELINE" ]; then
    SAVE_FLAG="--save-baseline ${SAVE_BASELINE}"
  fi

  if [ "$FORMAT" = "sarif" ]; then
    SARIF_FILE="${RUNNER_TEMP:-/tmp}/mcplint-results.sarif"
    # shellcheck disable=SC2086
    mcplint scan "$SCAN_PATH" --format sarif --fail-on "$FAIL_ON" $CONFIG_FLAG $SAVE_FLAG > "$SARIF_FILE" 2>&1
    EXIT_CODE=$?
    extract_sarif_counts "$SARIF_FILE"
    echo "sarif-file=${SARIF_FILE}" >> "$GITHUB_OUTPUT"
  else
    # shellcheck disable=SC2086
    OUTPUT=$(mcplint scan "$SCAN_PATH" --format "$FORMAT" --fail-on "$FAIL_ON" $CONFIG_FLAG $SAVE_FLAG 2>&1)
    EXIT_CODE=$?
    echo "$OUTPUT"
    TOTAL="unknown"
    CRITICAL="unknown"
    HIGH="unknown"
  fi

  if [ -n "$SAVE_BASELINE" ]; then
    echo "baseline-file=${SAVE_BASELINE}" >> "$GITHUB_OUTPUT"
  fi

  {
    echo "findings-count=${TOTAL}"
    echo "critical-count=${CRITICAL}"
    echo "high-count=${HIGH}"
    echo "exit-code=${EXIT_CODE}"
    echo "new-findings-count="
    echo "resolved-findings-count="
  } >> "$GITHUB_OUTPUT"

# ── Run: diff mode ─────────────────────────────────────────────────
elif [ "$MODE" = "diff" ]; then

  DIFF_FORMAT="json"

  # shellcheck disable=SC2086
  DIFF_OUTPUT=$(mcplint diff "$SCAN_PATH" --baseline "$BASELINE" --fail-on-new "$FAIL_ON_NEW" --format "$DIFF_FORMAT" $CONFIG_FLAG 2>&1)
  EXIT_CODE=$?

  # Parse diff JSON for counts
  if command -v jq &> /dev/null; then
    NEW_COUNT=$(echo "$DIFF_OUTPUT" | jq '.new_findings | length' 2>/dev/null || echo "unknown")
    RESOLVED_COUNT=$(echo "$DIFF_OUTPUT" | jq '.resolved_findings | length' 2>/dev/null || echo "unknown")
    TOTAL=$(echo "$DIFF_OUTPUT" | jq '.current_total' 2>/dev/null || echo "unknown")
  else
    NEW_COUNT="unknown"
    RESOLVED_COUNT="unknown"
    TOTAL="unknown"
  fi

  {
    echo "findings-count=${TOTAL}"
    echo "critical-count="
    echo "high-count="
    echo "exit-code=${EXIT_CODE}"
    echo "new-findings-count=${NEW_COUNT}"
    echo "resolved-findings-count=${RESOLVED_COUNT}"
  } >> "$GITHUB_OUTPUT"

  # Also produce human-readable output
  # shellcheck disable=SC2086
  mcplint diff "$SCAN_PATH" --baseline "$BASELINE" --fail-on-new "$FAIL_ON_NEW" --format text $CONFIG_FLAG 2>&1 || true

  # If SARIF is also requested, run a scan to produce SARIF for Code Scanning
  if [ "$FORMAT" = "sarif" ]; then
    SARIF_FILE="${RUNNER_TEMP:-/tmp}/mcplint-results.sarif"
    # shellcheck disable=SC2086
    mcplint scan "$SCAN_PATH" --format sarif $CONFIG_FLAG > "$SARIF_FILE" 2>/dev/null || true
    echo "sarif-file=${SARIF_FILE}" >> "$GITHUB_OUTPUT"
  fi

else
  echo "::error::Unknown mode '${MODE}'. Use 'scan' or 'diff'."
  exit 1
fi

# ── Job Summary ─────────────────────────────────────────────────────
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## mcplint ${MODE} results"
    echo ""
    if [ "$MODE" = "scan" ]; then
      echo "| Metric | Count |"
      echo "|--------|-------|"
      echo "| Total findings | ${TOTAL} |"
      echo "| Critical | ${CRITICAL:-—} |"
      echo "| High | ${HIGH:-—} |"
      echo "| Threshold | \`--fail-on ${FAIL_ON}\` |"
      echo ""
      if [ "$EXIT_CODE" -eq 2 ]; then
        echo "> **Findings detected above \`${FAIL_ON}\` threshold.**"
      elif [ "$EXIT_CODE" -eq 1 ]; then
        echo "> **Scan encountered an error.** Check logs for details."
      else
        echo "> **No findings above \`${FAIL_ON}\` threshold.**"
      fi
    elif [ "$MODE" = "diff" ]; then
      echo "| Metric | Count |"
      echo "|--------|-------|"
      echo "| New findings | ${NEW_COUNT} |"
      echo "| Resolved findings | ${RESOLVED_COUNT} |"
      echo "| Current total | ${TOTAL} |"
      echo "| Threshold | \`--fail-on-new ${FAIL_ON_NEW}\` |"
      echo ""
      if [ "$EXIT_CODE" -eq 2 ]; then
        echo "> **New findings detected above \`${FAIL_ON_NEW}\` threshold.**"
      elif [ "$EXIT_CODE" -eq 1 ]; then
        echo "> **Diff encountered an error.** Check logs for details."
      else
        echo "> **No new findings. Safe to merge.**"
      fi
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

# ── Exit ────────────────────────────────────────────────────────────
if [ "$EXIT_CODE" -eq 2 ]; then
  echo "::warning::mcplint found findings exceeding the threshold"
elif [ "$EXIT_CODE" -eq 1 ]; then
  echo "::error::mcplint encountered an operational error"
fi

exit "$EXIT_CODE"
