#!/usr/bin/env bash
set -uo pipefail

# All values are passed via environment variables from action.yml
HEADER="${COMMENT_HEADER:-mcplint scan results}"
MODE="${COMMENT_MODE:-scan}"
EXIT_CODE="${COMMENT_EXIT_CODE:-0}"
MARKER="<!-- mcplint-action-report -->"

# Build comment body
BODY="${MARKER}
## ${HEADER}
"

if [ "$MODE" = "scan" ]; then
  FINDINGS="${COMMENT_FINDINGS:-unknown}"
  CRITICAL="${COMMENT_CRITICAL:-unknown}"
  HIGH="${COMMENT_HIGH:-unknown}"

  BODY+="
| Metric | Count |
|--------|-------|
| Total findings | ${FINDINGS} |
| Critical | ${CRITICAL} |
| High | ${HIGH} |
"
  if [ "$EXIT_CODE" = "0" ]; then
    BODY+="
**No findings above threshold. Looking good!**"
  elif [ "$EXIT_CODE" = "2" ]; then
    BODY+="
**Findings detected above threshold. Please review.**"
  else
    BODY+="
**Scan encountered an error. Check the workflow logs.**"
  fi

elif [ "$MODE" = "diff" ]; then
  NEW="${COMMENT_NEW:-unknown}"
  RESOLVED="${COMMENT_RESOLVED:-unknown}"
  TOTAL="${COMMENT_FINDINGS:-unknown}"

  BODY+="
| Metric | Count |
|--------|-------|
| New findings | ${NEW} |
| Resolved findings | ${RESOLVED} |
| Current total | ${TOTAL} |
"
  if [ "$EXIT_CODE" = "0" ]; then
    BODY+="
**No new findings since baseline. Safe to merge.**"
  elif [ "$EXIT_CODE" = "2" ]; then
    BODY+="
**New findings detected. Please review before merging.**"
  else
    BODY+="
**Diff encountered an error. Check the workflow logs.**"
  fi
fi

# Upsert: find existing comment with marker, update or create
EXISTING_COMMENT_ID=$(gh api "repos/${REPO}/issues/${PR_NUMBER}/comments" \
  --jq ".[] | select(.body | startswith(\"${MARKER}\")) | .id" 2>/dev/null | head -1)

if [ -n "$EXISTING_COMMENT_ID" ]; then
  gh api "repos/${REPO}/issues/comments/${EXISTING_COMMENT_ID}" \
    --method PATCH \
    --field body="$BODY" > /dev/null 2>&1
  echo "Updated existing PR comment #${EXISTING_COMMENT_ID}"
else
  gh api "repos/${REPO}/issues/${PR_NUMBER}/comments" \
    --method POST \
    --field body="$BODY" > /dev/null 2>&1
  echo "Posted new PR comment"
fi
