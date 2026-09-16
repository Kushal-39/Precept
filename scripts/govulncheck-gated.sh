#!/usr/bin/env bash
# Filtered govulncheck gate: passes only when every reachable
# (symbol-level) finding is listed in the ignore file.
set -euo pipefail

IGNORE_FILE="${1:-.govulncheck-ignore}"
if [ ! -f "$IGNORE_FILE" ]; then
	echo "error: ignore file not found: $IGNORE_FILE" >&2
	exit 1
fi

output=$(mktemp)
trap 'rm -f "$output"' EXIT

code=0
govulncheck -json ./... >"$output" 2>/dev/null || code=$?
if [ "$code" -ne 0 ] && [ "$code" -ne 3 ]; then
	echo "error: govulncheck failed with exit code $code" >&2
	exit 1
fi

reachable=$(jq -r 'select(.finding != null and (.finding.trace | length > 0) and ([.finding.trace[] | select(.function != null and .function != "")] | length > 0)) | .finding.osv' "$output" | sort -u)

count=0
unignored=0
for id in $reachable; do
	count=$((count + 1))
	if grep -qxF "$id" "$IGNORE_FILE"; then
		continue
	fi
	module=$(jq -r --arg id "$id" 'select(.finding != null and .finding.osv == $id) | .finding.trace[0].module // empty' "$output" | head -n 1)
	echo "error: reachable vulnerability $id (${module:-unknown module}) is not in $IGNORE_FILE" >&2
	unignored=1
done

if [ "$unignored" -ne 0 ]; then
	exit 1
fi
echo "$count reachable vulnerabilities; all accepted ($IGNORE_FILE)"
