#!/usr/bin/env bash
# Runs go test with the given arguments. In GitHub Actions, failing tests are
# also reported as annotations, which are readable without repository admin
# rights (job logs are not).
set -uo pipefail
log=$(mktemp)
go test "$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ] && [ -n "${GITHUB_ACTIONS:-}" ]; then
  # Each failing test with the lines that follow it (bounded).
  grep -n -E -- '--- FAIL|^FAIL|panic:|race detected' "$log" | head -20 | while IFS=: read -r line _; do
    msg=$(sed -n "$((line > 15 ? line - 15 : 1)),$((line + 25))p" "$log" | sed 's/%/%25/g' | awk 1 ORS='%0A')
    echo "::error title=go test failure (log line $line)::$msg"
  done
fi
exit "$status"
