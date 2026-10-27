#!/usr/bin/env bash
# End-to-end browser tests against a real kernhaven-core with a fresh database.
# Requires Go, Node.js and Playwright's Chromium (npx playwright install chromium).
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${KH_E2E_PORT:-18471}
WORK=$(mktemp -d)
cleanup() {
  if [ -n "${CORE_PID:-}" ]; then kill -TERM "$CORE_PID" 2>/dev/null || true; wait "$CORE_PID" 2>/dev/null || true; fi
  if [ "${KH_E2E_KEEP:-}" = "1" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

(cd web && npm run build)
CGO_ENABLED=0 go build -trimpath -o "$WORK/kernhaven-core" ./cmd/kernhaven-core

mkdir -m 700 "$WORK/data"
cat > "$WORK/core.toml" <<CFG
[server]
listen = "127.0.0.1:$PORT"
public_origin = "http://localhost:$PORT"
[storage]
data_dir = "$WORK/data"
CFG

"$WORK/kernhaven-core" -config "$WORK/core.toml" 2> "$WORK/core.log" &
CORE_PID=$!
for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$PORT/api/v1/health/ready" >/dev/null && break
  sleep 0.1
done
TOKEN=$(grep -o '"setup_token":"[^"]*"' "$WORK/core.log" | head -1 | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then echo "no setup token in log"; cat "$WORK/core.log"; exit 1; fi

status=0
(cd web && KH_BASE_URL="http://localhost:$PORT" KH_SETUP_TOKEN="$TOKEN" npx playwright test) || status=$?
if [ $status -ne 0 ]; then
  echo "--- core log"; tail -50 "$WORK/core.log"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    # Annotations are readable without repository admin rights.
    msg=$(tail -15 "$WORK/core.log" | sed "s/%/%25/g" | awk 1 ORS="%0A")
    echo "::error title=kernhaven-core log (tail)::$msg"
  fi
fi
exit $status
