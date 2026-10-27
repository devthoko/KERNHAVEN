#!/usr/bin/env bash
# End-to-end browser tests against a real kernhaven-core with a fresh database.
# Requires Go, Node.js and Playwright's Chromium (npx playwright install chromium).
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${KH_E2E_PORT:-18471}
WORK=$(mktemp -d)
cleanup() {
  if [ -n "${AGENT_PID:-}" ]; then kill -TERM "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "${DOCKER_SOCK:-}" ] && command -v docker >/dev/null; then
    DOCKER_HOST="unix://$DOCKER_SOCK" docker rm -f e2e-web >/dev/null 2>&1 || true
    DOCKER_HOST="unix://$DOCKER_SOCK" docker volume rm e2e-vol >/dev/null 2>&1 || true
    DOCKER_HOST="unix://$DOCKER_SOCK" docker network rm e2e-net >/dev/null 2>&1 || true
    DOCKER_HOST="unix://$DOCKER_SOCK" docker rm -f e2e-stack-app e2e-stack-worker >/dev/null 2>&1 || true
    DOCKER_HOST="unix://$DOCKER_SOCK" docker volume rm e2e-stack_data >/dev/null 2>&1 || true
    DOCKER_HOST="unix://$DOCKER_SOCK" docker network rm e2e-stack_default >/dev/null 2>&1 || true
    DOCKER_HOST="unix://$DOCKER_SOCK" docker rm -f e2e-app-app >/dev/null 2>&1 || true
    DOCKER_HOST="unix://$DOCKER_SOCK" docker volume rm e2e-app_data e2e-app_data.snapshot >/dev/null 2>&1 || true
    DOCKER_HOST="unix://$DOCKER_SOCK" docker network rm e2e-app_default >/dev/null 2>&1 || true
  fi
  if [ -n "${CORE_PID:-}" ]; then kill -TERM "$CORE_PID" 2>/dev/null || true; wait "$CORE_PID" 2>/dev/null || true; fi
  if [ "${KH_E2E_KEEP:-}" = "1" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

(cd web && npm run build)
CGO_ENABLED=0 go build -trimpath -o "$WORK/kernhaven-core" ./cmd/kernhaven-core
CGO_ENABLED=0 go build -trimpath -o "$WORK/kernhaven-agent" ./cmd/kernhaven-agent

# Docker for the container tests: KH_E2E_DOCKER_SOCKET, else /var/run/docker.sock.
DOCKER_SOCK=${KH_E2E_DOCKER_SOCKET:-/var/run/docker.sock}
if [ ! -S "$DOCKER_SOCK" ]; then
  if [ "${KH_E2E_REQUIRE_DOCKER:-}" = "1" ]; then echo "Docker socket $DOCKER_SOCK not found"; exit 1; fi
  DOCKER_SOCK=""
fi

mkdir -m 700 "$WORK/data"
cat > "$WORK/core.toml" <<CFG
[server]
listen = "127.0.0.1:$PORT"
public_origin = "http://localhost:$PORT"
[storage]
data_dir = "$WORK/data"
[agent]
socket = "$WORK/agent.sock"
CFG

"$WORK/kernhaven-core" -config "$WORK/core.toml" 2> "$WORK/core.log" &
CORE_PID=$!
for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$PORT/api/v1/health/ready" >/dev/null && break
  sleep 0.1
done
if [ -n "$DOCKER_SOCK" ]; then
  cat > "$WORK/agent.toml" <<CFG
socket = "$WORK/agent.sock"
allowed_uids = [$(id -u)]
grant_public_key = "$WORK/data/agent-grant.pub"
docker_socket = "$DOCKER_SOCK"
CFG
  "$WORK/kernhaven-agent" -config "$WORK/agent.toml" 2> "$WORK/agent.log" &
  AGENT_PID=$!
  export KH_E2E_DOCKER=1
fi

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
