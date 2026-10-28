#!/usr/bin/env bash
# End-to-end browser tests against a real kernhaven-core with a fresh database.
# Requires Go, Node.js and Playwright's Chromium (npx playwright install chromium).
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${KH_E2E_PORT:-18471}
WORK=$(mktemp -d)
cleanup() {
  if [ -n "${AGENT_PID:-}" ]; then kill -TERM "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "${STORAGE_PID:-}" ]; then kill -TERM "$STORAGE_PID" 2>/dev/null || true; wait "$STORAGE_PID" 2>/dev/null || true; fi
  if [ -n "${FILES_PID:-}" ]; then kill -TERM "$FILES_PID" 2>/dev/null || true; wait "$FILES_PID" 2>/dev/null || true; fi
  for pid in "${PROXY_PID:-}" "${CADDY_PID:-}" "${SITE_PID:-}"; do
    if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
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
storage_socket = "$WORK/storage.sock"
files_socket = "$WORK/files.sock"
CFG
# Reverse proxy (M12) with a real Caddy: KH_E2E_CADDY=/path/to/caddy.
if [ -n "${KH_E2E_CADDY:-}" ]; then
  sed -i "/^\[agent\]/a proxy_socket = \"$WORK/proxy.sock\"" "$WORK/core.toml"
fi

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

# Storage service (M9) without root: inventory of the real disks, no changes.
# Its mount root doubles as the file manager root "data" (M10).
mkdir -p "$WORK/mnt"
cat > "$WORK/storage.toml" <<CFG
role = "storage"
socket = "$WORK/storage.sock"
allowed_uids = [$(id -u)]
grant_public_key = "$WORK/data/agent-grant.pub"
mount_root = "$WORK/mnt"
CFG
"$WORK/kernhaven-agent" -config "$WORK/storage.toml" 2> "$WORK/storage.log" &
STORAGE_PID=$!
# File service (M10) without root, on the same mount root.
sed -e 's/^role = "storage"/role = "files"/' -e 's/storage.sock/files.sock/' "$WORK/storage.toml" > "$WORK/files.toml"
"$WORK/kernhaven-agent" -config "$WORK/files.toml" 2> "$WORK/files.log" &
FILES_PID=$!

if [ -n "${KH_E2E_CADDY:-}" ]; then
  # A plain upstream for the test route, Caddy with a private admin socket and
  # high ports, and the proxy service in front of it.
  mkdir -p "$WORK/site" "$WORK/caddy"
  echo "hello from upstream" > "$WORK/site/index.html"
  python3 -m http.server 18490 --bind 127.0.0.1 --directory "$WORK/site" >/dev/null 2>&1 &
  SITE_PID=$!
  printf '{"admin":{"listen":"unix/%s/caddy/admin.sock","origins":["kernhaven-proxy"]}}' "$WORK" > "$WORK/caddy/boot.json"
  HOME="$WORK/caddy" XDG_DATA_HOME="$WORK/caddy/data" XDG_CONFIG_HOME="$WORK/caddy/config" \
    "$KH_E2E_CADDY" run --config "$WORK/caddy/boot.json" --resume > "$WORK/caddy.log" 2>&1 &
  CADDY_PID=$!
  cat > "$WORK/proxy.toml" <<CFG
role = "proxy"
socket = "$WORK/proxy.sock"
allowed_uids = [$(id -u)]
grant_public_key = "$WORK/data/agent-grant.pub"
caddy_admin_socket = "$WORK/caddy/admin.sock"
core_address = "127.0.0.1:$PORT"
http_port = 18480
https_port = 18443
CFG
  "$WORK/kernhaven-agent" -config "$WORK/proxy.toml" 2> "$WORK/proxy.log" &
  PROXY_PID=$!
  export KH_E2E_PROXY=1
  # An own CA and a certificate for custom.kh.test (M13 upload test).
  C="$WORK/certs"; mkdir -p "$C"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$C/ca.key" -out "$C/ca.crt" -days 30 \
    -subj "/CN=Kernhaven E2E Own CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$C/leaf.key" -out "$C/leaf.csr" -subj "/CN=custom.kh.test" 2>/dev/null
  printf 'subjectAltName=DNS:custom.kh.test\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > "$C/ext.cnf"
  openssl x509 -req -in "$C/leaf.csr" -CA "$C/ca.crt" -CAkey "$C/ca.key" -CAcreateserial -days 20 -out "$C/leaf.crt" -extfile "$C/ext.cnf" 2>/dev/null
  cat "$C/leaf.crt" "$C/ca.crt" > "$C/chain.pem"
  export KH_E2E_CERT_DIR="$C"
fi

TOKEN=$(grep -o '"setup_token":"[^"]*"' "$WORK/core.log" | head -1 | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then echo "no setup token in log"; cat "$WORK/core.log"; exit 1; fi

status=0
(cd web && KH_BASE_URL="http://localhost:$PORT" KH_SETUP_TOKEN="$TOKEN" npx playwright test) || status=$?
if [ $status -ne 0 ]; then
  echo "--- core log"; tail -50 "$WORK/core.log"
  if [ -f "$WORK/caddy.log" ]; then echo "--- caddy log"; tail -20 "$WORK/caddy.log"; echo "--- proxy log"; tail -20 "$WORK/proxy.log"; fi
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    # Annotations are readable without repository admin rights.
    msg=$(tail -15 "$WORK/core.log" | sed "s/%/%25/g" | awk 1 ORS="%0A")
    echo "::error title=kernhaven-core log (tail)::$msg"
  fi
fi
exit $status
