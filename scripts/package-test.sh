#!/usr/bin/env bash
# Installs, repairs, upgrades, rolls back and removes the real packages on a
# disposable host (CI runner, root) — M18, AT-F15-01..04, AT-F17-01..04.
#   scripts/package-test.sh RELEASES_DIR PUBKEY OLD NEW BROKEN
# RELEASES_DIR holds one signed release directory per version.
set -Eeuo pipefail
REL=$1
PUB=$2
OLD=$3
NEW=$4
BROKEN=$5
API=http://127.0.0.1:8470/api/v1
ORIGIN=http://localhost:8470
JAR=$(mktemp)
STEP=start
exec 3>&1 # annotations reach the log even from redirected blocks
fail() {
  echo "::error::package test, step '$STEP': $*" >&3
  journalctl -u kernhaven-core --no-pager -n 50 >&2 || true
  exit 1
}
trap 'echo "::error::package test, step '"'"'$STEP'"'"', line $LINENO: $BASH_COMMAND" >&3' ERR
step() { STEP=$*; echo; echo "=== $*"; }

# run COMMAND...: shows the output; a failure is reported with its last lines.
run() {
  local out
  out=$(mktemp)
  if ! "$@" > "$out" 2>&1; then
    cat "$out"
    fail "$(basename "$1") failed: $(tail -6 "$out" | tr '\n' ' ')"
  fi
  cat "$out"
  rm -f "$out"
}

# host_state records what Kernhaven must not change: SSH configuration,
# firewall rules (without Docker's own chains) and installed packages.
host_state() {
  {
    if [ -d /etc/ssh ]; then (find /etc/ssh -type f -print0 | sort -z | xargs -0 -r sha256sum) || true; fi
    (iptables-save 2>/dev/null | grep -v '^#' | grep -iv docker) || true
    (nft list ruleset 2>/dev/null | grep -iv docker) || true
    dpkg-query -W -f='${Package} ${Version}\n' | grep -v '^kernhaven ' | sort
  } > "$1"
  [ -s "$1" ] || fail "could not record the host state"
}

wait_ready() {
  for _ in $(seq 60); do
    curl -fsS "$API/health/ready" >/dev/null 2>&1 && return 0
    sleep 2
  done
  fail "the Core did not become ready"
}

version() { kernhaven-core version | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])'; }

# http METHOD PATH [JSON]: the body on stdout; any status >= 400 fails with
# the status and the start of the body.
http() {
  local csrf code out
  csrf=$(cat "$JAR.csrf" 2>/dev/null || true)
  out=$(mktemp)
  code=$(curl -sS -o "$out" -w '%{http_code}' -b "$JAR" -c "$JAR" -X "$1" -H "Origin: $ORIGIN" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' ${3:+--data "$3"} "$API$2")
  if [ "$code" -ge 400 ]; then
    fail "HTTP $code for $1 $2: $(head -c 400 "$out" | tr '\n' ' ')"
  fi
  cat "$out"
  rm -f "$out"
}
api() { http "$@"; }

login() { # user password
  rm -f "$JAR" "$JAR.csrf"
  api POST /auth/login "{\"username\":\"$1\",\"password\":\"$2\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])' > "$JAR.csrf"
}

step "baseline of the host"
host_state /tmp/before.txt

step "install $OLD with pre-flight checks (AT-F17-01)"
run "$REL/$OLD/install.sh" --pubkey "$PUB" --allow-unsupported "$REL/$OLD"
[ "$(version)" = "$OLD" ] || fail "version $(version), want $OLD"
# The test reaches the Core directly over http.
sed -i 's|^public_origin = .*|public_origin = "http://localhost:8470"|' /etc/kernhaven/core.toml
systemctl restart kernhaven-core
wait_ready
systemctl is-active kernhaven-core kernhaven-agent kernhaven-storage kernhaven-files kernhaven-monitor

step "first-run setup and data"
token=$(journalctl -u kernhaven-core --no-pager | sed -n 's/.*"setup_token":"\([^"]*\)".*/\1/p' | tail -1)
[ -n "$token" ] || fail "no setup token in the journal"
rm -f "$JAR" "$JAR.csrf"
http POST /setup "{\"token\":\"$token\",\"username\":\"owner\",\"password\":\"Package-Test-Passw0rd!\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])' > "$JAR.csrf"
api POST /users '{"username":"alice","role":"viewer","password":"Alice-Test-Passw0rd!"}' >/dev/null
login alice 'Alice-Test-Passw0rd!'

step "a second run of the installer repairs and changes nothing else (AT-F17-02)"
rm -f /etc/kernhaven/agent-grant.pub
systemctl stop kernhaven-agent
run "$REL/$OLD/install.sh" --pubkey "$PUB" --allow-unsupported "$REL/$OLD"
[ -s /etc/kernhaven/agent-grant.pub ] || fail "grant key not repaired"
grep -q 'public_origin = "http://localhost:8470"' /etc/kernhaven/core.toml || fail "the administrator's configuration was replaced"
wait_ready
systemctl is-active kernhaven-agent
login alice 'Alice-Test-Passw0rd!'

step "unsigned and tampered releases are refused (AT-F15-01)"
bad=$(mktemp -d)
cp -r "$REL/$NEW/." "$bad/"
rm "$bad/SHA256SUMS.minisig"
if kernhaven-upgrade apply "$bad"; then fail "unsigned release accepted"; fi
cp "$REL/$NEW/SHA256SUMS.minisig" "$bad/"
printf 'x' >> "$bad/$(ls "$bad" | grep "\.deb$")"
if kernhaven-upgrade apply "$bad"; then fail "tampered package accepted"; fi
[ "$(version)" = "$OLD" ] || fail "a refused release changed the version"

step "upgrade $OLD → $NEW with the data (AT-F15-02, AT-F15-04)"
run kernhaven-upgrade apply "$REL/$NEW"
[ "$(version)" = "$NEW" ] || fail "version $(version), want $NEW"
ls /var/lib/kernhaven-upgrade/snapshots/*/kernhaven.db >/dev/null || fail "no snapshot"
login alice 'Alice-Test-Passw0rd!'
login owner 'Package-Test-Passw0rd!'
api GET /backup/repositories >/dev/null || fail "the new version's migrations did not run"

step "a version that does not become healthy is rolled back (AT-F15-03)"
set +e
kernhaven-upgrade apply --health-timeout 30s "$REL/$BROKEN"
code=$?
set -e
[ "$code" = 3 ] || fail "broken upgrade exited with $code, want 3 (rolled back)"
[ "$(version)" = "$NEW" ] || fail "version $(version) after the rollback, want $NEW"
wait_ready
login alice 'Alice-Test-Passw0rd!'

step "manual rollback to $OLD with its database (AT-F15-03)"
run kernhaven-upgrade rollback
[ "$(version)" = "$OLD" ] || fail "version $(version), want $OLD"
wait_ready
login alice 'Alice-Test-Passw0rd!'
kernhaven-upgrade status

step "no side effects on firewall, SSH or other packages (AT-F17-04)"
host_state /tmp/after.txt
diff -u /tmp/before.txt /tmp/after.txt || fail "the host changed"

step "uninstall keeps apps running and data in place (AT-F17-03)"
docker run -d --name kh-pkgtest-app --label io.kernhaven.managed=true alpine:3 sleep 600 >/dev/null
run /usr/share/kernhaven/uninstall.sh --yes
[ "$(docker inspect -f '{{.State.Running}}' kh-pkgtest-app)" = true ] || fail "an app was stopped"
! systemctl list-unit-files 'kernhaven*' --no-legend | grep -q . || fail "units left"
! getent passwd kernhaven >/dev/null || fail "user left"
[ -s /var/lib/kernhaven/kernhaven.db ] || fail "data removed without being asked"
[ ! -e /etc/kernhaven ] || fail "configuration left"
docker rm -f kh-pkgtest-app >/dev/null

step "reinstall onto the kept data, then remove everything on request"
run "$REL/$OLD/install.sh" --pubkey "$PUB" --allow-unsupported "$REL/$OLD"
wait_ready
run /usr/share/kernhaven/uninstall.sh --yes --remove-data
[ ! -e /var/lib/kernhaven ] || fail "data kept although its removal was requested"
echo
echo "package test passed"
