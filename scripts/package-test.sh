#!/usr/bin/env bash
# Installs, repairs, upgrades, rolls back and removes the real packages on a
# disposable host (CI runner, root) — M18, AT-F15-01..04, AT-F17-01..04.
#   scripts/package-test.sh RELEASES_DIR PUBKEY OLD NEW BROKEN
# RELEASES_DIR holds one signed release directory per version.
set -euo pipefail
REL=$1
PUB=$2
OLD=$3
NEW=$4
BROKEN=$5
API=http://127.0.0.1:8470/api/v1
ORIGIN=http://localhost:8470
JAR=$(mktemp)
fail() { echo "FAIL: $*" >&2; journalctl -u kernhaven-core --no-pager -n 50 >&2 || true; exit 1; }
step() { echo; echo "=== $*"; }

host_state() {
  {
    sha256sum /etc/ssh/sshd_config /etc/ssh/ssh_config 2>/dev/null || true
    find /etc/ssh -type f -exec sha256sum {} + 2>/dev/null | sort
    iptables-save 2>/dev/null | grep -v '^#' | grep -iv docker || true
    nft list ruleset 2>/dev/null | grep -iv docker || true
    dpkg-query -W -f='${Package} ${Version}\n' | grep -v '^kernhaven ' | sort
  } > "$1"
}

wait_ready() {
  for _ in $(seq 60); do
    curl -fsS "$API/health/ready" >/dev/null 2>&1 && return 0
    sleep 2
  done
  fail "the Core did not become ready"
}

version() { kernhaven-core version | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])'; }

api() { # method path [json]
  local csrf
  csrf=$(cat "$JAR.csrf" 2>/dev/null || true)
  curl -fsS -b "$JAR" -c "$JAR" -X "$1" -H "Origin: $ORIGIN" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' ${3:+--data "$3"} "$API$2"
}

login() { # user password
  rm -f "$JAR" "$JAR.csrf"
  api POST /auth/login "{\"username\":\"$1\",\"password\":\"$2\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])' > "$JAR.csrf"
}

step "baseline of the host"
host_state /tmp/before.txt

step "install $OLD with pre-flight checks (AT-F17-01)"
"$REL/$OLD/install.sh" --pubkey "$PUB" --allow-unsupported "$REL/$OLD"
[ "$(version)" = "$OLD" ] || fail "version $(version), want $OLD"
# The test reaches the Core directly over http.
sed -i 's|^public_origin = .*|public_origin = "http://localhost:8470"|' /etc/kernhaven/core.toml
systemctl restart kernhaven-core
wait_ready
systemctl is-active kernhaven-core kernhaven-agent kernhaven-storage kernhaven-files kernhaven-monitor

step "first-run setup and data"
token=$(journalctl -u kernhaven-core --no-pager | sed -n 's/.*"setup_token":"\([^"]*\)".*/\1/p' | tail -1)
[ -n "$token" ] || fail "no setup token in the journal"
rm -f "$JAR"
curl -fsS -c "$JAR" -H "Origin: $ORIGIN" -H 'Content-Type: application/json' --data "{\"token\":\"$token\",\"username\":\"owner\",\"password\":\"Package-Test-Passw0rd!\"}" "$API/setup" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])' > "$JAR.csrf"
api POST /users '{"username":"alice","role":"viewer","password":"Alice-Test-Passw0rd!"}' >/dev/null
login alice 'Alice-Test-Passw0rd!'

step "a second run of the installer repairs and changes nothing else (AT-F17-02)"
rm -f /etc/kernhaven/agent-grant.pub
systemctl stop kernhaven-agent
"$REL/$OLD/install.sh" --pubkey "$PUB" --allow-unsupported "$REL/$OLD"
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
kernhaven-upgrade apply "$REL/$NEW"
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
kernhaven-upgrade rollback
[ "$(version)" = "$OLD" ] || fail "version $(version), want $OLD"
wait_ready
login alice 'Alice-Test-Passw0rd!'
kernhaven-upgrade status

step "no side effects on firewall, SSH or other packages (AT-F17-04)"
host_state /tmp/after.txt
diff -u /tmp/before.txt /tmp/after.txt || fail "the host changed"

step "uninstall keeps apps running and data in place (AT-F17-03)"
docker run -d --name kh-pkgtest-app --label io.kernhaven.managed=true alpine:3 sleep 600 >/dev/null
/usr/share/kernhaven/uninstall.sh --yes
[ "$(docker inspect -f '{{.State.Running}}' kh-pkgtest-app)" = true ] || fail "an app was stopped"
! systemctl list-unit-files 'kernhaven*' --no-legend | grep -q . || fail "units left"
! getent passwd kernhaven >/dev/null || fail "user left"
[ -s /var/lib/kernhaven/kernhaven.db ] || fail "data removed without being asked"
[ ! -e /etc/kernhaven ] || fail "configuration left"
docker rm -f kh-pkgtest-app >/dev/null

step "reinstall onto the kept data, then remove everything on request"
"$REL/$OLD/install.sh" --pubkey "$PUB" --allow-unsupported "$REL/$OLD"
wait_ready
/usr/share/kernhaven/uninstall.sh --yes --remove-data
[ ! -e /var/lib/kernhaven ] || fail "data kept although its removal was requested"
echo
echo "package test passed"
