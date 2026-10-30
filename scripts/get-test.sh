#!/usr/bin/env bash
# Tests the one-line installer (packaging/get.sh) on a disposable host as
# root: piped from curl, against a local mirror of a signed release, with a
# copy of get.sh that pins the test key instead of the (missing) release key.
#   scripts/get-test.sh RELEASE_DIR VERSION PUBKEY
set -Eeuo pipefail
REL=$1
VERSION=$2
PUB=$3
PORT=18500
M=$(mktemp -d)
exec 3>&1
fail() { echo "::error::get.sh test: $*" >&3; exit 1; }
trap 'echo "::error::get.sh test, line $LINENO: $BASH_COMMAND" >&3' ERR

# Unchanged, get.sh refuses: no release key exists yet.
if out=$(bash packaging/get.sh 2>&1); then fail "get.sh without a pinned key installed something"; fi
echo "$out" | grep -q "release key does not exist" || fail "unexpected refusal: $out"

mkdir -p "$M/v$VERSION" "$M/v9.9.9"
cp "$REL"/SHA256SUMS "$REL"/SHA256SUMS.minisig "$REL"/install.sh "$REL"/kernhaven_"$VERSION"_*.deb "$M/v$VERSION/"
key=$(grep -v '^untrusted comment:' "$PUB" | head -1)
sed "s|^RELEASE_PUBKEY=\"\"|RELEASE_PUBKEY=\"$key\"|" packaging/get.sh > "$M/get.sh"
grep -q "^RELEASE_PUBKEY=\"$key\"" "$M/get.sh" || fail "test key not inserted"
# A release whose checksum list was changed after signing.
cp "$M/v$VERSION/"* "$M/v9.9.9/"
printf '%064d  extra.txt\n' 0 >> "$M/v9.9.9/SHA256SUMS"
(cd "$M" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
srv=$!
trap 'kill $srv 2>/dev/null || true' EXIT
for _ in $(seq 20); do curl -fsS "http://127.0.0.1:$PORT/get.sh" >/dev/null 2>&1 && break; sleep 0.5; done
env_vars=(KERNHAVEN_RELEASE_URL="http://127.0.0.1:$PORT" KERNHAVEN_ALLOW_UNSUPPORTED=1)

echo "=== a tampered release is refused before anything is installed"
if curl -fsSL "http://127.0.0.1:$PORT/get.sh" | env "${env_vars[@]}" KERNHAVEN_VERSION=9.9.9 bash; then fail "tampered release installed"; fi
! dpkg-query -W kernhaven >/dev/null 2>&1 || fail "kernhaven installed from a tampered release"

echo "=== the one-liner installs the signed release"
curl -fsSL "http://127.0.0.1:$PORT/get.sh" | env "${env_vars[@]}" KERNHAVEN_VERSION="$VERSION" bash
for _ in $(seq 60); do curl -fsS http://127.0.0.1:8470/api/v1/health/ready >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:8470/api/v1/health/ready >/dev/null || fail "the Core is not ready"
[ "$(dpkg-query -W -f='${Version}' kernhaven)" = "$VERSION" ] || fail "wrong version installed"
[ -s /etc/kernhaven/release-keys/release.pub ] || fail "the pinned key was not kept for upgrades"
ls /var/lib/kernhaven-upgrade/packages/kernhaven_"$VERSION"_*.deb >/dev/null || fail "package not cached for rollback"
/usr/share/kernhaven/uninstall.sh --yes --remove-data >/dev/null
echo "get.sh test passed"
