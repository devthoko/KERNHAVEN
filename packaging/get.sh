#!/usr/bin/env bash
# Kernhaven one-line installer:
#
#   curl -fsSL https://raw.githubusercontent.com/devthoko/KERNHAVEN/main/packaging/get.sh | sudo bash
#
# It downloads a release from GitHub, verifies SHA256SUMS against the
# release key pinned below and the files against SHA256SUMS, and only then
# runs the release's own install.sh (pre-flight checks, package
# installation). Nothing unverified is executed. ADR-0013, ADR-0032.
#
# Settings (environment):
#   KERNHAVEN_VERSION=1.0.0         a version instead of the latest release
#   KERNHAVEN_ALLOW_UNSUPPORTED=1   allow hosts other than Debian 13 (development)
#   KERNHAVEN_RELEASE_URL=...       download base instead of GitHub (mirrors; the
#                                   signature check against the pinned key still applies)

# The owner's minisign public key (the second line of the .pub file). It is
# empty until the release key exists (B-3); until then this script refuses
# to install. It must equal the key in deploy/release-keys/ (checked by
# scripts/check.sh).
RELEASE_PUBKEY=""

set -euo pipefail

# Everything runs from main(), called on the last line: a download cut
# short executes nothing.
main() {
  local repo="devthoko/KERNHAVEN"
  local base="${KERNHAVEN_RELEASE_URL:-https://github.com/$repo/releases/download}"
  local version="${KERNHAVEN_VERSION:-}"
  local arch tag deb

  fail() { echo "kernhaven: $*" >&2; exit 1; }
  [ "$(id -u)" = 0 ] || fail "run as root (… | sudo bash)"
  [ -n "$RELEASE_PUBKEY" ] || fail "no release has been signed yet (the release key does not exist); see https://github.com/$repo"
  command -v curl >/dev/null || fail "curl is needed"
  command -v dpkg >/dev/null || fail "this installer needs a Debian system"
  arch=$(dpkg --print-architecture)
  case "$arch" in amd64|arm64) ;; *) fail "architecture $arch is not supported" ;; esac
  if ! command -v minisign >/dev/null; then
    echo "kernhaven: installing minisign to verify the release"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends minisign >/dev/null
  fi

  if [ -z "$version" ]; then
    version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/^ *"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
    [ -n "$version" ] || fail "could not find the latest release; set KERNHAVEN_VERSION"
  fi
  [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+-][0-9A-Za-z.~+-]+)?$ ]] || fail "invalid version $version"
  tag="v$version"

  work=$(mktemp -d) # global: the EXIT trap runs after main returns
  trap 'rm -rf "$work"' EXIT
  chmod 0755 "$work"
  local proto="=https"
  case "$base" in http://127.0.0.1:*|http://localhost:*) proto="=http" ;; esac # local test mirrors only
  get() { curl -fsSL --proto "$proto" --proto-redir "$proto" --retry 3 -o "$work/$1" "$base/$tag/$1" || fail "download of $1 failed"; }

  echo "kernhaven: downloading release $version for $arch"
  get SHA256SUMS
  get SHA256SUMS.minisig
  printf 'untrusted comment: Kernhaven release key (pinned in get.sh)\n%s\n' "$RELEASE_PUBKEY" > "$work/release.pub"
  minisign -Vq -p "$work/release.pub" -m "$work/SHA256SUMS" -x "$work/SHA256SUMS.minisig" ||
    fail "the release signature is not valid for the pinned release key"

  deb="kernhaven_${version}_${arch}.deb"
  for f in "$deb" install.sh; do
    grep -q "^[0-9a-f]\{64\}  $f\$" "$work/SHA256SUMS" || fail "$f is not part of the signed release"
    get "$f"
    (cd "$work" && grep "^[0-9a-f]\{64\}  $f\$" SHA256SUMS | sha256sum -c --quiet -) || fail "$f does not match the signed checksum"
  done
  chmod 0755 "$work/install.sh"
  echo "kernhaven: release verified; running its installer"
  local opts=(--pubkey "$work/release.pub")
  if [ "${KERNHAVEN_ALLOW_UNSUPPORTED:-}" = 1 ]; then opts+=(--allow-unsupported); fi
  "$work/install.sh" "${opts[@]}" "$work"
}

main "$@"
