#!/usr/bin/env bash
# Kernhaven installer (M18, AT-F17-01/02/04): checks the host, verifies the
# signed release and installs the package. Safe to run again: it repairs a
# partial installation. It does not change the firewall, SSH or packages
# other than Kernhaven and its dependencies.
#
#   install.sh [--pubkey owner.pub] [--allow-unsupported] RELEASE_DIR
set -euo pipefail

pubkey=""
unsupported=0
while [ $# -gt 1 ]; do
  case "$1" in
    --pubkey) pubkey=$2; shift 2 ;;
    --allow-unsupported) unsupported=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
dir=${1:?usage: install.sh [--pubkey FILE] [--allow-unsupported] RELEASE_DIR}
fail() { echo "install.sh: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"

# ---- pre-flight ----
. /etc/os-release
if [ "${ID:-}" = debian ] && [ "${VERSION_ID:-}" = 13 ]; then
  :
elif [ "$unsupported" = 1 ]; then
  echo "warning: ${PRETTY_NAME:-unknown system} is not a supported platform (Debian 13); continuing as requested"
else
  fail "${PRETTY_NAME:-this system} is not supported (Debian 13 required; --allow-unsupported for development hosts)"
fi
arch=$(dpkg --print-architecture)
case "$arch" in amd64|arm64) ;; *) fail "architecture $arch is not supported" ;; esac
[ -d /run/systemd/system ] || fail "systemd is not running"
installed=$(dpkg-query -W -f='${Status}' kernhaven 2>/dev/null || true)
if [ "$installed" != "install ok installed" ]; then
  # Ports of a fresh installation must be free (a repair keeps its own).
  for p in 8470 80 443; do
    if ss -Hltn "sport = :$p" | grep -q .; then
      if [ "$p" = 8470 ]; then fail "port $p is in use"; fi
      echo "warning: port $p is in use; the reverse proxy cannot start until it is free"
    fi
  done
fi
avail=$(df --output=avail -k /var/lib | tail -1)
[ "$avail" -ge 2097152 ] || fail "less than 2 GiB free in /var/lib"
if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
  echo "warning: Docker is not available; container and app features stay disabled until it is installed"
fi
command -v minisign >/dev/null || fail "minisign is needed to verify the release (apt-get install minisign)"

# ---- verify ----
keys=()
if [ -n "$pubkey" ]; then keys+=("$pubkey"); fi
for k in /etc/kernhaven/release-keys/*.pub; do
  if [ -e "$k" ]; then keys+=("$k"); fi
done
[ ${#keys[@]} -gt 0 ] || fail "no release key: pass --pubkey with the owner's minisign public key"
ok=0
for k in "${keys[@]}"; do
  if minisign -Vq -p "$k" -m "$dir/SHA256SUMS" -x "$dir/SHA256SUMS.minisig"; then ok=1; break; fi
done
[ "$ok" = 1 ] || fail "the release signature is not valid for any trusted key"
deb=$(sed -n "s/^[0-9a-f]\{64\}  \(kernhaven_[0-9A-Za-z.~+-]*_${arch}\.deb\)$/\1/p" "$dir/SHA256SUMS" | head -1)
[ -n "$deb" ] || fail "the release has no package for $arch"
(cd "$dir" && grep "  $deb\$" SHA256SUMS | sha256sum -c --quiet -) || fail "$deb does not match the signed checksum"
echo "verified $deb"

# ---- install ----
if [ -n "$pubkey" ]; then
  install -d -m 0755 /etc/kernhaven/release-keys
  install -m 0644 "$pubkey" "/etc/kernhaven/release-keys/$(basename "$pubkey")"
fi
export DEBIAN_FRONTEND=noninteractive
if [ "$installed" = "install ok installed" ] && [ "$(dpkg-query -W -f='${Version}' kernhaven)" = "$(dpkg-deb -f "$dir/$deb" Version)" ]; then
  apt-get install -y --no-install-recommends --reinstall "$(realpath "$dir/$deb")"
else
  apt-get install -y --no-install-recommends "$(realpath "$dir/$deb")"
fi
kernhaven-upgrade cache-package "$dir/$deb"
echo "done. Upgrades: kernhaven-upgrade apply RELEASE_DIR; removal: /usr/share/kernhaven/uninstall.sh"
