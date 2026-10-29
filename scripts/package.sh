#!/usr/bin/env bash
# Builds dist/kernhaven_<version>_<arch>.deb from bin/ (scripts/build.sh with
# the same VERSION) — M18, ADR-0032.
#   scripts/package.sh 1.0.0 amd64 [bin-dir] [out-dir]
set -euo pipefail
VERSION=${1:?version}
ARCH=${2:?architecture (amd64 or arm64)}
BIN=${3:-bin}
OUT=${4:-dist}
cd "$(dirname "$0")/.."
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+-][0-9A-Za-z.~+-]+)?$ ]] || { echo "invalid version $VERSION" >&2; exit 2; }
[[ $ARCH == amd64 || $ARCH == arm64 ]] || { echo "invalid architecture $ARCH" >&2; exit 2; }
umask 022
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
chmod 0755 "$root"
install -d "$root/DEBIAN" "$root/usr/bin" "$root/lib/systemd/system" "$root/usr/share/kernhaven/config" \
  "$root/usr/share/kernhaven/release-keys" "$root/usr/share/doc/kernhaven"
for b in kernhaven-core kernhaven-agent kernhaven-upgrade; do
  install -m 0755 "$BIN/$b-linux-$ARCH" "$root/usr/bin/$b"
done
install -m 0644 deploy/systemd/*.service "$root/lib/systemd/system/"
install -m 0644 deploy/config/* "$root/usr/share/kernhaven/config/"
for k in deploy/release-keys/*.pub; do
  if [ -e "$k" ]; then install -m 0644 "$k" "$root/usr/share/kernhaven/release-keys/"; fi
done
install -m 0755 packaging/install.sh packaging/uninstall.sh "$root/usr/share/kernhaven/"
install -m 0755 packaging/debian/postinst packaging/debian/prerm packaging/debian/postrm "$root/DEBIAN/"
size=$(du -sk "$root" | cut -f1)
cat > "$root/DEBIAN/control" <<CTL
Package: kernhaven
Version: $VERSION
Architecture: $ARCH
Maintainer: Kernhaven <noreply@users.noreply.github.com>
Installed-Size: $size
Depends: systemd, passwd
Recommends: docker.io | docker-ce, caddy (>= 2.6)
Section: admin
Priority: optional
Homepage: https://github.com/devthoko/KERNHAVEN
Description: secure self-hosting management for Linux homelabs
 Kernhaven manages containers, apps, storage, files, the reverse proxy,
 certificates, monitoring, alerts and encrypted backups from a web UI,
 without giving the web application root access to the host.
CTL
mkdir -p "$OUT"
dpkg-deb --root-owner-group -Zxz --build "$root" "$OUT/kernhaven_${VERSION}_${ARCH}.deb" >/dev/null
echo "$OUT/kernhaven_${VERSION}_${ARCH}.deb"
