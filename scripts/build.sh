#!/usr/bin/env bash
# Builds the web UI and the Core for linux/amd64 and linux/arm64 into bin/.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
# Reproducible builds (M19): the build time is the commit time, also for the
# package's file times (dpkg-deb clamps to SOURCE_DATE_EPOCH).
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}
DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
PKG=github.com/devthoko/KERNHAVEN/internal/platform/version

(cd web && npm ci --ignore-scripts --no-audit --no-fund && npm run build)
for arch in amd64 arm64; do
  for cmd in kernhaven-core kernhaven-agent kernhaven-upgrade; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
      -ldflags "-s -w -X $PKG.Version=$VERSION -X $PKG.Commit=$COMMIT -X $PKG.BuildDate=$DATE" \
      -o "bin/$cmd-linux-$arch" "./cmd/$cmd"
  done
done
ls -l bin/
