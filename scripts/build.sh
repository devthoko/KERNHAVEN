#!/usr/bin/env bash
# Builds the web UI and the Core for linux/amd64 and linux/arm64 into bin/.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PKG=github.com/devthoko/KERNHAVEN/internal/platform/version

(cd web && npm ci --ignore-scripts --no-audit --no-fund && npm run build)
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X $PKG.Version=$VERSION -X $PKG.Commit=$COMMIT -X $PKG.BuildDate=$DATE" \
    -o "bin/kernhaven-core-linux-$arch" ./cmd/kernhaven-core
done
ls -l bin/
