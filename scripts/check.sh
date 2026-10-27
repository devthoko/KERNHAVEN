#!/usr/bin/env bash
# Local equivalent of the CI change gate (G1). Usage: scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

STATICCHECK_VERSION=v0.8.2
GOVULNCHECK_VERSION=v1.9.0

echo "== gofmt"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then echo "$unformatted"; exit 1; fi

echo "== go mod verify"
go mod verify

echo "== go vet"
go vet ./...

echo "== staticcheck"
go run "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}" ./...

echo "== govulncheck"
go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...

echo "== tests"
if command -v gcc >/dev/null 2>&1; then
  go test -race -count=1 ./...
else
  echo "(no C toolchain: running without -race; CI runs with -race)"
  go test -count=1 ./...
fi

echo "== build linux/amd64 + linux/arm64"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "bin/kernhaven-core-linux-$arch" ./cmd/kernhaven-core
done

echo "== web"
if command -v npm >/dev/null 2>&1; then
  (cd web && npm ci --ignore-scripts --no-audit --no-fund >/dev/null && npm run typecheck && npm test && npm run build >/dev/null && npm audit --audit-level=high)
else
  echo "(npm not found: skipping web checks; CI runs them)"
fi
if grep -rn "dangerouslySetInnerHTML" web/src; then echo "dangerouslySetInnerHTML is forbidden (TH-04)"; exit 1; fi

echo "== secret scan"
if git grep -nE -- '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' -- . ':!scripts/check.sh' ':!.github/workflows/ci.yml'; then
  echo "private key material found"; exit 1
fi

echo "All checks passed."
