# ADR-0009: Pure-Go SQLite driver

- Status: Accepted
- Date: 2026-10-27

## Context
Releases target amd64 and arm64. A cgo SQLite driver complicates
cross-compilation and reproducible builds.

## Decision
Use `modernc.org/sqlite` (pure Go translation of SQLite) via `database/sql`.

## Alternatives
- `mattn/go-sqlite3`: mature, but requires cgo and a C toolchain per target.

## Consequences
`CGO_ENABLED=0` static builds for both architectures. Slightly lower
performance than the C build, acceptable for the workload. The driver version
determines the embedded SQLite version; it is tracked for SQLite CVEs.
