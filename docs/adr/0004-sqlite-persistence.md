# ADR-0004: SQLite for single-node persistence

- Status: Accepted
- Date: 2026-10-27

## Context
Single node, low administration effort, reliable backups required.

## Decision
SQLite in WAL mode with `foreign_keys=ON`, `busy_timeout`, and
`synchronous=FULL`. One database file per process (`kernhaven.db` for Core).
Online backups via SQLite's backup mechanism (`VACUUM INTO`).

## Consequences
No separate DB server. Write concurrency is limited to one writer, which is
adequate for the workload; long writes must be avoided in request paths.
