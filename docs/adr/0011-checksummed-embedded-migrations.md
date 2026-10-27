# ADR-0011: Embedded, checksummed, forward-only migrations

- Status: Accepted
- Date: 2026-10-27

## Decision
SQL migrations are embedded in the binary (`go:embed`), numbered
(`0001_name.sql`), applied in order, each in its own transaction, and recorded
in `schema_migrations` with a SHA-256 checksum. On startup:
- an applied migration whose checksum differs from the embedded file aborts
  startup;
- a database newer than the binary (unknown applied versions) aborts startup;
- a failing migration rolls back and aborts startup.

Down-migrations are not supported; rollback is restoring the pre-upgrade DB
snapshot (ADR-0013/M18).

## Consequences
Schema history is tamper-evident and deterministic. Upgrades require the
snapshot mechanism for rollback.
