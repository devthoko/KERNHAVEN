# ADR-0016: Hash-chained audit log in SQLite

- Status: Accepted
- Date: 2026-10-27

## Context
Audit records must be tamper-evident (AT-F10-02, TH-52) without external
infrastructure.

## Decision
Store audit events in `audit_events` with append-only triggers. Each record
contains the predecessor's hash and its own SHA-256 over the predecessor hash
and a canonical JSON encoding. State changes append their record inside the
same transaction as the change. A verification endpoint recomputes the chain.

## Consequences
- Modification or deletion of any record except the newest is detected.
- Truncating the newest records with raw database access is not detectable
  from the chain alone; mitigated later by exporting chain heads to an external
  sink (M17).
- Writes are serialized by SQLite's write lock (`_txlock=immediate`).
