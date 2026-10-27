# ADR-0019: AES-256-GCM encryption for stack variables

- Status: Accepted
- Date: 2026-10-27

## Context
Stack variables often hold passwords and API tokens (TH-51). A copy of the
database file (backup, disk theft, misconfigured permissions) must not reveal
them.

## Decision
Encrypt every stack variable value with AES-256-GCM (Go standard library)
using a random 256-bit key stored in `<data_dir>/secrets.key` (mode 0600,
created on first use). The variable name and stack ID are authenticated as
associated data, so ciphertexts cannot be swapped between variables. Secret
values are write-only through the API.

## Consequences
- The key and the database live on the same host; this protects copies of the
  database, not a fully compromised host. Encrypted backups (M16) must include
  the key in their own encrypted envelope, otherwise restores cannot decrypt.
- Key rotation is not implemented in 1.0 (tracked).
