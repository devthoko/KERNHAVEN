# ADR-0029: Own backup format: STREAM encryption with AES-256-GCM, Argon2id-wrapped key

- Status: Accepted
- Date: 2026-10-29

## Context
AT-F14-01 requires client-side authenticated encryption with the key never
stored unencrypted on the target; AT-F14-06 requires that damaged or
tampered backups are detected. Candidates were restic (a separate program
and repository format the Core would have to drive as a subprocess), age
(public-key format: anyone who knows the recipient can create a valid
object, so a target could forge snapshots without a separate MAC), and a
small format of our own built from standard library primitives.

## Decision
- A repository holds one plaintext file, `kernhaven-repo.json`: format
  version, random repository ID, Argon2id parameters (bounded when read) and
  the random 256-bit data key sealed with AES-256-GCM under
  `Argon2id(passphrase)`, the repository ID as associated data. The
  passphrase is never stored; the Core keeps the data key sealed with its
  own secret key (ADR-0019) so scheduled backups need no passphrase.
- Every object (database, secret key, `core.toml`, one per volume) is
  encrypted in the STREAM construction: a 32-byte random salt; a per-object
  key `HKDF-SHA256(data key, salt, "repository/snapshot/object identity")`;
  1 MiB segments sealed with AES-256-GCM; nonce = 88-bit segment counter and
  a last-segment flag. Truncation, reordering, moving an object to another
  place and appending data all fail authentication.
- A snapshot is a directory `snapshots/<time>-<random>/` with numbered
  objects and an encrypted manifest (written last) that lists each object's
  identity, plaintext size, stored size and SHA-256 of the ciphertext.
  Object names on the target reveal no stack or volume names.
- Verification reads and authenticates every object of every snapshot and
  compares the Core's record of snapshots with the target, so deleted
  snapshots are reported too.

## Consequences
- Every backup is a full copy; there is no deduplication or incremental
  backup in 1.0 (space and time grow with the data).
- The format is small enough to review; it uses only `crypto/aes`,
  `crypto/cipher`, `crypto/hkdf` and `golang.org/x/crypto/argon2`. It is
  not readable by other tools; the format is documented here and in
  `internal/core/backup/format.go`.
- Losing the passphrase and the Core's data directory together means the
  backups cannot be restored on another host.
