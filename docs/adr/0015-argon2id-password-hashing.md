# ADR-0015: Argon2id password hashing via golang.org/x/crypto

- Status: Accepted
- Date: 2026-10-27

## Context
Passwords must be stored with a memory-hard function (ASVS V6/V11). The Go
standard library has no Argon2 implementation.

## Decision
Use `golang.org/x/crypto/argon2` (Argon2id) with m=64 MiB, t=2, p=2, 16-byte
salt and 32-byte key, encoded in PHC string format. At most two hashes run
concurrently. Stored parameters are bounds-checked before verification.

## Consequences
- New dependency `golang.org/x/crypto` (Go project, maintained by the Go team).
- `govulncheck` reports GO-2026-5932 for the unmaintained
  `golang.org/x/crypto/openpgp` package in the same module. Kernhaven does not
  import that package; govulncheck confirms the code is not affected. Re-check
  on every dependency update.
- Login costs ~100–300 ms CPU on small arm64 boards, which also slows online
  guessing.
