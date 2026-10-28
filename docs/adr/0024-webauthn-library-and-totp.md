# ADR-0024: go-webauthn for passkeys, TOTP in the standard library

- Status: Accepted
- Date: 2026-10-28

## Context
Passkeys (M11) need WebAuthn verification: CBOR attestation objects, COSE
keys in several algorithms, client data, RP ID hashes, flags and counters.
Getting any detail wrong breaks the security of the login. TOTP (RFC 6238)
is a few lines of HMAC.

## Decision
Use `github.com/go-webauthn/webauthn` (v0.18.2, released 2026-09-19) for
WebAuthn ceremonies: the widely used Go implementation, BSD-licensed,
maintained, and covered by govulncheck in CI. Kernhaven asks for resident
keys and requires user verification, accepts "none" attestation (no device
allow-listing in 1.0) and stores credentials as JSON next to the user.
Ceremony session data is kept server-side in the challenge table, never in
the browser. TOTP is implemented with `crypto/hmac` and tested against the
RFC 6238 vectors.

## Consequences
- 15 new indirect modules (CBOR, JWT for FIDO metadata, TPM attestation
  parsing). They are pinned in go.sum and scanned like all dependencies.
- No attestation trust store: any FIDO2 authenticator with user verification
  is accepted.
- WebAuthn needs a secure context; `public_origin` must be HTTPS or
  `localhost`. The RP ID is the origin's host name.
