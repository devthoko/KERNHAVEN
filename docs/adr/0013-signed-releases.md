# ADR-0013: Signed and verifiable releases

- Status: Accepted (M18); the key ceremony itself is open (B-3)
- Date: 2026-10-27, decided 2026-10-29

## Context
Upgrades replace privileged binaries; a compromised release channel would
compromise every installation.

## Decision
- Reproducible `CGO_ENABLED=0` builds with `-trimpath`.
- Each release directory holds the packages, `install.sh` and a
  `SHA256SUMS` file signed with **minisign** (Ed25519, prehashed) by a key
  the owner keeps offline. minisign is a small, standard tool the owner can
  run on an offline machine; Debian packages it.
- Hosts trust the public keys in `/etc/kernhaven/release-keys/*.pub`. The
  package installs the keys of `deploy/release-keys/`; `install.sh
  --pubkey` adds one on first installation.
- `install.sh` verifies with the minisign tool; `kernhaven-upgrade`
  verifies with its own implementation (`internal/release`), which CI checks
  against signatures made by the real minisign. Unsigned releases, unknown
  keys, changed checksum lists or comments and packages that differ from
  their checksum are refused before anything changes (AT-F15-01).
- No key exists until the owner holds the ceremony; until then every
  upgrade is refused (fail closed).

## Consequences
- The release workflow needs the owner to sign `SHA256SUMS` offline; CI
  produces the unsigned artifacts.
- Key rotation: add the new key to `deploy/release-keys/` in a release
  signed with the old key, then sign with the new key; remove the old one in
  a later release.
- SLSA provenance and Sigstore signatures are not part of 1.0.
