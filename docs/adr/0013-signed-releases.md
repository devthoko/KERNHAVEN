# ADR-0013: Signed and verifiable releases

- Status: Proposed (decision due in M18)
- Date: 2026-10-27

## Context
Upgrades replace privileged binaries; a compromised release channel would
compromise every installation.

## Proposal
- Reproducible `CGO_ENABLED=0` builds with `-trimpath`.
- Release artifacts signed with an offline-held Ed25519 key (minisign format);
  public key shipped with the installer and pinned in the upgrade module.
- SLSA build provenance generated in CI and published with each release.
- Upgrade refuses artifacts with missing or invalid signatures (AT-F15-01).

## Open questions
Key ceremony and rotation; whether to additionally publish Sigstore
signatures.
