# ADR-0020: Ed25519-signed JSON catalogs with per-source trust keys

- Status: Accepted
- Date: 2026-10-27

## Context
App catalogs decide which Compose files Kernhaven deploys (TH-40, A7). A
catalog fetched over HTTPS is only as trustworthy as the server hosting it,
and a stale catalog can keep users on vulnerable versions. Full frameworks
(TUF) need several roles and metadata files that a homelab catalog maintainer
will not operate.

## Decision
A catalog is one JSON envelope with a base64 payload and a detached Ed25519
signature over `kernhaven-catalog/v1\n` + payload. Each source has exactly one
trust key configured by an owner. Kernhaven accepts a payload only if the
signature verifies, the serial does not go backwards, and `expires` lies in
the future but at most 400 days ahead. Catalogs are parsed strictly and
rejected as a whole if any entry is invalid. Signing uses the Go standard
library (`crypto/ed25519`); `kernhaven-catalog` creates keys and signs.

## Consequences
- Compromise of a hosting server alone cannot inject apps; compromise of a
  source's signing key can, limited to that source and still subject to the
  container policy and the disclosure shown before install.
- Key rotation means the owner replaces the source's key; there is no
  delegation or threshold signing (TUF remains an option for later).
- Unknown fields make a catalog invalid, so the format version must change
  when fields are added.
