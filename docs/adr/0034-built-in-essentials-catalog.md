# ADR-0034: A built-in "Kernhaven Essentials" catalog

- Status: Proposed (pending owner review)
- Date: 2026-10-30

## Context
Kernhaven shipped without any catalog source (M8, ADR-0020): a new
installation showed an empty app store until the owner found a catalog,
obtained its publisher's key and added it. The owner asked for an app store
that works from the first start, like other homelab platforms. ADR-0020
trusts catalogs through a per-source Ed25519 key; a shipped catalog would
need a signing key whose ceremony does not exist yet (blocker B-3).

## Decision
- **Trust anchor is the release.** The Essentials catalog is part of the
  Core binary (`internal/core/apps/essentials`, embedded at build time). The
  release signature (minisign over SHA256SUMS, ADR-0013/0032) and the
  reproducible build cover it, so it needs no key of its own. It has no URL,
  no trust key and no expiry: it is exactly as current as the installed
  Kernhaven version and changes only with an upgrade or rollback.
- **Same checks as any catalog.** `catalog.OpenBuiltin` applies every content
  check of `catalog.Open` (strict JSON, fields, Compose subset, policy
  validation) except signature and expiry. The disclosure and the install,
  update and removal flows are unchanged.
- **Stricter rules for its content**, enforced by a unit test: every image
  pinned by digest, no policy exceptions, a memory limit per service, web
  UI, homepage and description present, ports above 1023 and default ports
  that do not collide between apps.
- **Seeding.** On every start the Core creates the source if it is missing
  and replaces its apps when the embedded payload's SHA-256 differs (audited
  as `catalog.sync` by `system`). An older payload after a Kernhaven rollback
  is accepted, because the binary is the anchor.
- **The owner decides.** Sync, upload and removal of the built-in source
  answer 409. Any source, the built-in one included, can be turned off with
  `PUT /catalog/sources/{id}/enabled` (`catalog.manage`, step-up, audited);
  a disabled source offers no apps, no details and no updates, and a restart
  never turns it back on. Installed apps keep running.
- **First content (11 apps, one container each):** Vaultwarden, Jellyfin,
  Uptime Kuma, Syncthing, Navidrome, Audiobookshelf, Forgejo, Stirling PDF,
  Mealie, Home Assistant (without host network), FreshRSS. Rootless image
  variants and an explicit `user` where the project offers them.

## Consequences
- The store is useful on the first start; nothing has to be trusted beyond
  the Kernhaven release itself.
- Compromise of the release pipeline could inject apps — it could inject
  code into the Core anyway; the container policy and disclosure still apply.
- App updates in Essentials arrive with Kernhaven releases, not on their own
  schedule; image digests must be refreshed for each release.
- Multi-container apps (for example Paperless-ngx with Redis, Immich,
  Nextcloud with a database) are not included: Kernhaven does not give
  services the Compose-style network alias of their service name yet, so a
  service cannot address another one without knowing the stack name.
- Data lives in named volumes. Media apps (Jellyfin, Navidrome,
  Audiobookshelf) cannot read host folders without a bind mount, which needs
  an owner-approved exception — out of scope for Essentials.
