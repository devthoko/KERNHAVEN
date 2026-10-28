# M8 — App Store and App Lifecycle

Status: Implemented (CI 40574613677); merge pending owner review
Depends on: M7
Acceptance tests: AT-F04-01 … AT-F04-04, AT-F05-01 … AT-F05-04
Threats addressed: TH-40 (malicious catalog entries), TH-41 (image changes on
update), TH-42 (SSRF on catalog URLs), TH-51 (app secrets at rest)

## Goal

Install, update and remove applications from signed catalogs. An app is a
Compose stack (M7) that Kernhaven manages on the user's behalf: the catalog
supplies the Compose file and a configuration form, Kernhaven fills in the
values, generates secrets, shows which privileges the app needs, deploys it as
a journaled job and rolls it back — data included — when an update fails.

## Catalogs (ADR-0020)

A catalog is a JSON document signed with Ed25519. Kernhaven never trusts a
catalog because of where it came from, only because its signature verifies
against the trust key the owner configured for that source.

```json
{
  "format": "kernhaven-catalog/v1",
  "key_id": "3f1c…(16 hex)",
  "payload": "<base64 of the catalog JSON>",
  "signature": "<base64 Ed25519 signature>"
}
```

The signature covers `kernhaven-catalog/v1\n` followed by the exact payload
bytes (domain separation). The payload contains `name`, a monotonically
increasing `serial`, an `expires` timestamp and the `apps`.

| Check at sync | Rejects |
|---|---|
| Envelope format and size (≤ 4 MiB fetched, server body limit for uploads) | other formats, oversized documents |
| Signature against the source's configured key | unsigned, tampered, signed with another key |
| `serial` ≥ last accepted serial; equal serial only with identical payload | rollback to an older catalog |
| `expires` in the future and at most 400 days ahead | freeze attacks (replaying an old catalog forever) |
| Strict JSON (unknown fields are errors), every app's fields, Compose file (parsed with placeholder values) and declared exceptions | malformed entries — the whole catalog is rejected, nothing is half-applied |

A source has a name, an optional HTTPS URL and its public key. URL sources are
fetched through the SSRF-safe fetcher of M7 (public HTTPS only, checked after
DNS resolution and on redirects). A signed catalog can also be uploaded to a
source, for air-gapped hosts; the same checks apply. Only owners manage
sources (AT-F04-03). Kernhaven ships without a default source; the
`kernhaven-catalog` tool creates keys and signs catalogs.

### App entry

| Field | Meaning |
|---|---|
| `id` | `^[a-z0-9][a-z0-9-]{0,30}$`, unique in the catalog |
| `name`, `version`, `summary`, `description`, `categories`, `homepage` | display (plain text; `homepage` must be https) |
| `compose` | Compose file (M7 subset) with `${FIELD}` placeholders |
| `fields` | configuration form: `name` (variable), `label`, `description`, `type` (`text`, `password`, `number`, `boolean`, `select`), `default`, `required`, `options` (select), `min`/`max` (number), `generate` (`password` or `hex32`) |
| `web` | optional `{service, port}`: the service and container port of the web UI |
| `exceptions` | policy exceptions the app needs, each with a reason |

## Policy disclosure (AT-F04-04)

Before installing, the app page shows what the app will be allowed to do,
computed by Kernhaven from the Compose file — not taken from the catalog's
own description: published ports, bind mounts of host paths, named volumes,
added capabilities, devices, privileged mode, host networking, unpinned images,
and every policy violation together with whether the catalog declares an
exception for it. Apps that need exceptions can only be installed by an owner
who explicitly approves them; the approval is audited and stored on the stack
revision like any M7 exception.

## Lifecycle

An installed app is a stack with `managed_by = 'app'`. The stack pages show it
read-only; changes go through the app pages so that the app's recorded
version and configuration stay consistent.

| Action | What happens |
|---|---|
| Install (AT-F05-01) | Validate values against the fields; generate missing generated values; `password` fields become secret stack variables (encrypted, write-only); create the managed stack with revision 1; queue the deploy job, which pulls images, creates networks and volumes, starts services in dependency order and waits until they are running and healthy. |
| Update (AT-F05-02) | Offered when the catalog version differs from the installed one. The update page shows the version change, changed images and the new disclosure. A new stack revision is deployed with a **pre-update snapshot**: after the old containers are removed, every volume of the stack is copied to a snapshot volume. If any later step fails — including the health check — the job removes the new containers, **restores the volumes from the snapshots** and starts the previous revision again. |
| Remove (AT-F05-03) | Containers and networks are removed and the app disappears. Keeping data keeps the volumes (and snapshots); deleting data removes them and requires the user to re-enter their password. |
| Interrupted operations (AT-F05-04) | Every step is journaled (M3). After a crash of the Core the job resumes at the interrupted step; steps are idempotent (copying clears the target first, creating replaces the container of the same name). After a crash of the agent the step fails and is retried, or the job compensates. |

The installed version is not stored separately: it is the version recorded for
the stack revision that is currently deployed. A failed update therefore can
never leave a wrong version on record.

## Volume snapshots (ADR-0021)

The agent gets one new allow-listed operation, `volumes.copy {source, target,
stack}`. Both volumes must carry the stack's label (the target is created with
it if missing), so the Core cannot copy data between stacks or out of
unmanaged volumes. The agent clears the target and copies with a helper
container that it builds itself — the Core supplies only volume names:

- image `busybox:1.37.0` pinned by its multi-arch digest (agent setting
  `helper_image`), command fixed in the agent;
- no network, read-only root file system, `no-new-privileges`, all
  capabilities dropped except `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`
  (needed to preserve ownership and modes), memory limit 256 MiB;
- source mounted read-only.

The operation returns the helper's name at once; the Core polls until it
exits, so long copies do not hold the agent connection open, and a restarted
job simply starts the copy again.

## API

| Route | Permission |
|---|---|
| `GET /api/v1/catalog/sources` | `apps.read` |
| `POST /api/v1/catalog/sources`, `DELETE …/{id}`, `POST …/{id}/sync`, `POST …/{id}/upload` | `catalog.manage` (owner) |
| `GET /api/v1/catalog/apps`, `GET /api/v1/catalog/apps/{source}/{app}` | `apps.read` |
| `GET /api/v1/apps`, `GET /api/v1/apps/{name}` | `apps.read` |
| `POST /api/v1/apps`, `POST /api/v1/apps/{name}/update`, `POST /api/v1/apps/{name}/remove` | `apps.manage` (owner, admin) |

`apps.read` is granted to every role. Approving exceptions additionally needs
`policy.exceptions` (owner).

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F04-01 | `internal/catalog`: valid, unsigned, tampered payload, tampered signature, wrong key, rollback, equal serial with other content, expired, too far ahead, unknown fields, invalid app; `TestCatalogSources` (URL sync through the fetcher, upload, error recorded on the source) |
| AT-F04-02 | `TestCatalogBrowseAndDisclosure` (search, category filter, detail); E2E store page |
| AT-F04-03 | `TestCatalogSources` (two sources with their own keys; admin forbidden); RBAC matrix |
| AT-F04-04 | `TestCatalogBrowseAndDisclosure` (ports, volumes, capabilities, exceptions, never-allowed Docker socket); E2E disclosure before install |
| AT-F05-01 | `TestAppInstall` (form validation, generated secrets encrypted and write-only, exceptions need the owner, health check); E2E |
| AT-F05-02 | `TestAppUpdateRollback` (snapshot taken, failing health check restores volume content and previous revision, installed version unchanged); agent `volumes.copy` tests incl. real Docker; E2E |
| AT-F05-03 | `TestAppRemove` (keep vs delete data, re-authentication, audit); E2E |
| AT-F05-04 | `TestAppInterrupted` (Core stopped during install and update, new instance resumes or rolls back); live SIGKILL test with real binaries |

## Publishing a catalog

```sh
kernhaven-catalog keygen -key catalog.key          # once; keep catalog.key offline
kernhaven-catalog sign -key catalog.key -in catalog.json -out signed.json
kernhaven-catalog verify -pub <trust key> -in signed.json
```

`catalog.json` is the payload (`name`, `serial`, `expires`, `apps`). `sign`
validates every entry with the same rules as the Core before signing and
refuses keys readable by other users. Publish `signed.json` at an HTTPS URL or
upload it on the sources page. Increase `serial` for every new catalog.

## Known limitations

- **Reverse proxy route (AT-F05-01) is not implemented**: it needs the reverse
  proxy of M12. Until then the app page links to the host port that publishes
  the app's web service.
- Catalogs are not required to pin images by digest. Unpinned images are
  flagged in the disclosure and the update page lists changed image
  references, but a tag replaced upstream is only noticed at pull time (TH-41).
- Snapshots are file-level copies of named volumes of the stack. External
  volumes and bind-mounted host folders are not copied. An update needs free
  space for one copy; there is one snapshot per volume, replaced by the next
  update and removed only with "delete data".
- The app stops during an update (containers are removed before the
  snapshot); there is no zero-downtime update.
- Re-authentication for deleting data uses the password; passkey step-up
  follows in M11.
- Kernhaven ships without a default catalog source; owners add the sources
  they trust. There is no automatic periodic sync yet.
- Rootful Docker with separate service users is verified only as far as CI
  runners allow (B-2). Local browser tests need Playwright's system libraries
  (B-5); they run in CI.

## Verification evidence (2026-10-27, branch `m8-apps`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds for amd64/arm64, guard against ignored source files) | `khv01-dev` | Passed |
| `internal/catalog`: valid catalog, 13 rejection cases (unsigned, tampered payload/signature, other key, rollback, same serial with other content, expired, too far ahead, unknown field, oversized), 17 invalid entries, field checks, 20 s fuzzing of `Open`; `kernhaven-catalog` keygen/sign/verify incl. refusing a world-readable key | `khv01-dev` | Passed |
| Agent `volumes.copy`: helper confinement (image, no network, read-only root, capabilities, mounts, fixed command), 9 rejections incl. cross-stack and unmanaged volumes; allow-list pinned | `khv01-dev` | Passed |
| Agent `volumes.copy` on **real rootless Docker 29.9.2**: snapshot, change, restore — content, dot files, owner `65534:65534` and mode `750` restored; cross-stack copy refused | `khv01-dev` | Passed |
| Core through a real agent server (`TestCatalogSources`, `TestCatalogBrowseAndDisclosure`, `TestAppInstall`, `TestAppUpdateRollback`, `TestAppRemove`, `TestAppInterrupted`), contract (71 operations ↔ OpenAPI ↔ permissions), RBAC matrix | `khv01-dev` | Passed (3 consecutive runs) |
| Mutation check: disabling the snapshot restore and loosening the disclosure each make the tests fail | `khv01-dev` | Passed |
| **Live with real binaries and rootless Docker**: signed catalog via `kernhaven-catalog`; install; update whose service migrates the data and crashes → rolled back, data restored, revision 1 running; **SIGKILL of the Core during the snapshot step** of an update with 200 MB of data → job resumed after restart and succeeded, data intact; remove with wrong password refused, with password removes app, volumes and snapshot | `khv01-dev` | Passed |
| Manual UI check through the browser (store, disclosure with exception, update review and update, remove dialog, 375 px width without horizontal overflow) | `khv01-dev` demo instance | Passed |
| CI full suite incl. browser E2E (source with trust key, tampered upload rejected, signed upload, search and category, disclosure, install, update, remove with password, viewer restrictions, 360/768/1440 px) | GitHub Actions | Passed (run 40574613677) |
