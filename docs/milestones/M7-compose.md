# M7 — Docker Compose: Import, Validation, Editing, Deployment

Status: In progress
Depends on: M6
Acceptance tests: AT-F03-01 … AT-F03-06
Threats addressed: TH-30 (stacks), TH-31 (bind mounts), TH-33 (per-stack networks), TH-42 (SSRF on URL import), TH-51 (secrets at rest)

## Goal

Run multi-container applications ("stacks") from Compose files: import them
(paste, upload, HTTPS URL), see line-accurate errors and policy findings while
editing, keep every change as a numbered revision, deploy a revision as a
journaled job, and roll back automatically when a deployment fails.

## Supported Compose subset (ADR-0018)

Kernhaven parses Compose YAML itself (`gopkg.in/yaml.v3`, line numbers kept)
and maps each service to the typed `ContainerSpec` of M6. **Keys that are not
supported are errors, not silently ignored** — deny by default.

| Level | Supported |
|---|---|
| Top level | `name`, `services`, `volumes`, `networks`, `x-*` extensions (ignored), `version` (ignored) |
| Service | `image` (required), `command`, `entrypoint`, `environment` (map or list), `user`, `working_dir`, `ports` (short syntax), `volumes` (short and long syntax: volume, bind, tmpfs), `networks` (one network per service), `network_mode`, `restart`, `labels`, `depends_on` (order), `healthcheck`, `privileged`, `cap_add`, `cap_drop`, `devices`, `security_opt`, `pid`, `ipc`, `read_only`, `mem_limit`, `cpus`, `deploy.resources.limits.{memory,cpus}`, `container_name` (must equal the generated name if set) |
| Volumes | named, `external: true`, `labels` |
| Networks | bridge, `internal`, `external: true`, `labels` |

Not supported in 1.0 (error with explanation): `build`, `env_file`, `secrets`,
`configs`, `extends`, `profiles`, multiple networks per service, port ranges.
YAML anchors, aliases and `<<` merge keys are supported with a node budget
against expansion bombs.

**Variables:** `${NAME}`, `${NAME:-default}`, `${NAME-default}` and `$$`
are interpolated from the stack's variables. Unknown variables without a
default are errors.

**Naming:** containers are `<stack>-<service>`, named volumes and networks
`<stack>_<name>` unless `external`. Everything a stack creates carries the
reserved labels `io.kernhaven.stack`, `io.kernhaven.stack.service`,
`io.kernhaven.stack.revision`, set by the agent.

## Secrets (ADR-0019)

Stack variables are stored encrypted (AES-256-GCM, key in
`<data_dir>/secrets.key`, 0600). Variables marked secret are never returned by
the API after they are set; the UI shows "set" and allows replacing them.
Rendered values reach the agent only inside the create request.

## Revisions

Each save creates revision n+1 with the Compose text, author, comment and the
owner-approved policy exceptions for that revision. Revisions are immutable;
"restore" creates a new revision from an old one.

## Deployment (job `stacks.deploy`)

| Step | Run | Compensate (rollback) |
|---|---|---|
| 1 resolve | interpolate, parse, policy-check every service (permanent failure on violation) | — |
| 2 pull | pull every image (records digests) | — |
| 3 networks & volumes | create missing ones; record what was created | remove networks created here (volumes are never removed by a rollback) |
| 4 replace | stop and remove the containers of the currently deployed revision | recreate and start the previous revision's containers |
| 5 create | create and start services in `depends_on` order | remove the containers created here |
| 6 verify | all services running (and healthy when a healthcheck exists) within 60 s | — |

Failure in any step after 3 rolls back to the previous revision, which keeps
running. Named volumes keep their data across deployments and rollbacks;
the container layer of replaced containers is not preserved (documented).

`stacks.down` stops and removes the stack's containers and networks; volumes
only on explicit request.

## URL import (TH-42)

HTTPS only; at most 256 KiB; 10 s timeout; at most 3 redirects. Every
connection — including after redirects and DNS resolution — is checked by the
dialer: loopback, private, link-local, unique-local, multicast, unspecified and
CGNAT addresses are refused. The content is returned for review; it is not
stored or deployed automatically.

## API (permissions)

Reading stacks: `containers.read`. Creating, revising, variables, deploy,
down, delete, import, validate: `containers.manage`. Exceptions:
`policy.exceptions`.

## Acceptance criteria → tests

| AT | Tests |
|---|---|
| AT-F03-01 | URL import: https only, size limit, private/loopback targets refused (incl. redirect and DNS), success against a TLS test server; paste/upload via API and E2E |
| AT-F03-02 | Parser tests: line/column of unknown keys, type errors, missing image, unsupported features, interpolation errors, anchors/merge, alias bomb |
| AT-F03-03 | Policy per service in validation output; deploy job fails permanently on violation; owner exceptions per revision |
| AT-F03-04 | Revisions increment, immutable, restore; E2E edit and redeploy |
| AT-F03-05 | Deploy, update to a new revision, teardown; failing deployment (exiting service) rolls back to the previous revision; process kill during deploy recovers (job journal) |
| AT-F03-06 | Secret values encrypted at rest (no plaintext in the DB file), never returned by the API, used in rendered containers |

## Known limitations

- Only the documented Compose subset is accepted; `build`, `env_file`,
  `secrets`, `configs`, `extends`, `profiles`, several networks per service
  and port ranges are rejected with an explanation.
- Updates replace containers (old revision stopped, new one started): there
  is a short downtime and no rolling or blue/green deployment.
- A rollback restores the previous revision's containers and networks, not
  data. Writes a failing revision made to volumes stay; volumes are never
  removed by a rollback.
- Secret variables are encrypted at rest and never returned by the API, but
  they are passed to containers as environment variables. Anyone with Docker
  access on the host (`docker inspect`) or inside the container can read them.
- `secrets.key` lies next to the database. Encryption protects a leaked
  database file or backup, not a compromised host; backups (M16) must handle
  the key separately, and losing it makes stored variables unreadable.
- Deployment with separate system users and rootful Docker is verified only
  as far as CI runners allow; full verification needs the Debian 13 VMs (B-2).

## Verification evidence (2026-10-27, branch `m7-compose`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds) | `khv01-dev` | Passed |
| Compose parser: realistic file (anchors, merge keys, interpolation, ports, mounts, healthcheck, limits, depends_on order), 24 error cases with exact line numbers, stack name and size limits, alias bomb, interpolation forms, shell splitting, external resources | `khv01-dev` | Passed |
| Secretbox: encrypt/decrypt, associated data prevents swapping, tampering detected, key file 0600 enforced, nonce not reused | `khv01-dev` | Passed |
| Core through a real agent server: validation with line numbers and per-service policy; owner-only exceptions (admin may carry, not add); secrets write-only and absent from `kernhaven.db` and its WAL; secret rendered into the container; deploy, update, failing deployment rolled back to the previous revision; revisions immutable (trigger); down keeps volumes; delete refused while deployed; URL import blocks loopback/private/link-local/CGNAT/http/userinfo, enforces size and redirect rules | `khv01-dev` | Passed (3 consecutive runs) |
| Contract: 58 operations, routes ↔ OpenAPI ↔ enforced permissions; RBAC matrix | `khv01-dev` | Passed |
| **Live on real rootless Docker 29.9.2** with the real `kernhaven-core` and `kernhaven-agent` binaries: create + deploy revision 1 (healthcheck, `depends_on: service_healthy`), update to revision 2, revision 3 with an exiting service fails in verification and **rolls back to revision 2** (both services running, app healthy), down removes containers and network and keeps the volume | `khv01-dev` | Passed |
| CI full suite incl. browser E2E on the runner Docker (editor errors with line numbers, create + deploy with variable, new revision, failing revision rolled back, take down) | GitHub Actions | Passed (run 40565761279, commit after the .gitignore fix) |

Found while testing: a test fake (`memDocker.Start`) had not received the
"exits immediately" behaviour because `gofmt` had reformatted the function;
the product code was correct.

The first full CI run (40564118825) failed in every Go job: the
`*secret*` safety pattern in `.gitignore` had also matched
`internal/platform/secretbox` and ADR-0019, so they were never
committed while the local tree was complete. Fixed with exact
exceptions; `scripts/check.sh` now fails when source or doc files are
ignored, and the fix was verified from a clean clone before pushing.
