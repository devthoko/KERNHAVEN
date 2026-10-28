# Kernhaven 1.0 — Progress Checkpoint

Last updated: 2026-10-28. This file is the resumption point for development
sessions. It states only verified facts; see the linked evidence.

## Overall status

**Kernhaven 1.0 is not complete.** 2 of 20 milestones are merged (M0, M1). M2, M3 and M5 are implemented with
green CI on stacked branches awaiting owner review; M4 and M6–M13 are implemented on
stacked branches up to `m13-tls`. Monitoring, backup and installer
functionality do not exist yet.

| MS | Name | State | Evidence |
|---|---|---|---|
| M0 | Spec, repo, CI | Done | `main` @ `f0d2c71` |
| M1 | Core foundation | Done | [M1 evidence](milestones/M1-core-foundation.md#verification-evidence-2026-10-27), CI run 40506636168 |
| M2 | Identity, sessions, RBAC, audit | Implemented, CI green (run 40510127374); owner review pending | [M2 evidence](milestones/M2-identity.md#verification-evidence-2026-10-27-branch-m2-identity) |
| M3 | Persistent jobs, crash recovery | Implemented, CI green (run 40511595535); owner review pending | [M3 evidence](milestones/M3-jobs.md#verification-evidence-2026-10-27-branch-m3-jobs) |
| M5 | Web dashboard shell | Implemented, CI green incl. browser E2E (run 40519204275); owner review pending | [M5 design](milestones/M5-dashboard.md) |
| M4 | Host agent and privilege boundary | Implemented, CI green incl. real Docker on amd64/arm64 (run 40528475951); owner review pending | [M4 evidence](milestones/M4-agent.md#verification-evidence-2026-10-27-branch-m4-agent) |
| M6 | Container management (F02-01..06) | Implemented, full CI green incl. browser E2E on real Docker (run 40559956035); owner review pending | [M6 evidence](milestones/M6-containers.md#verification-evidence-2026-10-27-branch-m6-containers) |
| M7 | Compose stacks (F03) | Done on branch `m7-compose` (stacked on M6), CI 40565761279; merge pending owner review | [M7 evidence](milestones/M7-compose.md#verification-evidence-2026-10-27-branch-m7-compose) |
| M8 | App store and app lifecycle (F04, F05) | Done on branch `m8-apps` (stacked on M7), CI 40574613677, merge pending owner review; AT-F05-01 completed by the reverse proxy route in M12 | [M8 evidence](milestones/M8-apps.md#verification-evidence-2026-10-27-branch-m8-apps) |
| M9 | Storage and disk management (F06-01..03) | Done on branch `m9-storage` (stacked on M8), CI 40601258272, merge pending owner review | [M9 evidence](milestones/M9-storage.md#verification-evidence-2026-10-28-branch-m9-storage) |
| M10 | File manager (F07) | Done on branch `m10-files` (stacked on M9), CI 40701148605, merge pending owner review | [M10 evidence](milestones/M10-files.md#verification-evidence-2026-10-28-branch-m10-files) |
| M11 | Passkeys, MFA, step-up (F09-02..05) | Done on branch `m11-mfa` (stacked on M10), CI 40719877647, merge pending owner review | [M11 evidence](milestones/M11-mfa.md#verification-evidence-2026-10-28-branch-m11-mfa) |
| M12 | Network and reverse proxy (F11, completes AT-F05-01) | Done on branch `m12-network` (stacked on M11), CI 40761331938, merge pending owner review | [M12 evidence](milestones/M12-network.md#verification-evidence-2026-10-28-branch-m12-network) |
| M13 | TLS certificates (F12-01..03) | Implemented on branch `m13-tls` (stacked on M12), CI pending, merge pending owner review | [M13 evidence](milestones/M13-tls.md#verification-evidence-2026-10-28-branch-m13-tls) |
| M6b, M14–M19 | see [milestones](milestones/MILESTONES.md) | Not started | — |

## Environment blockers

| ID | Blocker | Blocks | Needed from owner |
|---|---|---|---|
| B-1 | Resolved: rootless Docker 29.9.2 for `dev01` on `khv01-dev` (root daemon disabled) | — | — |
| B-2 | No disposable Debian 13 VMs (amd64, arm64) | All privileged integration, upgrade, backup/restore and release tests (G3/G4) | Provide VMs or a hypervisor the dev server may use |
| B-3 | Release signing key ceremony undecided (ADR-0013) | M18, signed artifacts | Decision + offline key |
| B-5 | Playwright browsers need system libraries on the dev server (`sudo`) | Local E2E runs | None — E2E runs in CI; optional `sudo npx playwright install-deps chromium` |
| B-6 | No C toolchain on the dev server | Local `-race` runs | None — CI covers it; optional `sudo apt install gcc` |

## Next steps (in order)

1. Owner reviews and merges `m2-identity`, then `m3-jobs`.
2. Owner reviews `m5-dashboard`.
3. Owner reviews PR #1 (`m7-compose`, M2–M7), then `m8-apps`, `m9-storage`, `m10-files`, `m11-mfa`, `m12-network` and `m13-tls`. Next: M14 monitoring, or M6b streaming.
4. Release evidence for M4+ still requires B-2 (Debian 13 VMs, rootful Docker with separate service users).

## Development environment

- Dev server `khv01-dev` (Ubuntu 26.04, amd64), user `dev01`, repo `~/KERNHAVEN`.
- Go 1.27.3 in `~/.local/go`, Node.js 24.22.1 LTS in `~/.local/node` (checksum-verified downloads).
- Push via deploy key `~/.ssh/kernhaven_deploy` (host alias `github-kernhaven`).
- Run `scripts/check.sh` before every commit.
