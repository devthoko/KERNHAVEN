# Kernhaven Test Strategy

Acceptance criteria and their IDs are defined in the
[Feature Matrix](../product/FEATURE-MATRIX.md). This document defines how they
are tested and where.

## 1. Test levels

| Level | Scope | Tooling | Runs on |
|---|---|---|---|
| Unit | Single package, pure logic, failure paths | `go test`, Vitest (web) | Every push (CI) |
| Component | One module with real SQLite, real HTTP server in-process | `go test` with `httptest`, temp dirs | Every push (CI) |
| Contract | Routes ↔ OpenAPI spec ↔ permission registry | `go test` | Every push (CI) |
| Integration | Core + agent + real Docker Engine, Caddy, systemd | `go test -tags integration` in a Debian 13 VM | Every PR touching agent/containers (from M4), nightly |
| End-to-end | Browser against a full installation | Playwright | Nightly, release candidates (from M5) |
| Security | SAST, dependency CVEs, fuzzing, DAST, ASVS checklist | `govulncheck`, `staticcheck`, `go test -fuzz`, OWASP ZAP | CI (SAST/CVE), nightly (fuzz/DAST), release (ASVS) |
| Resilience | Crash, kill -9, power loss, disk full, interrupted upgrade | Fault-injection harness + VM reset | Nightly from M3, release-blocking |
| Upgrade/rollback | N-1 → N with real data; forced failure → rollback | VM snapshots | Release-blocking from M18 |
| Backup/restore | Backup, wipe, restore on fresh host, verify app health | VM pair | Release-blocking from M16 |

## 2. Conventions

- Tests that verify an acceptance criterion reference its ID in the test name
  or a comment (`// AT-F00-02`), so coverage of the matrix can be checked by
  `scripts/at-coverage.sh` (added when the first integration tests land).
- Every meaningful change includes tests of error and failure paths, not only
  the happy path (CLAUDE.md).
- No test may be skipped, weakened or marked flaky to make CI pass. A flaky test
  is a defect with an issue and an owner.
- Integration tests use real services. Mocks are allowed only in unit tests and
  never count as acceptance evidence.
- The race detector (`-race`) runs in CI for all Go tests.

## 3. Integration environment

| Environment | OS | Arch | Purpose |
|---|---|---|---|
| `ci-unit` | GitHub-hosted Ubuntu runner | amd64, arm64 | Unit/component/contract tests, builds |
| `ci-debian` | `debian:13` container on GitHub runners | amd64, arm64 | Unit/component tests on the primary OS userland |
| `int-debian-amd64` | Debian 13 VM with Docker Engine + Caddy + systemd | amd64 | Integration, resilience, upgrade, backup |
| `int-debian-arm64` | Debian 13 VM or arm64 board | arm64 | Same as above |
| `dev` | `khv01-dev` (Ubuntu 26.04) | amd64 | Development only; not release evidence |

The VM-based integration environments do not exist yet. They are a
prerequisite for M4 (see [Milestones](../milestones/MILESTONES.md), blocker B-2).

## 4. Acceptance test execution per milestone

A milestone is accepted only when its acceptance tests are automated, run in
the environments listed for them and pass. The milestone design document
(`docs/milestones/Mx-*.md`) lists the exact commands to reproduce the
verification.

## 5. Release-blocking suites (1.0)

1. All AT-* in the feature matrix on `int-debian-amd64` and `int-debian-arm64`
2. Backup → wipe → restore on a fresh host (AT-F14-05)
3. Upgrade N-1 → N and forced rollback (AT-F15-02..04)
4. Kill/power-loss resilience during jobs, installs, upgrades (AT-F18-02, AT-F18-04, AT-F05-04)
5. Security: ASVS 5.0 L2 checklist with evidence, ZAP baseline without high findings, `govulncheck` clean, fuzzers run ≥ 1 h each without findings
