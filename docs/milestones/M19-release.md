# M19 — Release Hardening and 1.0 Verification

Status: Implemented (CI pending); the 1.0 gate is **not** passed — see
[1.0 gate status](../release/1.0-GATE.md)
Depends on: all milestones

## Scope

| Item | Result |
|---|---|
| Reproducible builds | `SOURCE_DATE_EPOCH` = commit time for the build date and the package's file times; CI job `reproducible` builds twice in different directories and compares binaries and packages |
| OWASP ZAP baseline | CI job `zap` scans the Core (first-run state) with ZAP 2.16.1 (pinned digest); medium and high findings fail unless `.zap/rules.tsv` accepts them with a reason (`scripts/zap-check.py`) |
| Threat model review | [§6](../security/THREAT-MODEL.md#6-review-for-10-m19-2026-10-29): proposals for the owner |
| ASVS 5.0 L2 | [chapter-level self-assessment](../security/ASVS-L2.md) |
| Documentation | [operator guide](../operations/OPERATIONS.md), [user guide](../user/USER-GUIDE.md), [security overview](../security/SECURITY.md), [release notes draft](../release/RELEASE-NOTES-1.0.0.md) |
| Gate status | [1.0 gate](../release/1.0-GATE.md) |

## Known limitations

- The ZAP scan covers what an unauthenticated visitor reaches (the SPA,
  public API endpoints, setup); an authenticated scan is not configured.
- The ASVS work is a self-assessment by chapter, not a requirement-level
  checklist or an independent review.
- Nothing in M19 replaces the Debian 13 VM runs (B-2) or the release key
  (B-3).

## Verification evidence (2026-10-29, branch `m19-release`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` | `khv01-dev` | Passed |
| CI full suite incl. `reproducible` and `zap` | GitHub Actions | pending |
