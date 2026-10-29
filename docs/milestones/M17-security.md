# M17 — Security Dashboard and Audit Search

Status: Implemented (CI 40950899401); merge pending owner review
Depends on: M2, M11, M12, M13, M14, M16
Acceptance tests: AT-F10-03, AT-F10-04
Threats addressed: TH-52 (tail truncation of the audit log, partially)

## Audit UI (AT-F10-03)

- The audit page filters by free-text search (action, actor, target,
  request ID, IP address and details; `%` and `_` are literal), action,
  actor, result and a date range, with paging.
- **Export** downloads the matching records as JSON Lines, oldest first,
  with `seq`, `prev_hash` and `hash`. Every export is itself recorded
  (`audit.export`, with the search in its details) before the records are
  written, so it appears in the file.
- `kernhaven-core audit-check NEW.jsonl [OLDER.jsonl]` runs anywhere
  without configuration. It checks every record's hash and the links between
  consecutive records; given an older *full* export, it checks that the
  newer one still contains the older one's last record unchanged. That
  detects the case the hash chain alone cannot (TH-52): someone with database
  access deleting the newest records, or deleting them and appending new
  ones.

## Security dashboard (AT-F10-04)

`GET /api/v1/security/overview` (`security.read`: owner, admin) and the
Security page list findings by severity, each linking to the page where it
is fixed:

| Area | Finding | Severity |
|---|---|---|
| MFA | An owner or admin without passkey or authenticator app | critical |
| MFA | Another user without a second factor although the policy requires one | warning |
| MFA | The policy does not require a second factor for owners or admins | warning |
| Exposure | A route without Kernhaven sign-in, LAN restriction or address list | warning |
| Policy | An approved exception in a deployed stack (`privileged`, `docker-socket`, host namespaces, devices, sensitive paths) | warning |
| Policy | Any other approved exception | info |
| Updates | An app whose catalog has a newer version | warning |
| Updates | An image used by a running container that was built more than 180 days ago | info |
| Sign-in | 10 or more failed sign-ins, or any lockout, in 24 hours | warning |
| Certificates | An uploaded or DNS-01 certificate in use that expires within 14 days / has expired | warning / critical |
| Audit | The chain fails verification | critical |
| Backup | No enabled plan, or no successful backup in 7 days | warning |

The page also shows MFA coverage per account, all routes with their
protection, all exceptions with reason and approver, failed sign-ins by
address and the latest ones, certificates and the backup state. It only
reads; nothing is changed from it.

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F10-03 | `TestSearchFilters` (search in every field, literal `%` and `_`, result, time range, combinations); `TestExportAndCheck` (JSON Lines with hashes; filtered exports checked record by record; changed actor or details, reordering, unknown fields and empty files refused; removed record shows as a gap; a newer export continues an older one; tail truncation and truncation plus new records detected although the chain itself verifies); `TestAuditSearchAndExport` (API parameters and errors, headers, export verifies, export audited, no access without session); `TestAuditCheckCommand`; E2E (search, result filter, download, every exported record matches) |
| AT-F10-04 | `TestSecurityOverview` (password-only owner and admin, policy, open route vs. route with sign-in, approved exception of a deployed stack, failed sign-in burst, missing backup plan, ordering by severity, tampered audit log shown as critical, operator refused); RBAC; E2E (findings and accounts, axe) |

## Known limitations

- Exports are manual; there is no automatic forwarding to a remote log
  server (syslog, Loki …). TH-52 stays partially mitigated: truncation is
  detected only against an export kept elsewhere.
- Image age is a hint: an old image is not necessarily vulnerable and a new
  one may be. There is no vulnerability scanner (CVE database) in 1.0.
- Certificates managed by Caddy itself (internal CA, ACME) renew
  automatically and are not listed; only uploaded and DNS-01 certificates.
- The dashboard is computed on request (all sources at once); it is
  refreshed every minute while open.

## Verification evidence (2026-10-29, branch `m17-security`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds) | `khv01-dev` | Passed |
| `internal/core/audit`, `TestSecurityOverview`, `TestAuditSearchAndExport`, `TestAuditCheckCommand`, contract, RBAC | `khv01-dev` | Passed |
| Mutation checks: LIKE wildcards not escaped, modified records accepted, rewritten log accepted, routes with sign-in reported as open, admins without MFA not reported, operators allowed to read the dashboard — each makes a test fail | `khv01-dev` | Passed |
| CI full suite: unit and API tests on amd64/arm64 and Debian 13, browser E2E (security findings and accounts, audit search with result filter, JSON Lines download where every record matches, axe) | GitHub Actions | Passed (run 40950899401) |
