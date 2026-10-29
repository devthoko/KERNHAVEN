# M15 — Notifications and Alerts

Status: Implemented (CI pending); merge pending owner review
Depends on: M3, M9, M13, M14
Acceptance tests: AT-F16-01 … AT-F16-03, AT-F06-04, AT-F12-04
Threats addressed: TH-19, TH-20 (below), TH-15 (credentials of channels)

## Model

- A **rule** watches one kind of condition and has thresholds and a list of
  channels. There is one rule per kind; all start enabled without channels,
  so alerts are recorded and shown in the UI before anything is sent.
- An **alert** is a rule firing for a key (a service, a disk, a
  certificate …). It is *firing* until the condition ends (*resolved*), or an
  *event* (a failed job, a burst of failed sign-ins) that does not resolve.
- A **delivery** is one alert (or a test) to one channel, retried with
  backoff and listed in the delivery log.

## Rules (AT-F16-02, AT-F06-04, AT-F12-04)

The Core evaluates every minute:

| Rule | Fires when (defaults) | Key |
|---|---|---|
| `service_down` | a configured service is down in 2 consecutive checks (M14 health) | service |
| `cpu_high` | host CPU average above 90 % over 10 minutes | host |
| `memory_high` | memory used above 90 % | host |
| `disk_full` | a mounted file system above 90 % used (storage service) | file system |
| `smart_failed` | a disk's SMART self-assessment fails | disk |
| `cert_expiry` | an uploaded or DNS-01 certificate in use expires within 30, 14 or 3 days — one alert per stage | certificate + stage |
| `job_failed` | a job ends as failed (backups, updates, DNS-01 …) | job |
| `security` | ≥ 10 failed sign-ins within 10 minutes; an account lockout; an MFA policy downgrade; a user created as or changed to owner/admin; the audit chain fails verification (hourly) | event |

Thresholds are editable; rules can be disabled.

## Channels (AT-F16-01)

| Kind | Settings (secrets in bold, stored encrypted, never returned) |
|---|---|
| E-mail (SMTP) | host, port, security (`starttls` default, `tls`, `none` without authentication), username, **password**, from, recipients |
| Webhook | URL, **secret** (HMAC-SHA256 signature header `X-Kernhaven-Signature: sha256=…`) |
| ntfy | server URL, topic, **access token** |
| Gotify | server URL, **application token** |

Destinations are chosen by owners and admins (with step-up) and are usually
in the LAN, so private addresses are allowed. Loopback, link-local
(including cloud metadata), unspecified and multicast addresses are refused
when the name is resolved, at every connection (no DNS rebinding);
redirects are not followed; responses are read up to 64 KiB (ADR-0028).

## Delivery (AT-F16-03)

- Each firing alert, resolution and test creates one delivery per channel.
- Retries after 1, 2, 4, 8 and 16 minutes; then the delivery fails.
- Deduplication: a firing alert is not sent again while it stays firing; it
  is sent again only when it resolves (and fires again later).
- Rate limit: at most 20 deliveries per channel and hour; further ones are
  recorded as `dropped` with the reason.
- The delivery log keeps 30 days.

## API

| Route | Permission |
|---|---|
| `GET /api/v1/alerts`, `GET /api/v1/alerts/rules`, `GET /api/v1/alerts/deliveries`, `GET /api/v1/notify/channels` | `alerts.read` (owner, admin, operator) |
| `PUT /api/v1/alerts/rules/{rule}` | `alerts.manage` (owner, admin) |
| `POST/PUT/DELETE /api/v1/notify/channels…` | `alerts.manage` + step-up |
| `POST /api/v1/notify/channels/{id}/test` | `alerts.manage` |

## Threats

| ID | Threat | Mitigation |
|---|---|---|
| TH-19 | The Core is used to reach internal endpoints (SSRF) through channel URLs | Only owners/admins with step-up; loopback, link-local, metadata and multicast refused at dial time; no redirects; bounded responses |
| TH-20 | Alert floods hide real problems or exhaust a channel | Deduplication per alert, per-channel rate limit, recorded drops |

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F16-01 | `TestHTTPChannels` (webhook JSON with HMAC-SHA256 of the exact body, ntfy topic/title/priority/bearer token, Gotify `/message` with token, error status and body, redirects refused, loopback refused without the test exception); `TestSMTP` (fake server: STARTTLS, AUTH PLAIN only after TLS, recipients, headers; a server without STARTTLS gets no credentials); `TestValidate` (11 invalid settings incl. header injection, auth without TLS); `TestGuard` (loopback, link-local, metadata, unspecified, multicast, IPv4-mapped refused at dial time; LAN allowed); `TestAlertsAPI` (secrets write-only and encrypted, forbidden literal addresses refused on save); E2E: webhook channel and test message |
| AT-F16-02 | `TestStateRules` (service down after 2 checks, resolved once; CPU, memory, disk capacity of mounted file systems, SMART failure; editable thresholds; disabled rules end their alerts silently; invalid parameters and channels refused); `TestEvents` (failed jobs and security events — lockout, MFA downgrade, escalation to admin, sign-in burst once per window — only after the first run; broken audit chain fires until it verifies); `TestAlertsAPI` (a real failed job reaches the webhook); E2E: rule with a channel |
| AT-F16-03 | `TestDelivery` (retries after 1, 2, 4, 8, 16 minutes — not earlier —, final failure after 6 attempts, rate limit 20 per channel and hour with drops, test messages unlimited); `TestStateRules` (deduplication while firing); delivery log through the API and in the E2E |
| AT-F06-04 | `TestStateRules` (disk_full for mounted file systems only, smart_failed) |
| AT-F12-04 | `TestCertificateExpiry` (one alert at 30, 14 and 3 days and on expiry; certificates not in use ignored; severity) |

## Known limitations

- Rules have fixed kinds; there are no custom expressions and no per-host or
  per-container thresholds.
- Container metrics and app health are not alert sources yet (only services
  and the host).
- Messages are plain text in English; no templates.
- Deliveries are sequential within a round; a slow destination delays the
  others by up to its timeout (45 s).
- Alerts and deliveries are kept 30 days (certificate warnings longer, so a
  stage is not sent twice).
- `[alerts] allow_loopback_for_tests` exists only for tests and must stay
  unset in production.

## Verification evidence (2026-10-29, branch `m15-alerts`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds) | `khv01-dev` | Passed |
| `internal/core/alerts` (`TestGuard`, `TestValidate`, `TestHTTPChannels`, `TestSMTP`, `TestStateRules`, `TestCertificateExpiry`, `TestEvents`, `TestDelivery`) | `khv01-dev` | Passed — `TestDelivery` found that the job cursor lost jobs finishing in the same millisecond (now queried inclusively, deduplicated per job) |
| `TestAlertsAPI`, contract (141 operations), RBAC | `khv01-dev` | Passed |
| Mutation checks: link-local allowed, no rate limit, no backoff, STARTTLS optional — each makes a test fail. Removing the deduplication check in code leaves the unique index `alerts_firing`, which still prevents a second firing alert (defence in depth, no duplicate sent) | `khv01-dev` | Passed |
| Live with the real Core: HMAC-signed test message, "Monitor service is down" delivered after two checks, the metadata address refused at connection (now also on save) | `khv01-dev` | Passed |
| CI full suite incl. browser E2E | GitHub Actions | pending |
