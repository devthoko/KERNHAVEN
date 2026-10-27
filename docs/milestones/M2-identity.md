# M2 — Identity, Sessions, RBAC and Audit Log

Status: In progress
Depends on: M1
Acceptance tests: AT-F08-01..04, AT-F08-06, AT-F09-01, AT-F10-01..02
Threats addressed: TH-01 (partial, MFA in M11), TH-02, TH-03, TH-08, TH-09, TH-10, TH-52

## Goal

Every API route is either explicitly public or requires an authenticated
session holding a named permission. Users authenticate with passwords, get
server-side sessions protected against fixation, CSRF and hijacking, and every
security-relevant action lands in a tamper-evident audit log.

## Design

### Deny-by-default routing

`httpserver.Router.Handle(pattern, access, handler)` requires an `Access`
value: `httpserver.Public()` or `httpserver.RequirePermission("<perm>")`.
There is no way to register a route without one. Non-public routes are wrapped
by a guard function supplied by the identity service. `Router.Routes()` lists
every route with its access; a contract test fails if a route uses an unknown
permission, if a route is public without being on the reviewed public
allow-list, or if a route is missing from the OpenAPI spec.

### Roles and permissions (`internal/core/authz`)

| Permission | Owner | Admin | Operator | Viewer |
|---|---|---|---|---|
| `self.manage` (own session, password, sessions) | ✓ | ✓ | ✓ | ✓ |
| `system.read` (version, dashboards) | ✓ | ✓ | ✓ | ✓ |
| `users.read` | ✓ | ✓ | | |
| `users.manage` | ✓ | ✓ (only operators/viewers) | | |
| `sessions.manage` (revoke others' sessions) | ✓ | | | |
| `audit.read` | ✓ | ✓ | | |

Later milestones add permissions; roles stay fixed for 1.0.

User management rules (enforced server-side, in the same transaction):
- Admins may only create, modify, delete or reset users with role operator or
  viewer, and may only assign those roles.
- Nobody can change their own role, disable or delete themselves.
- The last enabled owner cannot be demoted, disabled or deleted.
- Role change, disable and password reset revoke all sessions of the target.
  Changing one's own password revokes all other own sessions.

### Passwords

- Argon2id (`golang.org/x/crypto/argon2`, ADR-0015), PHC string format,
  default m=64 MiB, t=2, p=2, 16-byte salt, 32-byte key. At most two hashes are
  computed concurrently to bound memory use.
- Policy (NIST SP 800-63B style): 12..256 characters, must not contain the
  username, at least 5 distinct characters, not in the embedded list of common
  passwords. No composition rules.
- Unknown users and locked accounts still run a dummy hash verification to keep
  timing uniform; all failures return the same `401 invalid_credentials`.

### Brute-force protection

- Per client IP: token bucket, 10 attempts, refilling 1 per 6 s, shared by
  login and setup. Exceeding it returns `429` with `Retry-After`.
- Per account: after 5 consecutive failures the account is locked for
  1 min × 2^(failures−5), max 1 h. Locked accounts answer like wrong
  passwords; the lock is audited.
- Client IP: the Core only listens on loopback (ADR-0010), so the peer is
  always the local reverse proxy. If the peer is loopback, the right-most
  `X-Forwarded-For` entry (set by Caddy) is used; otherwise the peer address.

### Sessions

- 256-bit random token in cookie `__Host-kh_session` (`Secure`, `HttpOnly`,
  `SameSite=Strict`, `Path=/`). With an `http://` loopback public origin (local
  development only) the cookie is `kh_session` without `Secure`.
- Only the SHA-256 of the token is stored. Each session also has a public ID
  (for listing/revoking) and a CSRF token.
- Idle timeout (default 30 min) and absolute timeout (default 12 h);
  `last_seen` is updated at most once per minute.
- A new session is created on every login (no fixation); logout deletes it.

### CSRF

For every non-safe method (`POST`, `PUT`, `PATCH`, `DELETE`):
- `Origin`, if present, must equal the configured `server.public_origin`;
  if absent, `Sec-Fetch-Site`, if present, must be `same-origin`.
- Authenticated routes additionally require `X-CSRF-Token` equal to the
  session's CSRF token (constant-time comparison).

### First-run setup

While no user exists, the Core creates a random setup token at startup
(valid 24 h, replaced on every restart) and writes it to the journal at warn
level. `POST /api/v1/setup` with the token creates the first owner. The token
is single-use; once any user exists, setup is permanently closed.

### Audit log (`internal/core/audit`)

- Table `audit_events` with append-only triggers (UPDATE/DELETE abort).
- Each record stores `prev_hash` and
  `hash = SHA-256(prev_hash ‖ canonical JSON of the record)`.
- State changes write their audit record in the same transaction as the
  change; failed attempts are recorded in their own transaction.
- `GET /api/v1/audit/verify` recomputes the chain and reports the first broken
  sequence number.

### API

| Method & path | Access |
|---|---|
| `GET /api/v1/health/live`, `GET /api/v1/health/ready` | public |
| `GET /api/v1/setup`, `POST /api/v1/setup` | public (origin-checked) |
| `POST /api/v1/auth/login` | public (origin-checked) |
| `POST /api/v1/auth/logout` | `self.manage` |
| `GET /api/v1/auth/session` | `self.manage` |
| `POST /api/v1/auth/password` | `self.manage` |
| `GET /api/v1/auth/sessions`, `DELETE /api/v1/auth/sessions/{id}` | `self.manage` (others' sessions need `sessions.manage`) |
| `GET /api/v1/version` | `system.read` |
| `GET /api/v1/users`, `GET /api/v1/users/{id}` | `users.read` |
| `POST /api/v1/users`, `PATCH /api/v1/users/{id}`, `DELETE /api/v1/users/{id}`, `POST /api/v1/users/{id}/password` | `users.manage` |
| `GET /api/v1/audit`, `GET /api/v1/audit/verify` | `audit.read` |

### Configuration additions

```toml
[server]
public_origin = "https://kernhaven.home.arpa"   # https, or http only for loopback hosts

[auth]
session_idle_timeout = "30m"      # 5m..24h
session_absolute_timeout = "12h"  # 1h..720h, >= idle
setup_token_ttl = "24h"           # 10m..72h
```

## Acceptance criteria → tests

| AT | Tests |
|---|---|
| AT-F08-01 | setup: wrong/expired/reused token rejected; setup closed after first user; token rotates on restart |
| AT-F08-02 | password hashing round trip and tamper rejection; policy cases; lockout and backoff; IP rate limit 429; uniform 401 for unknown/disabled/locked |
| AT-F08-03 | cookie attributes; idle and absolute expiry with a controlled clock; new session per login; logout invalidates; sessions revoked on role change, disable, reset |
| AT-F08-04 | missing/wrong CSRF token → 403; foreign Origin → 403 on public and authenticated routes; `Sec-Fetch-Site: cross-site` → 403 |
| AT-F08-06 | create/update/delete users; admin limits; last-owner and self protection |
| AT-F09-01 | route enumeration contract test; RBAC matrix test calling every route with every role |
| AT-F10-01 | each audited action produces a record with actor, action, target, result, request ID, IP |
| AT-F10-02 | chain verifies; UPDATE/DELETE blocked by triggers; manual tampering (triggers dropped) detected |

## Security considerations

- Secrets: only hashes of session and setup tokens are stored; password hashes
  use Argon2id. The setup token appears once in the journal by design (TH-10);
  journal access must be restricted to administrators.
- Tail truncation of the audit log (deleting the newest records with direct DB
  write access) is not detectable from the chain alone; external anchoring is
  planned with audit export (M17).
- Usernames entered at failed logins are recorded in the audit log (truncated
  to 64 characters). Users who type a password into the username field leak
  it to audit readers; this is a common, accepted trade-off for forensics.

## Known limitations

- No MFA, passkeys or step-up re-authentication yet (M11).
- The common-password list is small and offline; there is no breach-corpus
  lookup (no external calls by design).
- Rate-limit state is in memory and resets on restart; account lockout state
  is persistent.
- The web UI for these features comes with M5.

## Verification evidence (2026-10-27, branch `m2-identity`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (gofmt, vet, staticcheck, govulncheck, tests, amd64+arm64 builds, secret scan) | `khv01-dev`, Go 1.27.3 | Passed; tests without `-race` (no C toolchain) |
| `internal/core/app` integration tests: contract, OpenAPI sync, RBAC matrix (every route × anonymous + 4 roles), setup, login, lockout, rate limit, timeouts, CSRF, user rules, session revocation, audit trail | `khv01-dev` | 21/21 passed |
| Smoke test with the real binary: setup token from log → setup 201 with HttpOnly cookie → create user without CSRF 403 / with CSRF 201 → audit verify ok → anonymous `/version` 401 → SIGTERM exit 0 | `khv01-dev` | Passed |
| govulncheck | `khv01-dev` | No reachable vulnerabilities; GO-2026-5932 (`x/crypto/openpgp`, not imported) noted in ADR-0015 |
| CI (race detector, arm64, Debian 13) | GitHub Actions | **Pending** — branch not pushed yet |

The last-owner rule is enforced in `checkManage`, but through the API it is
currently shadowed by self-protection (an owner acting on another enabled owner
implies two owners). It remains as defense in depth.
