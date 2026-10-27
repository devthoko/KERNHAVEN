# M5 — Web Dashboard Shell

Status: In progress
Depends on: M2 (identity API), M3 (jobs API)
Acceptance tests: AT-F01-01..04, AT-F08-05, AT-F18-03
Threats addressed: TH-04 (XSS), TH-03 (CSRF, client side)

## Goal

A production-quality, responsive web interface for everything the API offers
so far: first-run setup, login, a dashboard of real platform state, user
management, own account (password, sessions, theme), jobs with live progress
and cancel, and the audit log with chain verification. Every visible control
performs a real, authorized API call; nothing is mocked. Features of later
milestones are not shown as placeholders.

## Design

### Frontend (`web/`)

- React + TypeScript (strict) + Tailwind CSS, built with Vite (ADR-0007).
- No UI framework, router or state library: a small typed API client, a
  history-based router (~60 lines) and React context for the session. Fewer
  dependencies mean less supply-chain exposure; all versions are pinned
  exactly and installed with `npm ci --ignore-scripts`.
- API client: same-origin `fetch` with `credentials: "same-origin"`, sends
  `X-CSRF-Token` on unsafe methods, maps the uniform error body, and sends the
  user to the login page on `401`.
- UI mirrors permissions from `/api/v1/auth/session` only to hide controls;
  the server enforces every decision (CLAUDE.md).
- Rendering uses React's escaping only; `dangerouslySetInnerHTML` is
  forbidden (checked in CI by `scripts/check.sh`).

### Pages

| Route | Content | API |
|---|---|---|
| `/setup` | First-run owner creation with the journal token | `GET/POST /setup` |
| `/login` | Username/password login | `POST /auth/login` |
| `/` | Dashboard: platform readiness, version, job counts and recent jobs, recent security events (if `audit.read`), session expiry | health, version, jobs, audit |
| `/jobs`, `/jobs/:id` | Job list with state filter, live refresh while jobs are active, detail with step journal and logs, cancel (`jobs.manage`) | jobs API |
| `/users` | List, create, edit role/display name, enable/disable, reset password, delete (`users.read` / `users.manage`) | users API |
| `/account` | Change password, own sessions with revoke, theme preference | auth API, preferences API |
| `/audit` | Filterable, paginated audit log; chain verification (`audit.read`) | audit API |

Live updates: the job views poll every 2 s while jobs are active. Server-sent
events (AT-F01-05) arrive with container management in M6.

### Backend additions

- `internal/core/webui`: serves the embedded build (`go:embed`) at `/` with an
  SPA fallback for non-API paths; `/api/...` paths never fall back to HTML.
  Hashed assets get `Cache-Control: public, max-age=31536000, immutable`,
  `index.html` gets `no-store`.
- Content-Security-Policy for UI responses: `default-src 'none'; script-src
  'self'; style-src 'self'; img-src 'self' data:; font-src 'self';
  connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action
  'self'; frame-ancestors 'none'`. API responses keep `default-src 'none'`.
- If the binary was built without the UI, `/` answers `503` with a plain
  explanation instead of a broken page.
- User preferences: `GET/PUT /api/v1/auth/preferences` (`self.manage`),
  table `user_preferences`, currently `{"theme": "system"|"light"|"dark"}`
  (AT-F01-03, server-side so it follows the user across devices).

### Build

- `web/` builds to `internal/core/webui/dist/` (gitignored except
  `.gitkeep`); `scripts/build.sh` builds UI then Go binaries for amd64/arm64.
- CI: a `web` job (typecheck, unit tests, build, `npm audit`), and an `e2e`
  job that builds the full binary, starts it, and runs Playwright with axe.

## Acceptance criteria → tests

| AT | Tests |
|---|---|
| AT-F01-01 | Go: UI served with strict CSP, SPA fallback, API paths never return HTML, 503 without build. E2E: no CSP violations in the console |
| AT-F01-02 | E2E: every page at 360, 768, 1440 px has no horizontal overflow and a reachable navigation |
| AT-F01-03 | Go: preferences API; E2E: theme switch persists across logout/login |
| AT-F01-04 | E2E: axe on every page reports no serious/critical violations; setup and login completable by keyboard only |
| AT-F08-05 | E2E: user sees own sessions and revokes another; owner revokes via API is covered in M2 |
| AT-F18-03 | E2E: job list and detail show steps and logs; cancel requires `jobs.manage` |

## Security considerations

- Strict CSP without `unsafe-inline`/`unsafe-eval`; Vite's inline module
  preload polyfill is disabled.
- The UI never stores tokens in `localStorage`; the session cookie is
  `HttpOnly`. Only the CSRF token is held in memory.
- Public routes added: `GET /` and the SPA fallback `GET /{path...}`; both
  serve static files only.

## Known limitations

- Playwright needs browser system libraries; E2E runs in CI, not on
  `khv01-dev` (no `sudo`).
- No live push updates yet (polling); SSE comes with M6.
- Dashboard shows only data that exists today; host metrics arrive in M14.

## Verification evidence (2026-10-27, branch `m5-dashboard`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` incl. web typecheck, 7 Vitest tests, production build, `npm audit` (0 vulnerabilities) | `khv01-dev` | Passed |
| Go: `webui` handler tests (CSP, caching, SPA fallback, 404 for missing assets, 503 without build), router fallback never serves `/api/`, preferences API, UI/API CSP split | `khv01-dev` | Passed |
| Binary smoke test: `/users` → HTML with strict CSP and `no-store`; hashed JS `immutable`; `/api/v1/nope` → JSON 404 | `khv01-dev` | Passed |
| Built `index.html` contains no inline script or style | `khv01-dev` | Verified |
| Playwright + axe E2E, 8 tests (setup by keyboard, user management, jobs, audit + verify, session revoke, 360/768/1440 px layout, theme persistence, viewer restrictions; axe on every page; no CSP violations) | GitHub Actions run [40519204275](https://github.com/devthoko/KERNHAVEN/actions/runs/40519204275), commit `fadc2ee` | All 9 CI jobs passed |

### Defects found by the end-to-end suite and fixed

| Defect | Fix |
|---|---|
| Users page 115 px wider than a 360 px screen: `sr-only` header labels are absolutely positioned and escaped the table scroll container | Table wrapper is `position: relative` (`048bbc7`) |
| Account page 792 px wide at 360 px: card grids used an auto-sized column that grew to the sessions table | Grids use `minmax(0, 1fr)` columns (`048bbc7`); verified in a browser on all six views at 360/768/1440 px |
| Theme radio did not change until the server answered, so clicks looked ignored | Optimistic update with rollback on error (`fadc2ee`) |
| Relative times mixed the browser language into the English UI ("in 12 Stunden at the latest") | Relative times formatted in English (`048bbc7`) |

Test-suite defects (not product defects) fixed on the way: the suite exceeded
the login rate limit of 10 attempts per minute and address (the M2 control
worked as designed) and used an ambiguous selector.
