# M12 — Network and Reverse Proxy

Status: Implemented (CI 40761331938); merge pending owner review
Depends on: M4, M5 (and M8 for app routes, M11 for step-up)
Acceptance tests: AT-F11-01 … AT-F11-04, completes AT-F05-01
Threats addressed: TH-05 (Core only behind Caddy), TH-08 (forwarded
headers), TH-09 (authorization per route), new TH-11…TH-14 (see below)

## Goal

Publish installed apps under their own host names through Caddy, with
per-route access control (Kernhaven sign-in, LAN only, IP allow-list), and
show the host's network read-only — without giving the Core or the UI any
way to hand Caddy arbitrary configuration.

## Processes (ADR-0025)

| Process | Runs as | Can |
|---|---|---|
| `kernhaven-caddy.service` | `caddy`, group `kernhaven-proxy`, only `CAP_NET_BIND_SERVICE` | serve 80/443; admin API **only** on `unix//run/kernhaven-caddy/admin.sock` (directory 0750 `caddy:kernhaven-proxy`) |
| `kernhaven-proxy.service` | agent binary, `role = "proxy"`, user `kernhaven-proxy`, no capabilities, no IP traffic | build the Caddy configuration from typed routes and load it; read interfaces and listening sockets |
| Core | `kernhaven` | store routes, authorize, audit, the sign-in gate |

The proxy service is a fourth privilege domain next to the Docker agent, the
disk service and the file service. It has no Docker access and no file
access; the Docker agent cannot reach Caddy's admin API.

Caddy starts from a fixed bootstrap file (`/etc/kernhaven/caddy.json`, admin
socket only) and resumes the last loaded configuration after a restart. The
Core re-applies the routes when the proxy reports a configuration that
differs from what it expects (a lost or foreign configuration).

## Routes (AT-F11-01)

A route maps `host` + optional path prefix to a **loopback port** on the
host (an app's published web port, or a port given by the admin):

| Field | Rules |
|---|---|
| `host` | lower-case DNS name (labels `a-z0-9-`, 1–63 characters, ≤ 253 total) or IPv4 address; not the Kernhaven host; no wildcards |
| `path_prefix` | empty or `/segment[/segment…]` with `a-z A-Z 0-9 . _ ~ -`; no `.`/`..` segments, no trailing slash, ≤ 128 characters |
| `strip_prefix` | remove the prefix before proxying |
| `upstream_port` | 1024–65535 (proxy configuration), never the Core's port or Caddy's own ports; the upstream is always `127.0.0.1` |
| `app` | the installed app the route belongs to (optional) |

Host + prefix is unique. Longer prefixes win. The Kernhaven host itself is
not available for routes: its paths belong to the UI and the API.

Both the Core and the proxy service validate every route; the proxy
service builds the whole Caddy JSON itself, so even a compromised Core can
only produce configurations of this shape: no file server, no foreign
upstreams, no admin endpoint on TCP, no trust store changes.

## Access control (AT-F11-02)

Per route, combinable:

- **LAN only** — clients from 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16,
  ::1, fc00::/7 and fe80::/10; others get 403 from Caddy.
- **IP allow-list** — up to 32 CIDRs; others get 403. With LAN only, both
  must match.
- **Kernhaven sign-in** (SSO gate) with a minimum role. Caddy asks the Core
  (`forward_auth`) for every request:
  1. No valid gate cookie → `302` to `<origin>/gate?route=<id>&rd=<url>`.
  2. The gate page (signed-in users only) calls `POST /api/v1/proxy/gate`. The
     Core checks the role and that `rd` belongs to the route (scheme, host,
     prefix — no open redirect), then issues a one-time code (60 s, stored
     hashed, bound to the Kernhaven session).
  3. The browser goes to `<route>/.kernhaven/gate?code=…&rd=<path>`, which
     Caddy forwards to the Core. The Core consumes the code and sets a
     host-only cookie `kh_gate_<id>` (HttpOnly, Secure, SameSite=Lax, path =
     prefix) holding a random token stored as a hash.
  4. Later requests: the token maps to the Kernhaven session; the Core checks
     the session like any request (idle and absolute expiry, disabled users,
     enrolment-only sessions refused, role) and answers `200` with
     `X-Kernhaven-User`, which Caddy passes to the app.

  Signing out of Kernhaven, revoking the session or its expiry ends app
  access too (the gate tokens are deleted with the session). Use counts as
  activity of the Kernhaven session.

On every route Caddy first deletes client-supplied `X-Kernhaven-User`
headers. The Core's internal endpoints (`/api/v1/proxy-internal/*`) are
answered with 404 when requested through the Kernhaven host.

## Safe apply (AT-F11-03)

Every change builds the complete set of routes and sends it to the proxy
service, which loads it with Caddy's `POST /load`. Caddy provisions and
starts the new configuration before it stops the old one; if anything fails
(invalid configuration, a port in use) the running configuration stays.
Only after a successful load does the Core commit the change; a failure
leaves database and Caddy unchanged and is shown with Caddy's message,
recorded as the proxy state and audited. `POST /api/v1/network/apply`
re-applies the stored routes.

TLS in M12: every host gets a certificate from Caddy's internal CA; ACME is
never attempted and Caddy does not install its root into the host's trust
store (`install_trust: false`). ACME, root download and custom certificates
follow in M13.

## Network overview (AT-F11-04)

Read-only: interfaces with addresses, MTU and state (netlink), listening TCP
and UDP sockets (`/proc/self/net`), Docker networks (Docker agent), and the
proxy state. Process names of listening sockets are not shown (they need
root).

## Apps (AT-F05-01)

The install form takes an optional web address (host, optional prefix) with
"LAN only" (default on) and "Kernhaven sign-in". The route points to the
app's published web port and is created after the app; a route failure does
not fail the install and is reported. Removing an app removes its routes; an
update that changes the web port moves its routes. The app's "Open" link
uses the route.

## Permissions and step-up

| Route | Permission |
|---|---|
| `GET /api/v1/network/routes`, `GET /api/v1/network/overview` | `network.read` (owner, admin, operator) |
| `POST/PUT/DELETE /api/v1/network/routes…` | `network.manage` (owner, admin) + **step-up** |
| `POST /api/v1/network/apply` | `network.manage` |
| `POST /api/v1/proxy/gate` | `self.manage` (role checked per route) |
| `GET /api/v1/proxy-internal/auth`, `…/callback` | public, called by Caddy |

Installing an app with a web address needs step-up as well.

## Threats

| ID | Threat | Mitigation |
|---|---|---|
| TH-11 | Core compromise turns Caddy into a file server, open proxy or moves the admin API to TCP | Caddy JSON built only by the proxy service from typed, validated routes; admin socket fixed; upstreams only loopback in the allowed range |
| TH-12 | Header spoofing of the gate identity | `X-Kernhaven-User` deleted on every route before anything else |
| TH-13 | Open redirect / code theft in the gate flow | `rd` bound to route host and prefix; one-time codes, 60 s, hashed, bound to the session and route; callback only on the route's host |
| TH-14 | Exposing a loopback-only service by accident | Ports 1024–65535 only, not the Core or Caddy ports; every change audited and behind step-up |

## API

See `api/openapi/v1.yaml` (tag `network`).

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F11-01 | `internal/proxy` (host, prefix, CIDR rules; configuration shape: fixed admin socket, internal issuer, `install_trust: false`, Kernhaven route first, longest prefix first, header deletion first on every route); `TestCaddyRoutes` against real Caddy 2.6.2 (host and prefix routing, strip prefix, HTTP→HTTPS redirect); `TestNetworkRoutes` (CRUD, normalization, 9 invalid inputs never reach Caddy, permissions, step-up, audit); E2E: route published in the UI, reached through Caddy |
| AT-F11-02 | `TestCaddyRoutes` (LAN only, allow-list, both combined, spoofed `X-Kernhaven-User` removed, gate redirect with the original URI, callback with route and host); `TestProxyGate` (no-cookie redirect, wrong host/route refused, 9 open-redirect attempts, prefix bound, role minimum at the gate and at every request, codes single use, bound to the route, 60 s, foreign return path ignored, role change, logout and idle timeout end app access, audit); E2E: Kernhaven sign-in through the real gate, allow-list 403 |
| AT-F11-03 | `TestCaddyRoutes` (a configuration Caddy cannot start because its port is taken is refused, the running one keeps serving; resume after a restart); `TestNetworkRoutes` (refused create/update/delete leave database and Caddy unchanged, error shown and audited; reconcile restores a lost configuration); CI job `proxy` with the real units |
| AT-F11-04 | `TestParseProcNet` (IPv4, IPv6, mapped addresses, UDP), `TestOverview`, `TestNetworkRoutes` (operator reads, viewer refused); CI job `proxy`: overview inside the unit's sandbox sees Caddy's port; E2E: interfaces and listening ports shown |
| AT-F05-01 | `TestAppRoute` (invalid address refused before install, route to the app's web port with LAN only, app URL, port move, removal with the app, Caddy refusal reported without failing the install, step-up, `network.manage` required) |

## Known limitations

- Routes cannot use the Kernhaven host itself (its paths belong to the UI);
  every app needs its own host name, and DNS (or a hosts file) must point it
  to the server. No wildcard hosts, no IPv6 literal route hosts.
- Upstreams are loopback ports 1024–65535 only; services on other machines
  cannot be proxied.
- Apps publish their ports on all interfaces by default (M8). A route does
  not close the direct port: LAN-only and Kernhaven sign-in protect only the
  address through Caddy. The UI says so; binding app ports to 127.0.0.1 is a
  follow-up.
- In M12 certificates come from Caddy's internal CA; ACME, the root download
  and custom certificates followed in M13. After a load Caddy issues
  certificates in the background, so the first request to a new host can
  fail for a moment.
- Caddy enables HTTP/3 on the HTTPS port (UDP); the unit allows it.
- The SSO gate passes the user name only (`X-Kernhaven-User`); apps that
  should trust it must be configured to, and must not be reachable around
  Caddy.
- Process names of listening sockets are not shown (they need root).
- The Debian/Ubuntu `caddy.service` must be disabled; the installer (M18)
  does that. Until then `kernhaven-caddy.service` declares `Conflicts=`.

## Verification evidence (2026-10-28, branch `m12-network`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds) | `khv01-dev` | Passed |
| `internal/proxy`, `internal/agent/network` unit tests; proxy role allow-list (`agent.info`, `network.overview`, `proxy.apply`, `proxy.status`); proxy configuration refusals | `khv01-dev` | Passed |
| `TestCaddyRoutes` against real Caddy 2.6.2 (Ubuntu archive, extracted without installing) | `khv01-dev` | Passed |
| Mutation check: without deleting `X-Kernhaven-User` the backend receives `user=mallory` — `TestCaddyRoutes` fails | `khv01-dev` | Passed |
| `TestNetworkRoutes`, `TestNetworkWithoutProxy`, `TestProxyGate`, `TestAppRoute`, contract (120 operations, 2 new public routes reviewed), RBAC | `khv01-dev` | Passed |
| Mutation checks in the gate: without the host check, without the role check at forward auth, with codes not bound to their route, without the callback's path check — each makes `TestProxyGate` fail | `khv01-dev` | Passed |
| systemd exposure: `kernhaven-caddy` 1.4, `kernhaven-proxy` 0.9 (threshold 2.0) | `khv01-dev` | Passed |
| Live with real binaries (Core, proxy service, Caddy 2.6.2, no root, high ports): gate redirect, one-time code, cookie, upstream reached; code replay 400; internal endpoint via the Kernhaven host 404; Kernhaven UI through Caddy; allow-list 403; Caddy restart resumes the routes; logout ends app access; no certificate in the host's trust store | `khv01-dev` | Passed |
| UI check: proxy page (state, route, access badges, interfaces, listening ports), route dialog, gate page refusing a foreign address, 375 px without horizontal overflow | `khv01-dev` | Passed |
| First full CI run (40759728674) | GitHub Actions | Failed: only E2E — the store's `Name` field selector also matched the new `Host name` field (selector made exact). Passed in that run: real units as root (job `proxy`), real Caddy on amd64/arm64, systemd hardening, all other jobs |
| Second full CI run (40760254534) | GitHub Actions | Failed: only E2E — axe `scrollable-region-focusable`: the wide interfaces table scrolled horizontally but its scroll area could not be reached by keyboard. Fixed in the shared table component (focusable region named after the table) |
| Third full CI run (40760805510) | GitHub Actions | Failed: only the last E2E step — sign-in through the real gate, the app behind Caddy and the allow-list 403 all passed in the browser; after deleting the route the test expected a 404 page, but Caddy no longer serves the host at all (TLS handshake refused). The test now only checks that the app is gone |
| CI full suite: real units as root (admin socket reachable only by the proxy service, routes on 443, overview inside the sandbox, trust store untouched), real Caddy on amd64/arm64, browser E2E through Caddy (route published in the UI, Kernhaven sign-in through the gate, app shown, allow-list 403, deleted route no longer served, axe on page and dialog) | GitHub Actions | Passed (run 40761331938) |
