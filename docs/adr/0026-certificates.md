# ADR-0026: Certificates — Caddy for internal and HTTP-01, the Core for DNS-01

- Status: Accepted
- Date: 2026-10-28

## Context
M13 needs ACME with HTTP-01 and DNS-01, a downloadable internal root and
uploaded certificates. Caddy (ADR-0006, ADR-0025) has an ACME issuer and a
local CA, but the Debian/Ubuntu package (2.6.2) contains no DNS provider
modules; those require a custom Caddy build. Lego, the common Go ACME
library, pulls in dozens of provider SDKs.

## Decision
- `internal` and `acme` (HTTP-01/TLS-ALPN-01) certificates stay with Caddy:
  the proxy service sets the issuer per host. The ACME CA is chosen by the
  proxy service from a fixed list (Let's Encrypt production or staging);
  only `proxy.toml` can override it, for tests.
- DNS-01 runs in the Core with `golang.org/x/crypto/acme` (already a
  dependency, no new module) and one in-house provider client, Cloudflare.
  Issued and uploaded certificates are loaded into Caddy as PEM through the
  proxy service, which validates them again.
- Keys, the ACME account key and DNS credentials are encrypted with the
  Core's secret key (ADR-0019).
- ACME is tested against Pebble, Let's Encrypt's test server, built from a
  pinned version in CI only (not shipped).
- `proxy.apply` may carry 2 MiB; all other agent operations keep 64 KiB.

## Consequences
- No custom Caddy build and no provider SDKs; more providers need code in
  Kernhaven (one small REST client each).
- Private keys of DNS-01 and uploaded certificates pass through the agent
  protocol and are stored by Caddy in its configuration file
  (`/var/lib/kernhaven-caddy`, mode 0700, user caddy) — the same protection
  as Caddy's own keys.
- The Cloudflare client is tested against a fake API, not the real service.
