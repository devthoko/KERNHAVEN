# M13 — TLS Certificate Management

Status: Implemented (CI pending); merge pending owner review
Depends on: M12
Acceptance tests: AT-F12-01 … AT-F12-03 (AT-F12-04, expiry warnings, is M15)
Threats addressed: TH-15 … TH-17 (below), TH-11 (Caddy stays configured
only by the proxy service)

## Certificates per host

TLS is chosen per host (SNI), for every host that has a route and for the
Kernhaven host itself. Each host has one mode:

| Mode | Who obtains the certificate | When to use |
|---|---|---|
| `internal` (default) | Caddy's local CA (M12) | LAN hosts; clients trust the downloadable root (AT-F12-02) |
| `acme` | Caddy, ACME HTTP-01 / TLS-ALPN-01 with Let's Encrypt | Hosts reachable from the internet on ports 80/443 |
| `dns` | the Core, ACME DNS-01 with Let's Encrypt and a DNS provider | Hosts with a public domain that are not reachable from the internet (LAN-only); wildcard-free |
| `custom` | uploaded by an admin (AT-F12-03) | Certificates of an own CA or another provider |

`acme` is refused for hosts with a LAN-only route: HTTP-01 only works when
the host is reachable from the internet. IP addresses can only use
`internal` or `custom`. A `dns` host uses the internal CA until its first
certificate is issued.

## ACME (AT-F12-01)

Settings (`PUT /api/v1/tls/settings`, owner and admin, step-up): contact
e-mail, Let's Encrypt production or staging, the explicit agreement to Let's
Encrypt's subscriber agreement (required before any ACME mode), and the DNS
provider with its credentials.

- **HTTP-01 / TLS-ALPN-01**: the proxy service adds an ACME issuer for the
  `acme` hosts to Caddy's automation policies. The Core sends only
  "production" or "staging"; the proxy service maps that to Let's Encrypt's
  directories, so the Core cannot point Caddy at another CA (tests set an
  override in `proxy.toml`).
- **DNS-01**: Caddy as packaged by Debian has no DNS provider modules, so the
  Core runs the ACME client (`golang.org/x/crypto/acme`, already a
  dependency; ADR-0026). Supported provider in 1.0: **Cloudflare** (API token
  with Zone:DNS:Edit, stored encrypted with ADR-0019, never returned). The
  issuance is a journaled job (`tls.issue`): order → TXT record
  `_acme-challenge.<host>` → wait for propagation → validate → finalize with
  a new ECDSA P-256 key → store certificate and key (encrypted) → remove the
  TXT record → apply. The account key is created once per directory and kept
  encrypted.
- **Renewal**: a daily maintenance job queues issuance for `dns`
  certificates that expire within 30 days. Caddy renews `internal` and
  `acme` certificates itself.

Outbound connections go only to the fixed ACME directory and the
provider's fixed API; nothing comes from user input.

## Internal CA (AT-F12-02)

`GET /api/v1/tls/root.crt` downloads Caddy's local root (read through the
proxy service from Caddy's admin API, `/pki/ca/local`) for every signed-in
user; the page shows its SHA-256 fingerprint for checking on the client.

## Custom certificates (AT-F12-03)

`POST /api/v1/tls/certificates` with a PEM chain and an unencrypted PEM key
(PKCS#8, PKCS#1 or SEC 1). Before anything is stored:

- the chain parses, the first certificate is the leaf, at most 10
  certificates and 64 KiB;
- the key matches the leaf; RSA keys have at least 2048 bits; ECDSA P-256 or
  P-384 or Ed25519;
- the leaf is valid now and for at least one more day, is not a CA, allows
  server authentication if it lists extended key usages;
- the chain verifies from the leaf through the uploaded intermediates to a
  system root or to a root included in the upload (an own CA);
- signatures with SHA-1 or MD5 are refused.

A certificate can be assigned to a host it covers (SAN, one-label wildcard).
The key is stored encrypted and never returned. Certificates in use cannot be
deleted. Expired certificates stay in use until replaced; warnings are M15.

The proxy service checks every certificate again (parse, key match, host
coverage) before it puts it into Caddy's configuration (`load_pem`, with a
TLS connection policy per host that selects exactly that certificate).

## Safe apply

Like routes (M12): a mode change, an assignment or a new DNS-01 certificate
is sent to Caddy together with all routes; the database is changed only when
Caddy accepted it. Requests to the proxy service may now carry up to 2 MiB
for `proxy.apply` only (certificates); every other operation keeps 64 KiB.

## Permissions

| Route | Permission |
|---|---|
| `GET /api/v1/tls` | `network.read` |
| `GET /api/v1/tls/root.crt` | `self.manage` |
| `PUT /api/v1/tls/settings`, `PUT /api/v1/tls/hosts/{host}`, `POST/DELETE /api/v1/tls/certificates…`, `POST /api/v1/tls/hosts/{host}/renew` | `network.manage` + step-up |

## Threats

| ID | Threat | Mitigation |
|---|---|---|
| TH-15 | Theft of private keys or DNS credentials from the database or API | Encrypted with the Core's key (ADR-0019); never in API responses or logs; only the proxy service receives keys, only for Caddy |
| TH-16 | A malicious or broken certificate is served (wrong host, expired, key mismatch) | Validated in the Core and again in the proxy service; per-host selection in Caddy |
| TH-17 | The Core is used to obtain certificates for foreign domains | ACME only for hosts with a route; DNS-01 only in the zone the DNS token can edit; every request audited |

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F12-01 | `TestCaddyTLS` (real Caddy 2.6.2 obtains a certificate from Pebble through HTTP-01/TLS-ALPN-01 with the configuration the proxy service builds); `TestDNS01AgainstPebble` (Core API → `tls.issue` job → `golang.org/x/crypto/acme` → TXT record → validation → certificate stored and applied; chain verified against Pebble's root); `TestTLS` (agreement and e-mail required, ACME refused for LAN-only, IP and private names, DNS-01 for a LAN-only host with a public name, failure recorded and audited without replacing the certificate, renewal on demand); `TestTLSRenewal` (30 days before expiry, old DNS-01 certificate removed); `TestCloudflare` (zone lookup from the closest name, TXT record, cleanup, errors without the token); `TestBuildTLS` (issuer per host, only Let's Encrypt or a test override) |
| AT-F12-02 | `TestCaddyTLS` (the Kernhaven host is served by the local CA whose root the proxy service returns); `TestTLS` (download for every signed-in user, fingerprint in the overview); CI job `proxy`: root through the real units; E2E: download |
| AT-F12-03 | `TestParseKeyPair`, `TestValidateUpload` (own CA chain, public-style chain, 9 refusals: missing intermediate, untrusted root, expiring, not yet valid, CA as leaf, client certificate, no names, chain of another CA, key mismatch/encrypted/weak/oversized/junk); `TestTLS` (upload through the API, key encrypted at rest and never returned, assignment only to covered hosts, certificate in use cannot be deleted, Caddy refusal leaves everything unchanged, step-up); `TestCaddyTLS` and CI job `proxy` (exactly the uploaded certificate served for its host); E2E: upload in the browser, assignment, served issuer checked over TLS |

## Known limitations

- DNS-01 supports Cloudflare only; other providers need a small client each.
  The Cloudflare client is tested against a fake API, not the real service.
- DNS-01 waits a fixed time for propagation (`[tls] dns_propagation`, default
  60 s) instead of querying the authoritative servers.
- No wildcard certificates from ACME; uploaded wildcard certificates work.
- Hosts with private names (`.lan`, `.local`, `.home.arpa`, `.internal`, …)
  can only use the internal CA or an own certificate.
- Expiry warnings (AT-F12-04) are M15; an expired uploaded certificate stays
  in use until it is replaced.
- Certificates for `acme` hosts are kept by Caddy, not listed under stored
  certificates.
- `proxy.toml` and `core.toml` accept keys ending in `_for_tests` that point
  ACME at another CA; they exist only for Pebble in CI and must stay unset in
  production.

## Verification evidence (2026-10-28, branch `m13-tls`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds) | `khv01-dev` | Passed |
| `internal/proxy` (`TestParseKeyPair`, `TestValidateUpload`, `TestBuildTLS`), `internal/core/certs` (`TestCloudflare`), proxy role allow-list with `proxy.ca`, request limits (2 MiB only for `proxy.apply` on the proxy role, 64 KiB everywhere else) | `khv01-dev` | Passed |
| `TestCaddyTLS` against real Caddy 2.6.2 and Pebble 2.10.1 | `khv01-dev` | Passed |
| `TestDNS01AgainstPebble` (real ACME DNS-01 through the Core) | `khv01-dev` | Passed — after two fixes found by it: the finalize URL was read from the polled order, and `CreateOrderCert` relied on a Location header Pebble does not send (now `CreateCertFromOrder`) |
| `TestTLS`, `TestTLSRenewal`, contract (127 operations), RBAC | `khv01-dev` | Passed — `TestTLS` first showed that `.lan` names were accepted for DNS-01; private suffixes are refused now |
| Mutation checks: the proxy accepting a certificate for another host, the proxy accepting a foreign ACME CA, uploads without chain verification, keys stored unencrypted — each makes a test fail | `khv01-dev` | Passed |
| Live with real binaries (Core, proxy service, Caddy 2.6.2, Pebble; no root): internal CA by default, root download and fingerprint, wrong key refused, own CA chain accepted and served for its host, key never in the API, HTTP-01 certificate from Pebble served, certificate in use cannot be deleted (409), trust store untouched | `khv01-dev` | Passed |
| UI check: certificates page, mode dialog, 375 px without horizontal overflow | `khv01-dev` | Passed |
| `TestPortInUseExitCode` failed once in `check.sh` (temporary directory still being written after `run` returned). The maintenance goroutine was not stopped on early returns; it now stops and is waited for before the runner and the database close. The failure did not recur in 20 runs before or after the fix, so the cause is likely but not proven | `khv01-dev` | Fixed (likely cause) |
| First full CI run (40773066128) | GitHub Actions | Failed: only the secret scan in the lint job — a test and a form placeholder contained a literal PEM private key header. `check.sh` scans tracked files only and the new files were not committed yet locally. The header is now built in code (test) and the placeholder reworded; the scan is unchanged. All other jobs passed, including Pebble on amd64/arm64, the real units and the browser E2E upload |
| CI full suite: Pebble on amd64/arm64, real units with an own certificate, browser E2E upload | GitHub Actions | pending |
