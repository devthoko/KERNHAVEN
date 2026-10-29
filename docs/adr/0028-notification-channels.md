# ADR-0028: Notification channels without SDKs, LAN destinations allowed, dial-time address checks

- Status: Accepted
- Date: 2026-10-29

## Context
M15 sends alerts by SMTP, webhook, ntfy and Gotify. Homelab users run ntfy,
Gotify and mail relays in their LAN, so the URL rules of the Compose import
(TH-42: public HTTPS only) would make the channels useless. Channel URLs are
set by trusted roles, but a compromised admin account or a typo must not let
the Core reach its own loopback services or the cloud metadata endpoint.

## Decision
- All four channels are implemented with the standard library (`net/smtp`,
  `net/http`); no notification SDKs.
- An outbound dialer resolves the host and refuses loopback, link-local
  (`169.254.0.0/16`, `fe80::/10`), unspecified and multicast addresses; it
  connects to the checked address, so DNS rebinding between check and
  connection is impossible. Private ranges (RFC 1918, ULA) are allowed.
- HTTP channels do not follow redirects and read at most 64 KiB of a
  response. SMTP authentication only over TLS (`starttls` or `tls`).
- Secrets are encrypted with the Core's key (ADR-0019) and write-only.

## Consequences
- An owner or admin can make the Core send requests to LAN hosts; that is
  the purpose of the feature and needs step-up and is audited.
- Tests use a loopback exception that only `core.toml`
  (`[alerts] allow_loopback_for_tests`) can set.
