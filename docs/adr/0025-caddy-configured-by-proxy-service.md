# ADR-0025: Caddy in its own unit, configured only by a proxy service from typed routes

- Status: Accepted
- Date: 2026-10-28

## Context
ADR-0006 chose Caddy and its admin API on a unix socket "reachable only by the
agent". Caddy's admin API accepts any configuration: a file server for `/`,
reverse proxies to any address, an admin endpoint on TCP, trust store
installation. Whoever can talk to it controls what the host serves. Debian 13
and Ubuntu ship Caddy 2.6.2; its `caddy.service` reads a Caddyfile and puts
the admin API on `localhost:2019` (TCP).

## Decision
- Kernhaven runs its own unit, `kernhaven-caddy.service`, with the
  distribution's `/usr/bin/caddy` (2.6.2 or newer), a fixed bootstrap file
  that only sets the admin API to `unix//run/kernhaven-caddy/admin.sock`, and
  `--resume`. The socket's directory belongs to `caddy:kernhaven-proxy`,
  mode 0750. The distribution's `caddy.service` stays disabled (installer, M18).
- Only a new agent role, `role = "proxy"` (`kernhaven-proxy.service`, user
  `kernhaven-proxy`, no capabilities, no IP traffic), talks to that socket.
  It receives typed routes from the Core (`proxy.apply`), validates them
  independently and builds the entire Caddy JSON itself, including the fixed
  admin block, the internal TLS issuer with `install_trust: false`, the
  Kernhaven route and header stripping.
- Apply is Caddy's `POST /load`, which keeps the running configuration when
  the new one fails. A separate `caddy validate` run is not used: it would
  provision the internal CA in a second place and adds nothing `/load` does
  not check.
- The SSO gate is Caddy's `forward_auth` (in 2.6.2: `reverse_proxy` with
  `rewrite` and `handle_response`) against the Core, with a one-time code
  flow to set a host-only cookie on the app's host.

## Consequences
- A compromised Core can publish loopback ports 1024–65535 under host names
  and switch access options, but cannot make Caddy serve files, proxy to
  other hosts or expose its admin API. Each change is audited and needs
  step-up in the Core.
- The Docker agent cannot reach Caddy; the proxy service cannot reach Docker
  or files.
- Hosts are served with certificates of Caddy's internal CA until M13 adds
  ACME and the root download; browsers warn until the root is trusted.
- Kernhaven needs Caddy ≥ 2.6.2; newer versions keep the used JSON fields.
