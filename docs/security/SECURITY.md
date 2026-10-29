# Kernhaven Security Overview

## Design in one paragraph

The web application (Core) runs as an unprivileged, sandboxed user, bound
to loopback, behind Caddy. Everything privileged runs in separate services
with their own users, sockets and allow-listed, typed operations; each call
carries an Ed25519 grant signed by the Core and bound to the operation and
its parameters. No API takes a shell command; no component but the Docker
agent touches Docker. Data at rest that is secret is encrypted; the audit log
is hash-chained; backups are encrypted on the host before they leave it;
releases are signed with an offline key. See the
[threat model](THREAT-MODEL.md) and the [architecture](../architecture/ARCHITECTURE.md).

## Hardening checklist for operators

- Owners and admins use passkeys or an authenticator app; require them by
  policy (Account → MFA policy).
- Publish apps to the internet only with Kernhaven sign-in; prefer LAN-only.
- Keep `public_origin` https.
- Export the audit log regularly and keep the files elsewhere.
- Keep backups on a different machine or disk; verify them (weekly by
  default) and test a restore.
- Install only signed releases; keep `/etc/kernhaven/release-keys/` to the
  owner's key.
- Review policy exceptions on the Security page.

## What Kernhaven does not protect against

- An attacker with root on the host.
- A compromised owner account (it may do everything the owner may).
- Vulnerabilities inside the apps you install; Kernhaven confines them with
  container policy but does not scan images for vulnerabilities.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting ("Security" tab → "Report a
vulnerability") of the repository. Please do not open public issues for
security problems.
