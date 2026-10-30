# Kernhaven

**Your Server. Your Control.**

Kernhaven is a security-first, self-hosted management platform for Linux
servers in the homelab: containers, Compose stacks, an app store, storage,
files, reverse proxy, TLS, monitoring, encrypted backups and safe upgrades —
without giving the web application root on your host.

> **Status: release candidate in review — no release yet.** All 1.0
> capabilities are implemented and tested in CI on stacked branches awaiting
> the owner's review. Version 1.0 will only be released when every gate in
> [docs/release/QUALITY-GATES.md](docs/release/QUALITY-GATES.md) passes
> ([current status](docs/release/1.0-GATE.md)).

## Install

On Debian 13 (amd64 or arm64), as soon as a signed release exists:

```bash
curl -fsSL https://raw.githubusercontent.com/devthoko/KERNHAVEN/main/packaging/get.sh | sudo bash
```

The script downloads the latest release, verifies it against the release
key pinned in the script, and runs the release's installer with its
pre-flight checks. To read it before running it:

```bash
curl -fsSLO https://raw.githubusercontent.com/devthoko/KERNHAVEN/main/packaging/get.sh
less get.sh
sudo bash get.sh
```

`KERNHAVEN_VERSION=1.0.0` installs a given version. Until the release key
exists, the script stops with a message instead of installing. Setup, upgrades
and removal: [operator guide](docs/operations/OPERATIONS.md).

## Documentation

| Topic | Document |
|---|---|
| What Kernhaven is | [Product specification](docs/product/SPECIFICATION.md) |
| 1.0 scope and acceptance tests | [Feature matrix](docs/product/FEATURE-MATRIX.md) |
| How it is built | [Architecture](docs/architecture/ARCHITECTURE.md), [ADRs](docs/adr/README.md) |
| Security | [Threat model](docs/security/THREAT-MODEL.md) |
| Testing | [Test strategy](docs/testing/TEST-STRATEGY.md) |
| Plan | [Milestones](docs/milestones/MILESTONES.md) |
| Release criteria | [Quality gates](docs/release/QUALITY-GATES.md), [status of the 1.0 gate](docs/release/1.0-GATE.md) |
| Install and operate | [Operator guide](docs/operations/OPERATIONS.md) |
| Use | [User guide](docs/user/USER-GUIDE.md) |
| Security overview | [Security](docs/security/SECURITY.md), [ASVS self-assessment](docs/security/ASVS-L2.md) |

## Development

Requirements: Go 1.27+, Node.js 24 LTS, Linux.

```bash
scripts/check.sh   # Go and web checks, tests, builds, audits
scripts/build.sh   # web UI + kernhaven-core for linux/amd64 and linux/arm64 into bin/
scripts/e2e.sh     # browser tests against a fresh instance (needs Playwright Chromium)
```

For UI development run the Core on 127.0.0.1:8470 and `npm run dev` in `web/`;
Vite proxies `/api` to the Core.

Running the Core locally is described in the
[M1 verification procedure](docs/milestones/M1-core-foundation.md#verification-procedure).

## License

Not yet chosen. Until a license is added, all rights are reserved by the
repository owner.
