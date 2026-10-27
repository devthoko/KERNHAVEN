# Kernhaven

**Your Server. Your Control.**

Kernhaven is a security-first, self-hosted management platform for Linux
servers in the homelab: containers, Compose stacks, an app store, storage,
files, reverse proxy, TLS, monitoring, encrypted backups and safe upgrades —
without giving the web application root on your host.

> **Status: early development.** Identity, jobs and the web shell exist;
> container, storage, network and backup features do not yet.
> Version 1.0 will only be released when every gate in
> [docs/release/QUALITY-GATES.md](docs/release/QUALITY-GATES.md) passes.

## Documentation

| Topic | Document |
|---|---|
| What Kernhaven is | [Product specification](docs/product/SPECIFICATION.md) |
| 1.0 scope and acceptance tests | [Feature matrix](docs/product/FEATURE-MATRIX.md) |
| How it is built | [Architecture](docs/architecture/ARCHITECTURE.md), [ADRs](docs/adr/README.md) |
| Security | [Threat model](docs/security/THREAT-MODEL.md) |
| Testing | [Test strategy](docs/testing/TEST-STRATEGY.md) |
| Plan | [Milestones](docs/milestones/MILESTONES.md) |
| Release criteria | [Quality gates](docs/release/QUALITY-GATES.md) |

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
