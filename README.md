# Kernhaven

**Your Server. Your Control.**

Kernhaven is a security-first, self-hosted management platform for Linux
servers in the homelab: containers, Compose stacks, an app store, storage,
files, reverse proxy, TLS, monitoring, encrypted backups and safe upgrades —
without giving the web application root on your host.

> **Status: early development (milestone M1).** Nothing here is usable yet.
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

Requirements: Go 1.27+, Linux.

```bash
scripts/check.sh                 # formatting, vet, staticcheck, govulncheck, tests, builds
go build -o bin/kernhaven-core ./cmd/kernhaven-core
```

Running the Core locally is described in the
[M1 verification procedure](docs/milestones/M1-core-foundation.md#verification-procedure).

## License

Not yet chosen. Until a license is added, all rights are reserved by the
repository owner.
