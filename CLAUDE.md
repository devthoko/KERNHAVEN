# Kernhaven Engineering Rules

Kernhaven — "Your Server. Your Control." A security-first, self-hosted Linux
server management platform. Specification and plans live in `docs/`:
[spec](docs/product/SPECIFICATION.md), [feature matrix](docs/product/FEATURE-MATRIX.md),
[architecture](docs/architecture/ARCHITECTURE.md), [threat model](docs/security/THREAT-MODEL.md),
[ADRs](docs/adr/README.md), [milestones](docs/milestones/MILESTONES.md),
[quality gates](docs/release/QUALITY-GATES.md).

## Mission
Build a secure, stable, maintainable self-hosting management platform for
Linux homelabs. Version 1.0 must be production-ready, not an MVP.

## Priorities
1. Host integrity and least privilege
2. Data integrity and recoverability
3. Reliable operations
4. Maintainability
5. User experience
6. Feature velocity

## Architecture
- Modular Go monolith for the Core (`kernhaven-core`)
- Separate privilege-restricted host agent (`kernhaven-agent`)
- React, TypeScript and Tailwind CSS frontend, embedded in the Core
- SQLite for single-node persistence
- Docker Engine runtime, reached only through the agent
- Caddy as TLS terminator and reverse proxy
- Native systemd deployment; Debian 13 amd64/arm64 is the primary platform
- Versioned API contracts (`api/openapi/`)

## Security Invariants
- Never expose Docker sockets to the Core or UI.
- Never execute arbitrary shell commands from API input.
- Never trust frontend authorization decisions.
- Never accept unvalidated filesystem paths.
- Never bypass agent authorization.
- Never store credentials in source control.
- Never default to privileged containers.
- Never silently weaken security policies.
- Never modify host firewall or SSH configuration
  without a dedicated design and explicit approval.

## Development Requirements
- Write a milestone design (`docs/milestones/Mx-*.md`) with acceptance
  criteria before implementing the milestone.
- Write tests for each meaningful change; test error and failure paths.
- Reference acceptance test IDs (`AT-…`) in tests that verify them.
- Prefer small, reviewable commits.
- Use explicit types for privileged operations.
- Do not add unnecessary infrastructure or dependencies; new dependencies need
  an ADR or a justification in the milestone design.
- Keep API contracts and documentation synchronized.
- Record major decisions in ADRs (`docs/adr/`).
- Run `scripts/check.sh` before every commit.

## AI Agent Restrictions
- Do not use permission-bypass modes.
- Do not run destructive host operations.
- Do not deploy to a production server.
- Do not read real credentials or private keys.
- Do not weaken failing tests to pass CI.
- Do not claim a security review was completed without evidence.
- Do not mark features Done in the feature matrix without passing,
  automated acceptance tests.
- Never report simulated or incomplete functionality as production-ready.

## Definition of Done
Every milestone must include:
- Implemented scope
- Tests and execution results
- Security considerations
- Known limitations
- Documentation updates
- A reproducible verification procedure
