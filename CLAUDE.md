# AegisHome Engineering Rules

## Mission
Build a secure, stable, maintainable self-hosting
management platform for Linux homelabs.

## Priorities
1. Host integrity and least privilege
2. Data integrity and recoverability
3. Reliable operations
4. Maintainability
5. User experience
6. Feature velocity

## Architecture
- Modular Go monolith for the Core
- Separate host agent
- React and TypeScript frontend
- SQLite for single-node persistence
- Versioned API contracts
- Native systemd deployment
- Rootless containers preferred

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
- Write tests for each meaningful change.
- Test error and failure paths.
- Prefer small, reviewable commits.
- Use explicit types for privileged operations.
- Do not add unnecessary infrastructure.
- Keep API contracts and documentation synchronized.
- Record major decisions in ADRs.

## AI Agent Restrictions
- Do not use permission-bypass modes.
- Do not run destructive host operations.
- Do not deploy to a production server.
- Do not read real credentials or private keys.
- Do not weaken failing tests to pass CI.
- Do not claim a security review was completed
  without evidence.

## Definition of Done
Every milestone must include:
- Implemented scope
- Tests and execution results
- Security considerations
- Known limitations
- Documentation updates
- A reproducible verification procedure
