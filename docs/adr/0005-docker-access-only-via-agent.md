# ADR-0005: Docker Engine access only via the agent

- Status: Accepted
- Date: 2026-10-27

## Context
Access to `/run/docker.sock` is root-equivalent. `CLAUDE.md` forbids exposing
it to the Core or UI.

## Decision
Only the agent talks to Docker Engine. The Core never mounts, proxies or
forwards the Docker socket. Rootful Docker Engine is the supported runtime for
1.0 because it is the Debian default; rootless Docker is evaluated as a
post-1.0 hardening option.

## Consequences
All container features are implemented as typed agent operations. Container
specs pass the policy engine in the Core *and* agent-side checks before reaching
Docker.
