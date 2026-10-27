# ADR-0017: Minimal Docker Engine API client instead of the Docker SDK

- Status: Accepted
- Date: 2026-10-27

## Context
The agent is root-equivalent through the Docker socket (ADR-0003). Every line
of code and every dependency in it is attack surface. The official Docker Go
SDK pulls in a large dependency tree and exposes the whole Engine API.

## Decision
The agent uses its own client (`internal/agent/docker`) built on `net/http`
over the unix socket. It implements only the endpoints behind the allow-listed
agent operations, negotiates the API version (max 1.47, min 1.44) and maps
errors to typed values. New Docker features are added endpoint by endpoint
together with their agent operation and tests.

## Consequences
- No new dependencies for Docker access; the privileged binary stays small.
- More code to maintain for Compose deployment (M7). If that becomes
  disproportionate, a superseding ADR must justify the SDK.
- Integration tests run against real Docker Engines (rootless on the dev
  server, rootful on CI runners) to catch API drift.
