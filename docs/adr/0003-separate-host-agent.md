# ADR-0003: Separate privilege-restricted host agent

- Status: Accepted
- Date: 2026-10-27

## Context
Container, disk and service management need privileges equivalent to root.
The web-facing process is the most exposed component.

## Decision
Privileged operations run in a separate `kernhaven-agent` process under its own
user. The Core reaches it only over a unix socket restricted by peer
credentials. Every request is a typed operation with an Ed25519-signed,
short-lived, single-use grant from the Core. The agent re-validates payloads and
enforces its own allow-list and policy independently of the Core.

## Consequences
- A Core compromise does not directly yield arbitrary host command execution.
- Membership in the `docker` group is root-equivalent; the agent is therefore
  treated as a high-value component: minimal code, no network listener, strict
  systemd sandboxing, fuzzed decoders.
- Residual risk: a compromised Core can still request any allow-listed
  operation. Mitigated by agent-side policy (e.g. never privileged containers
  without an Owner-approved exception signed with a separate key) — detailed in
  the M4 design.
