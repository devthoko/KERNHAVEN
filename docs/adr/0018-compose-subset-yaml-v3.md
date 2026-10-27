# ADR-0018: Own Compose parser on gopkg.in/yaml.v3 for a supported subset

- Status: Accepted
- Date: 2026-10-27

## Context
Compose files must be validated with line-accurate errors and mapped onto the
policy-checked `ContainerSpec`. The reference implementation (`compose-go`)
is large and accepts the full specification, including features Kernhaven
cannot enforce policy on (`build`, `extends`, many host-level options).

## Decision
Parse YAML with `gopkg.in/yaml.v3` (node API with line/column) and implement a
documented subset (M7 design). Unsupported keys are errors. Aliases and merge
keys are resolved with a node budget to stop expansion bombs.

## Consequences
- One small dependency instead of the Compose library tree.
- Some real-world Compose files need adjustment; errors say exactly which key
  and why. The subset grows deliberately, each key with policy coverage.
