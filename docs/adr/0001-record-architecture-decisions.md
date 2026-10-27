# ADR-0001: Record architecture decisions

- Status: Accepted
- Date: 2026-10-27

## Context
Kernhaven is security-critical and built incrementally, partly by AI agents.
Decisions must be traceable and reviewable.

## Decision
Every significant architectural, security or dependency decision is recorded as
an ADR in `docs/adr/`. Accepted ADRs are not edited except for status changes;
superseding decisions get new ADRs.

## Consequences
Reviews can check changes against recorded decisions. Adding a dependency or
weakening a control without an ADR is a review blocker.
