# ADR-0002: Go modular monolith for the Core

- Status: Accepted
- Date: 2026-10-27

## Context
A single-node product needs simple deployment and low resource use (arm64
boards), but the feature set is large.

## Decision
The Core is one Go binary composed of modules under `internal/core/<module>`.
Modules communicate through Go interfaces, own their tables and do not access
each other's tables. Cross-module workflows go through the job system (M3).

## Alternatives
- Microservices: operational overhead disproportionate for one host.
- Unstructured monolith: does not scale to 25 modules maintainably.

## Consequences
Single binary to ship and sign. Module boundaries are enforced by review and by
an import-boundary test added in M2.
