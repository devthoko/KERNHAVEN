# ADR-0012: Versioned REST API with OpenAPI contract

- Status: Accepted
- Date: 2026-10-27

## Decision
JSON REST API under `/api/v1/`, specified in `api/openapi/v1.yaml`. A contract
test asserts that every registered route is in the spec and vice versa, and
that every route declares a permission (from M2). Breaking changes require a
new major version path.

## Consequences
API and documentation stay synchronized (CLAUDE.md requirement) by test, not by
discipline alone.
