# ADR-0014: CI actions pinned by commit SHA

- Status: Accepted
- Date: 2026-10-27

## Decision
All third-party GitHub Actions are referenced by full commit SHA with the tag as
a comment. Workflows run with `permissions: contents: read` by default. Go tool
dependencies in CI (`govulncheck`, `staticcheck`) are installed at pinned
versions.

## Consequences
Tag re-pointing attacks on actions do not affect CI. Updates are deliberate
commits.
