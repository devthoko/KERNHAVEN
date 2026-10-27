# ADR-0007: React + TypeScript + Tailwind SPA embedded in the Core

- Status: Accepted
- Date: 2026-10-27

## Decision
The web UI is a React + TypeScript single-page app styled with Tailwind CSS,
built with Vite and embedded into the Core binary via `go:embed`. Served with a
strict Content Security Policy without inline scripts or third-party origins.
The UI never makes authorization decisions; it only hides controls the API
would reject anyway.

## Consequences
One artifact to ship. Node.js is needed only at build time, not on the host.
