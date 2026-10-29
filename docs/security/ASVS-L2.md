# OWASP ASVS 5.0 Level 2 — Kernhaven self-assessment

Status: **incomplete self-assessment, not an audit.** It maps each ASVS 5.0
chapter to Kernhaven's controls and the tests that show them. A
requirement-by-requirement checklist with evidence is still to be done, and
an independent review has not taken place; the 1.0 gate box "ASVS 5.0
Level 2 checklist complete with evidence" stays **unchecked**.

Legend: **Covered** (controls and tests exist for the chapter's L1/L2
requirements as far as they apply), **Partial** (gaps listed), **N/A**.

| Chapter | Status | Controls | Evidence | Gaps |
|---|---|---|---|---|
| V1 Encoding and sanitization | Covered | React escaping; no `dangerouslySetInnerHTML`; parameterised SQL only; Compose YAML via a strict subset parser; no shell from API input | TH-04, M5/M7 tests, contract tests | — |
| V2 Validation and business logic | Covered | Strict JSON decoding (unknown fields refused) in Core and agent; typed agent operations; limits on every list and body | agent fuzzing (CI), API tests per module | Business-limit review per feature not documented requirement by requirement |
| V3 Web frontend security | Covered | Strict CSP without `unsafe-inline`, `X-Frame-Options`, `nosniff`, Referrer-Policy; SameSite=Strict cookies; attachments for untrusted files | TH-04, middleware tests, E2E | ZAP baseline run pending (M19 CI job) |
| V4 API and web service | Covered | Versioned OpenAPI contract; route/permission registry tested against the spec; RBAC matrix over every route | `TestRoutesMatchOpenAPISpec`, `TestOpenAPIPermissionsMatchRoutes`, `TestRBACMatrix` | — |
| V5 File handling | Covered | `os.Root` (openat2 RESOLVE_BENEATH) in a separate file service; upload limits; previews only for safe types | TH-31, M10 tests incl. real root service | — |
| V6 Authentication | Covered | Argon2id; lockout and rate limits; passkeys (WebAuthn), TOTP with replay protection, recovery codes; MFA policy per role; step-up for sensitive actions | TH-01/02, M2/M11 tests, E2E | Breached-password check (k-anonymity service) not implemented (offline homelab default) |
| V7 Session management | Covered | Server-side sessions, rotation on login and step-up, idle/absolute timeouts, revocation, session list; live streams re-authenticate every 5 min | TH-02, TH-26, M2/M6b tests | — |
| V8 Authorization | Covered | Deny-by-default router; permission per route; agent re-checks policy; ownership checks (consoles per browser session) | RBAC matrix, `TestConsoleThroughCore`, TH-09/TH-21 | TH-21 partially mitigated (exception signing outside the Core) |
| V9 Self-contained tokens | Covered | Agent grants: Ed25519, op + params hash, 60 s lifetime, nonce cache | TH-23, fuzzing | — |
| V10 OAuth and OIDC | N/A | Kernhaven is not an OAuth client or server in 1.0 | — | — |
| V11 Cryptography | Covered | Standard library primitives: AES-256-GCM, Ed25519, SHA-256, HKDF; Argon2id; backup STREAM format (ADR-0029); random from crypto/rand | M16 tamper tests, M2/M8 crypto tests | Key rotation for the secret key not implemented (ADR-0019) |
| V12 Secure communication | Partial | TLS by Caddy (ACME, DNS-01, internal CA, own certificates); TLS 1.2+ for S3/SMTP; pinned SSH host keys | M12/M13/M16 tests | Core ↔ Caddy over loopback HTTP by design (ADR-0010) |
| V13 Configuration | Covered | Strict TOML (unknown keys refused), loopback-only listener, private data directory, sandboxed units, no secrets in source control (secret scan) | config tests, unit hardening job, secret scan | — |
| V14 Data protection | Covered | Secrets encrypted at rest and write-only; logs without secrets; backups encrypted; console content not recorded | TH-51, M7/M15/M16/M6b tests | — |
| V15 Secure coding and architecture | Covered | Privilege separation (ADR-0003), minimal dependencies with govulncheck, pinned CI actions | ADR-0014, lint job | Dependency SBOM not published |
| V16 Logging and error handling | Covered | Hash-chained audit log with verification and verifiable exports; uniform error model; panics recovered | TH-07/TH-52, M2/M17 tests | Automatic remote log forwarding not implemented (TH-52 partial) |
| V17 WebRTC | N/A | — | — | — |
