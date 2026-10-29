# Kernhaven Threat Model

Status: Draft v0.1 (M0). Method: STRIDE per trust boundary, reviewed at every
milestone gate. Verification target: OWASP ASVS 5.0 Level 2.

## 1. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Host integrity (root) | Full compromise of the server and everything on it |
| A2 | User credentials, sessions, passkeys, TOTP secrets | Account takeover |
| A3 | App data volumes and user files | Confidentiality and loss of personal data |
| A4 | Secrets (app secrets, backup keys, Core grant-signing key) | Escalation, backup decryption |
| A5 | Backups | Last line of recovery; also a data exfiltration target |
| A6 | Audit log | Detection and forensics |
| A7 | Release and catalog signing keys / supply chain | Mass compromise of installations |
| A8 | Availability of apps and platform | Homelab services the household depends on |

## 2. Actors

| ID | Actor | Capability assumed |
|---|---|---|
| T1 | Internet attacker | Reaches Caddy if the user exposes ports; no credentials |
| T2 | LAN attacker | Same as T1 plus LAN-only routes, mDNS, ARP-level tricks |
| T3 | Low-privilege authenticated user (Viewer/Operator) | Valid session, tries to escalate |
| T4 | Malicious or compromised app container | Code execution inside one container |
| T5 | Malicious catalog / Compose file / image | Content the user imports |
| T6 | Compromised Core process | Arbitrary code as the `kernhaven` user |
| T7 | Supply-chain attacker | Tampers with dependencies, CI, release or catalog channel |
| T8 | Local unprivileged host user | Shell on the host without root |

Out of scope: an attacker who already has root on the host; physical attacks
beyond theft of a powered-off disk (covered by backup encryption only).

## 3. Trust boundaries

See [Architecture §1](../architecture/ARCHITECTURE.md#1-processes-and-trust-boundaries).

- **TB-1** Network ↔ Caddy
- **TB-2** Caddy ↔ Core (loopback HTTP)
- **TB-3** Core ↔ Agent (unix socket, signed grants)
- **TB-4** Agent ↔ host resources (Docker, systemd, disks, files)
- **TB-5** Containers ↔ host and each other
- **TB-6** External sources (catalogs, registries, ACME, backup targets, notification endpoints) ↔ Core/agent

## 4. Threats and mitigations

Each threat has an owner milestone and verifying tests. Status: **Open**
(mitigation not implemented), **Mitigated** (implemented and tested),
**Accepted** (documented residual risk).

### TB-1/TB-2 — Network, Caddy and Core HTTP

| ID | STRIDE | Threat | Mitigation | MS | Status |
|---|---|---|---|---|---|
| TH-01 | S | Credential stuffing / brute force on login | Argon2id, rate limits per IP and account, exponential backoff, MFA | M2/M11 | Mitigated (M2: Argon2id, IP rate limit, lockout; M11: TOTP with replay protection, passkeys, MFA policy per role; wrong second factors count towards the lockout) |
| TH-02 | S | Session hijacking | Secure/HttpOnly/SameSite=Strict cookies, server-side sessions, rotation, idle/absolute timeouts | M2/M11 | Mitigated (AT-F08-03; M11: destructive and security-relevant actions need a step-up within 10 minutes) |
| TH-03 | T | CSRF on state-changing endpoints | CSRF token + Origin check; SameSite cookies | M2 | Mitigated (AT-F08-04) |
| TH-04 | T/E | XSS in dashboard (e.g. container names, logs, file previews) | React escaping, strict CSP, no `dangerouslySetInnerHTML`, attachment disposition for untrusted files | M5/M10 | Mitigated (M5: strict CSP without unsafe-inline, React escaping only, dangerouslySetInnerHTML banned in CI; M10: file content only as attachment with sandbox CSP and nosniff, previews as text, images by content sniffing without SVG) |
| TH-05 | I | Core reachable directly from the network, bypassing Caddy | Loopback-only bind enforced in config validation; Caddy proxies the Core only for its configured host (M12) | M1/M12 | Mitigated (AT-F00-01) |
| TH-06 | D | Slowloris / large bodies / request floods | Server timeouts, header/body limits, rate limits | M1/M2 | Partially mitigated (M1: timeouts, body limit; M2: auth rate limits) |
| TH-07 | I | Error responses leak internals (stack traces, SQL) | Uniform error model; panics recovered and logged with request ID only | M1 | Mitigated (AT-F00-04) |
| TH-08 | S | Host header / proxy header spoofing (`X-Forwarded-For`) | Trust forwarded headers only from configured proxy (loopback Caddy) | M2 | Mitigated (forwarded header trusted only from loopback proxy; ClientIP tests) |
| TH-09 | E | Missing authorization on a new route | Deny-by-default router; route permission registry with enumeration test | M2 | Mitigated (AT-F09-01: access required at registration, contract + RBAC matrix tests) |
| TH-10 | S | First-run setup takeover (someone else creates the owner) | One-time setup token printed to journal, expiring, single-use | M2 | Mitigated (AT-F08-01) |
| TH-11 | E/T | Core compromise turns Caddy into a file server or open proxy, or moves its admin API to TCP | Caddy configured only by the proxy service, which builds the whole JSON from typed, validated routes; admin socket fixed and reachable only by the proxy service; upstreams only loopback 1024–65535 | M12 | Mitigated (ADR-0025; `internal/proxy` tests, CI job `proxy`) |
| TH-12 | S | Spoofed identity header to an app behind the sign-in gate | `X-Kernhaven-User` deleted on every route before anything else; set only from the Core's forward-auth answer | M12 | Mitigated (real-Caddy test incl. mutation check) |
| TH-13 | S/T | Open redirect or code theft in the sign-in gate | Return address bound to the route's host, port and prefix; one-time codes (60 s, hashed, bound to session and route); callback only on the route's host; internal endpoints 404 on the Kernhaven host | M12 | Mitigated (`TestProxyGate` incl. mutation checks) |
| TH-14 | I | A route exposes a loopback-only service by accident, or an app stays reachable around the proxy | Ports below 1024, the Core's and Caddy's ports refused; LAN-only default for app routes; every change audited and behind step-up; direct app ports remain open (documented) | M12 | Partially mitigated |
| TH-15 | I | Theft of private keys, the ACME account key or DNS credentials | Encrypted with the Core's key (ADR-0019); never in API responses or logs; keys reach only the proxy service, only for Caddy | M13 | Mitigated (`TestTLS`, mutation check) |
| TH-16 | T | A wrong, broken or foreign certificate is served | Validated in the Core (chain, key, validity, purpose, signatures) and again in the proxy service (parse, key, host); one certificate per host selected by SNI | M13 | Mitigated (`TestValidateUpload`, `TestBuildTLS`, real Caddy) |
| TH-17 | S/T | The Core points Caddy at a foreign ACME CA or obtains certificates for foreign names | CA chosen by the proxy service from Let's Encrypt only; ACME only for hosts with routes; DNS-01 only in zones the token can edit; every issuance audited | M13 | Mitigated |
| TH-18 | D | Monitoring exhausts disk, CPU or the Docker daemon | Sampling interval 5–60 s, 300-series cap, retention pruning (bounded at about 25 MB), one stats call per running container with a timeout; the monitor role has no capabilities and no IP traffic | M14 | Mitigated (`TestMetricsHistory`, ADR-0027) |
| TH-19 | S/I | The Core is used to reach internal endpoints (SSRF) through notification channels | Owners/admins with step-up only; loopback, link-local (metadata), unspecified and multicast refused on save and at every connection; no redirects; bounded responses (ADR-0028) | M15 | Mitigated (`TestGuard`, live check) |
| TH-60 | D | Alert floods hide real problems or exhaust a channel | Deduplication per alert (code and unique index), 20 deliveries per channel and hour, drops recorded | M15 | Mitigated (`TestDelivery`) |

### TB-3 — Core ↔ Agent

| ID | STRIDE | Threat | Mitigation | MS | Status |
|---|---|---|---|---|---|
| TH-20 | E | Compromised Core (T6) runs arbitrary host commands | No generic exec operation; typed allow-listed operations only | M4 | Mitigated (AT-M4-01: pinned allow-list of typed operations, no exec or passthrough) |
| TH-21 | E | Compromised Core requests privileged containers or host mounts | Agent-side container policy; exceptions require Owner-signed approval with a key not held by Core at rest | M4/M6 | Partially mitigated (M6: agent re-evaluates policy; exceptions owner-only, reasoned, audited, labelled; signing exceptions outside the Core planned with M11) |
| TH-22 | S | Local user (T8) connects to the agent socket | Socket mode 0660 owned by agent group with only `kernhaven` member; `SO_PEERCRED` check | M4 | Mitigated (AT-M4-02: socket 0660 + SO_PEERCRED allow-list) |
| TH-23 | T/R | Replay of a captured grant | Grants bound to operation+target, short expiry, nonce cache | M4 | Mitigated (AT-M4-03/04: Ed25519 grants bound to op and params hash, 60 s lifetime, nonce cache) |
| TH-24 | D | Malformed requests crash the agent | Strict decoding, size limits, fuzzing in CI | M4 | Mitigated (AT-M4-05: strict decoding, 64 KiB limit, timeouts; fuzzing in CI) |
| TH-25 | E | The exec console is used to reach the host | Only sh/bash (no command from the API) in managed running containers; agent refuses privileged, host-PID and Docker-socket containers; container's own user; owner/admin with step-up; bound to the opening browser session; 2 per user, 15 min idle, 1 h; audited without content (ADR-0031) | M6b | Mitigated (`TestCheckExec`, `TestM6bConsoleAndFollow`, `TestConsoleThroughCore`) |
| TH-26 | I/D | Long-lived streams outlive a sign-out or exhaust the Core | Event streams end after 5 min and re-authenticate; listener cap; one shared poller; console and log-follow time limits | M6b | Mitigated (`TestLiveEventsAndLogFollow`) |

### TB-4/TB-5 — Host resources and containers

| ID | STRIDE | Threat | Mitigation | MS | Status |
|---|---|---|---|---|---|
| TH-30 | E | Container escape via privileged mode, host namespaces, dangerous capabilities or `docker.sock` mount | Policy engine denies by default; explicit, audited exceptions | M6/M7 | Mitigated for single containers (M6, AT-F02-04: deny-by-default policy in Core and agent; Docker socket and system paths never exemptible); Compose in M7 |
| TH-31 | T | Path traversal / symlink escape in file manager, mounts, Compose bind mounts | Allow-listed roots, `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`, canonicalisation tests | M7/M9/M10 | Mitigated for the file manager and mounts (M9: mount points only as single names below the mount root; M10: every file operation through os.Root / openat2 RESOLVE_BENEATH in a separate file service, ADR-0023); Compose bind mounts resolved with EvalSymlinks (M6) |
| TH-32 | D | Formatting or unmounting the system disk | System disk detection; never offered; typed confirmation; agent refuses | M9 | Mitigated (M9: the storage service classifies every disk on every request and refuses the system disk, disks in use and disks whose identity changed before running any tool; typed confirmation and password in the Core; never retried; separate root service with its own allow-list, ADR-0022) |
| TH-33 | I | App containers reach Core/agent | Core loopback only, agent unix socket only; Docker networks isolated per stack | M6 | Mitigated for stacks (M7: every stack gets its own default network; services join only declared networks; one network per service) |
| TH-34 | E | Shell/argument injection in host operations | No shell invocation; `exec` with argument arrays; typed parameters validated against patterns | M4 | Mitigated for M4 operations (no process execution; Docker API calls only with validated, path-escaped references) |
| TH-35 | T | Kernhaven modifies firewall or SSH and locks the user out | Out of scope by policy; agent has no such operations | — | Mitigated by design |

### TB-6 — External content and supply chain

| ID | STRIDE | Threat | Mitigation | MS | Status |
|---|---|---|---|---|---|
| TH-40 | T | Malicious catalog entries (T5) | Signed catalogs; per-source trust keys; policy check of every app | M8 | Mitigated (M8, ADR-0020: Ed25519-signed catalogs, one trust key per source set by an owner, rollback and freeze protection, strict parsing; every app is evaluated by the container policy and its privileges are shown before install; exceptions need an owner) |
| TH-41 | T | Image tag replaced upstream | Digest pinning; update shows digest change | M6/M8 | Partially mitigated (M6: pulls record the resolved digest, UI warns about unpinned images; M8: the update page lists changed images and flags unpinned ones; catalogs are not required to pin digests) |
| TH-42 | S | SSRF via Compose URL import, webhooks, catalog URLs | HTTPS-only, block private/loopback/link-local ranges unless explicitly allowed, size/time limits | M7/M15 | Mitigated for Compose URL import (M7: HTTPS only, dialer refuses non-public addresses after DNS resolution and on redirects, size and time limits); webhooks in M15 |
| TH-43 | T | Tampered release or upgrade (T7) | minisign-signed SHA256SUMS with an offline key; keys pinned in /etc/kernhaven/release-keys; verification before any change (ADR-0013, ADR-0032) | M18 | Partially mitigated (verification implemented and tested; the owner's release key does not exist yet, B-3 — upgrades fail closed) |
| TH-45 | E/T | The installer weakens the host or changes unrelated packages | No firewall, SSH or unrelated package changes; configuration written only where missing; services keep their sandboxing | M18 | Mitigated (CI package job compares host state before and after) |
| TH-44 | T | Compromised CI action or dependency | Actions pinned by SHA, `govulncheck`, minimal dependencies, `go.sum` verification | M0 | Mitigated (ADR-0014) |

### Data protection

| ID | STRIDE | Threat | Mitigation | MS | Status |
|---|---|---|---|---|---|
| TH-50 | I | Theft of backups | Client-side authenticated encryption (STREAM, AES-256-GCM); data key wrapped with Argon2id(passphrase), passphrase never stored; no stack or volume names in object paths (ADR-0029) | M16 | Mitigated (`TestRepoHeader`, `TestBackupAndRestoreThroughCore`: no plaintext on the target) |
| TH-55 | T | A damaged or tampered backup is restored | Every segment authenticated before use; manifest bound to repository and snapshot; restores keep the current data until the stack is healthy; scheduled verification reports damaged and deleted snapshots | M16 | Mitigated (`TestStreamTamper`, `TestRepoObjects`, failed restore puts data back) |
| TH-56 | I/T | A compromised Core uses backup operations to read or overwrite other data | The agent exports/imports only volumes labelled for the named stack (no snapshot copies, no unmanaged volumes); archives filtered in both directions (no `..`, absolute names, paths below links, devices) (ADR-0030) | M16 | Mitigated (`TestFilterTar`, `TestM16VolumeExportImport`) |
| TH-57 | S/I | SSRF or credential theft through backup targets | Address guard (ADR-0028) for SFTP and S3; SFTP host keys pinned after fingerprint comparison; local repositories only below configured roots via `os.Root`; credentials sealed and write-only; step-up | M16 | Mitigated (`TestSFTPTarget`, `TestS3Target`, `TestLocalTarget`) |
| TH-51 | I | Secrets readable from DB file or logs | Secrets encrypted at rest with a key in a separate file (0600); log redaction | M2/M7 | Mitigated for stack variables and app secrets (M7/M8, ADR-0019: AES-256-GCM at rest, write-only, generated app secrets never leave the server) |
| TH-52 | R | Admin hides actions by editing the audit log | Hash-chained audit log; chain verification; verifiable JSON Lines exports kept elsewhere and `kernhaven-core audit-check` (continuation between exports) | M2/M17 | Partially mitigated (M2: hash chain + append-only triggers; M17: tail truncation detected against a kept export; no automatic remote sink) |
| TH-53 | T | Database corruption after crash/power loss | WAL + `synchronous=FULL`; integrity check on startup; journaled jobs | M1/M3 | Partially mitigated (M1: WAL, FULL sync; M3: journaled jobs with SIGKILL recovery tests; VM power-loss test blocked by B-2) |
| TH-54 | I | Data directory readable by other local users (T8) | Startup refuses data dir with group/other permissions | M1 | Mitigated (AT-F00-01) |

## 5. Accepted risks (current)

| ID | Risk | Rationale |
|---|---|---|
| AR-01 | The agent's Docker access is root-equivalent | Inherent to managing Docker; contained by ADR-0003 controls and agent minimalism |
| AR-02 | A compromised Core can request any allow-listed agent operation within policy | Policy-enforcing agent limits impact. M11 enforces step-up for destructive actions in the Core; binding agent grants to a step-up is not implemented, so a compromised Core is not limited by it |


## 6. Review for 1.0 (M19, 2026-10-29)

Every threat was reviewed against its row above. All are **Mitigated**
except the ones below, which are partially mitigated. Accepting a residual
risk is the owner's decision; until the owner decides, each stays open and
the 1.0 gate box "all threats Mitigated or Accepted with rationale" stays
unchecked.

| ID | Residual risk | Proposed decision | Rationale |
|---|---|---|---|
| TH-06 | Request floods beyond the sign-in rate limits (e.g. many valid sessions) | Accept | A homelab platform behind Caddy on a LAN; Caddy and the router are the place for volumetric limits; server timeouts and body limits are in place |
| TH-14 | Apps' published Docker ports stay reachable around the proxy | Accept (documented) | Publishing ports is the user's choice in the Compose file; the UI shows published ports; closing them would need firewall management, which is out of scope (CLAUDE.md) |
| TH-21 | Exceptions are approved in the Core; a compromised Core could forge one | Needs work or acceptance | Signing exceptions with an owner key outside the Core (planned since M6) is not implemented; the agent re-evaluates policy, exceptions are owner-only, reasoned and audited |
| TH-41 | Catalogs need not pin image digests | Accept | Digests are recorded and changes shown at update time; catalogs from untrusted sources are refused by signature (TH-40) |
| TH-43 | No release key exists yet | Blocked by B-3 | Verification is implemented and fails closed; the key ceremony is the owner's |
| TH-52 | No automatic remote log sink | Accept for 1.0 | Verifiable exports and `audit-check` detect truncation against kept exports; a remote sink is a feature for a later version |
| TH-53 | Power loss not tested on real hardware or VMs | Blocked by B-2 | SQLite WAL with FULL sync, integrity check at start and SIGKILL recovery tests exist; the VM power-loss test needs B-2 |

## 7. Review log

| Date | Milestone | Change |
|---|---|---|
| 2026-10-27 | M0/M1 | Initial model; TH-05, TH-07, TH-54 mitigated by M1 |
| 2026-10-27 | M2 | TH-02, TH-03, TH-08, TH-09, TH-10 mitigated; TH-01, TH-06, TH-52 partially |
| 2026-10-27 | M3–M5 | TH-04 partially (CSP), TH-53 partially (journaled jobs) |
| 2026-10-27 | M4 | TH-20, TH-22, TH-23, TH-24, TH-34 mitigated |
| 2026-10-27 | M6 | TH-30 mitigated for single containers; TH-21, TH-31, TH-33, TH-41 partially |
| 2026-10-27 | M7 | TH-42 (Compose URL import), TH-51 (stack variables), TH-33 (stacks) mitigated |
| 2026-10-27 | M8 | TH-40 mitigated (signed catalogs); TH-41 update diff; TH-51 app secrets; new agent operation volumes.copy (ADR-0021) |
| 2026-10-28 | M9 | TH-32 mitigated; new privilege domain: root storage service with its own allow-list (ADR-0022); mount points only below the mount root, nosuid,nodev |
| 2026-10-28 | M10 | TH-31 mitigated for files (os.Root in a separate root file service); TH-04 mitigated for file content; stream endpoint in the agent protocol (ADR-0023) |
| 2026-10-28 | M11 | TH-01 mitigated (MFA, passkeys, policy); TH-02 extended by step-up; AR-02 rationale corrected (no step-up-bound agent grants yet) |
| 2026-10-28 | M12 | New TH-11…TH-14 (reverse proxy, sign-in gate); TH-11–TH-13 mitigated, TH-14 partially; fourth privilege domain: proxy service, the only client of Caddy's admin socket (ADR-0025) |
| 2026-10-28 | M13 | New TH-15…TH-17 (certificates); TB-6 now includes Let's Encrypt and the Cloudflare API, both fixed endpoints (ADR-0026) |
| 2026-10-29 | M14 | New TH-18 (resource use of monitoring), mitigated; fifth privilege domain: monitor service, read-only host counters (ADR-0027) |
| 2026-10-29 | M15 | New TH-19 (SSRF through channels) and TH-60 (alert floods; first numbered TH-20, which M4 already used — corrected in M16), mitigated; TB-6 now includes notification endpoints (ADR-0028) |
| 2026-10-29 | M16 | TH-50 mitigated; new TH-55 (tampered backups), TH-56 (backup operations of a compromised Core), TH-57 (backup targets), mitigated; TB-6 includes backup targets (ADR-0029, ADR-0030); M15's alert-flood threat renumbered TH-60 |
| 2026-10-29 | M17 | TH-52: verifiable exports and continuation check detect tail truncation against a kept export (still partial: no automatic remote sink); the security dashboard surfaces MFA gaps, open routes, exceptions and a broken chain |
| 2026-10-29 | M6b | New TH-25 (exec console) and TH-26 (long-lived streams), mitigated; TH-20 still holds: the console starts only sh or bash, never a command from the API (ADR-0031) |
| 2026-10-29 | M18 | TH-43 partially mitigated (verification in place, key ceremony open, B-3); new TH-45 (installer side effects), mitigated |
| 2026-10-29 | M19 | Review for 1.0 (section 6): all other threats mitigated; TH-06, TH-14, TH-41, TH-52 proposed for acceptance, TH-21 needs work or acceptance, TH-43 and TH-53 blocked by B-3 and B-2 — owner decision pending |
