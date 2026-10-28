# M11 — Passkeys, MFA and Step-Up Authentication

Status: Implemented (CI pending); merge pending owner review
Depends on: M2, M5
Acceptance tests: AT-F09-02 … AT-F09-05
Threats addressed: TH-01 (credential stuffing, brute force), TH-02 (session
hijacking: sensitive actions need a fresh proof), AR-02 (partially: a stolen
session alone cannot run destructive actions)

## Factors

| Factor | Details |
|---|---|
| Password | Argon2id (M2); can be switched off for passkey-only accounts |
| TOTP | RFC 6238, SHA-1, 6 digits, 30 s, ±1 step. The secret (160 bit) is encrypted at rest with the secretbox of ADR-0019 (associated data `user:<id>/totp`). The last accepted time step is stored; a code for that step or an earlier one is rejected (**replay protection**). |
| Recovery codes | 10 single-use codes of 10 base32 characters (50 bit), shown once, stored as SHA-256 hashes, regenerated as a set |
| Passkeys | WebAuthn (ADR-0024) with resident keys and **user verification required**; a passkey alone is a complete multi-factor login (possession + PIN/biometric). Usernameless sign-in. Sign counters are checked. |

**Passkey-only accounts** (AT-F09-02): a user with at least one passkey can
switch off password sign-in. The password hash is kept but cannot be used to
sign in until the user switches it back on (with step-up) or an admin resets
the account's MFA.

## Sign-in

1. `POST /auth/login` with username and password. If the account has TOTP or
   passkeys, no session is created: the response carries a short-lived MFA
   challenge (5 minutes, 5 attempts, stored hashed) and the available methods.
2. `POST /auth/login/mfa` with the challenge and a TOTP or recovery code, or
   `…/mfa/passkey/begin|finish` with a passkey of that account → session.
3. `POST /auth/passkey/begin|finish` signs in with a passkey alone.

Wrong second factors count towards the account lockout of M2 and the IP rate
limit applies to every step. Sessions record when the second factor was
verified.

## MFA policy (AT-F09-05)

The owner can require MFA per role (`PUT /auth/mfa-policy`). A user of such a
role without a second factor gets an **enrolment-only session** after the
password: every route except adding a factor, the own session and sign-out
answers `403 mfa_enrollment_required`. Removing a role from the policy is a
downgrade: it needs step-up and is audited as such. The last factor of a user
whose role requires MFA cannot be removed.

## Step-up (AT-F09-04)

A session counts as *recently authenticated* for 10 minutes after sign-in or
after `POST /auth/step-up`. Step-up needs the strongest proof the account
has: a passkey, or password plus TOTP / recovery code; accounts without MFA
use the password (passkey-only accounts a passkey). Actions that need it
answer `403 step_up_required`; the UI asks for the proof and repeats the
request.

| Area | Actions that need step-up |
|---|---|
| Users | create owner/admin, change role, disable, delete, reset password, reset MFA |
| Security | MFA policy, own TOTP/passkeys/recovery codes, password sign-in on/off |
| Apps & catalogs | add/remove a catalog source, approve policy exceptions, remove an app with its data |
| Containers & stacks | create or deploy with policy exceptions |
| Storage & files | format a disk, empty the trash |

Step-up replaces the password re-entry of M8 (app removal) and M9 (format).

## API

| Route | Permission |
|---|---|
| `POST /auth/login/mfa`, `…/login/mfa/passkey/begin`, `…/finish`, `POST /auth/passkey/begin`, `…/finish` | public (rate-limited) |
| `GET /auth/mfa`, `POST /auth/step-up`, `…/step-up/passkey/begin`, `…/finish`, TOTP, recovery codes, passkeys, password sign-in | `self.manage` |
| `GET/PUT /auth/mfa-policy` | `security.manage` (owner) |
| `POST /users/{id}/mfa/reset` | `users.manage` (with the M2 management rules) |

## Acceptance criteria → tests

| AT | Test |
|---|---|
| AT-F09-02 | `TestPasskeys` with a software authenticator in Go (ES256, "none" attestation, own CBOR encoder): register, usernameless sign-in, passkey as second factor, replayed assertion and foreign origin rejected, passkey-only account refuses the password, last passkey protected, step-up with a passkey, audit; E2E with Chrome's virtual authenticator |
| AT-F09-03 | `identity/totp_test.go` (RFC 6238 vectors, recovery code format and hashing); `TestTOTP`: enrolment, no session before the second factor, replay of the same code rejected, next step accepted, recovery code single use, five wrong codes lock the account; E2E with a code computed from the shown secret and sign-in with a recovery code |
| AT-F09-04 | `TestStepUp`: 11 actions (users, policy, own factors, catalog sources, stack exceptions, disk format) answer `step_up_required` after the window, password alone is refused with TOTP, password + code unlocks them, the window expires again; `TestAppRemove`, `TestStorageFormat` use step-up instead of a password; web unit test for the dialog's retry |
| AT-F09-05 | `TestMFAPolicy`: enrolment-only session, last factor protected, downgrade needs step-up and is audited, operators cannot change the policy, admin MFA reset |

## Known limitations

- The TOTP setup shows the key and an `otpauth://` link, no QR code (no new
  dependency for a QR encoder).
- The step-up dialog in the browser is not covered by E2E: the window cannot
  expire inside a run. The server side is covered in Go, the client retry by
  a unit test.
- Passkeys use "none" attestation; there is no trust store for authenticator
  models (ADR-0024).
- Agent grants are not bound to a step-up (AR-02 stays partially mitigated:
  a stolen session within the 10-minute window can still act).
- No e-mail or SMS factors, no remembered devices, no per-user policy (only
  per role).
- A lost last factor needs another owner or admin (`/users/{id}/mfa/reset`);
  a single owner who loses every factor needs the M2 offline reset.

## Verification evidence (2026-10-28, branch `m11-mfa`)

| Check | Environment | Result |
|---|---|---|
| `scripts/check.sh` (Go + web; staticcheck, govulncheck, builds) | `khv01-dev` | Passed |
| `TestTOTP`, `TestMFAPolicy`, `TestStepUp`, `TestPasskeys`, TOTP vectors, step-up versions of `TestAppRemove` and `TestStorageFormat`, contract (112 operations), RBAC | `khv01-dev` | Passed |
| Mutation check: disabling the TOTP `last_step` check lets a code be used twice — `TestTOTP` fails | `khv01-dev` | Passed |
| Mutation check: without the explicit `CloneWarning` check a replayed passkey assertion signs in — `TestPasskeys` fails. Finding: go-webauthn only flags a counter regression, it does not reject it | `khv01-dev` | Passed |
| Live with real binaries: TOTP setup with the shown key, recovery codes shown once, sign-out, password step leads to "Confirm it is you" (desktop and 375 px) | `khv01-dev` | Passed |
| First full CI run (40706483457) | GitHub Actions | Failed: axe `label-content-name-mismatch` on the users page — the "Reset MFA" button was named "Reset second factors of …" (label fixed); all other jobs passed |
| Second full CI run (40717328320) | GitHub Actions | Failed: the E2E sign-in helper's `Sign in` button selector also matched the new "Sign in with a passkey" button (selector made exact); all other jobs passed |
| Third full CI run (40717985129) | GitHub Actions | Failed: E2E `AT-F02-02` — the new container's heading did not appear within 5 s after "Create container". The test and the container code path (no exceptions, no step-up) are unchanged since run 40717328320, where it passed; treated as unexplained, re-run without changes |
| Fourth full CI run (40718605650) | GitHub Actions | Failed: 23 of 24 E2E tests passed (including `AT-F02-02`); in the M11 test the TOTP setup and the passkey registration with the virtual authenticator succeeded, but the check for the passkey's name matched it twice (visible and in the remove button's screen-reader text) — the test now checks the "Remove E2E key" button |
| Fifth full CI run (40719195663) | GitHub Actions | Failed: the browser passkey sign-in succeeded (`/auth/passkey/finish` 200), but the test expected the dashboard; the app correctly returned to `/account` (`?next=` after signing out there) — the test now expects the account page |
| CI full suite incl. browser E2E (TOTP, recovery code, virtual passkey sign-in) | GitHub Actions | pending |
