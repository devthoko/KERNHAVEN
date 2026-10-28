-- Passkeys, TOTP, recovery codes, MFA policy and step-up (M11).

-- 0 = passkey-only account: the password cannot be used to sign in.
ALTER TABLE users ADD COLUMN password_login INTEGER NOT NULL DEFAULT 1 CHECK (password_login IN (0, 1));
-- Random WebAuthn user handle, created with the first passkey.
ALTER TABLE users ADD COLUMN webauthn_id BLOB;

-- When the session's second factor or passkey was verified (0 = password only),
-- when it was last authenticated strongly (sign-in or step-up), and whether it
-- may only enrol a second factor (MFA required by policy, none enrolled).
ALTER TABLE sessions ADD COLUMN mfa_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN step_up_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN enrollment_only INTEGER NOT NULL DEFAULT 0 CHECK (enrollment_only IN (0, 1));

CREATE TABLE user_totp (
    user_id    INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    secret     BLOB    NOT NULL,                 -- AES-256-GCM (ADR-0019)
    confirmed  INTEGER NOT NULL DEFAULT 0 CHECK (confirmed IN (0, 1)),
    last_step  INTEGER NOT NULL DEFAULT 0,       -- replay protection
    created_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE user_recovery_codes (
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT    NOT NULL,                  -- SHA-256 of the normalized code
    used_ms   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, code_hash)
) STRICT;

CREATE TABLE user_passkeys (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id BLOB    NOT NULL UNIQUE,
    name          TEXT    NOT NULL,
    credential    TEXT    NOT NULL,              -- JSON of the verified credential
    created_ms    INTEGER NOT NULL,
    last_used_ms  INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX user_passkeys_user ON user_passkeys (user_id);

-- Pending sign-in, step-up and passkey ceremonies. id is the SHA-256 of the
-- token handed to the browser.
CREATE TABLE auth_challenges (
    id         TEXT    PRIMARY KEY,
    user_id    INTEGER REFERENCES users (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL,
    data       TEXT    NOT NULL DEFAULT '',
    attempts   INTEGER NOT NULL DEFAULT 0,
    expires_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE mfa_policy (
    role     TEXT    PRIMARY KEY CHECK (role IN ('owner', 'admin', 'operator', 'viewer')),
    required INTEGER NOT NULL CHECK (required IN (0, 1))
) STRICT;
