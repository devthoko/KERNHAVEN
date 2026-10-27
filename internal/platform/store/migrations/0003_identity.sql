-- Users, sessions and first-run setup (M2). Times are Unix milliseconds (UTC).
CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE,
    display_name    TEXT    NOT NULL DEFAULT '',
    role            TEXT    NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'viewer')),
    password_hash   TEXT    NOT NULL,
    disabled        INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until_ms INTEGER NOT NULL DEFAULT 0,
    created_ms      INTEGER NOT NULL,
    updated_ms      INTEGER NOT NULL
) STRICT;

CREATE TABLE sessions (
    id                  TEXT    PRIMARY KEY,          -- public identifier
    token_hash          TEXT    NOT NULL UNIQUE,      -- SHA-256 of the cookie token
    user_id             INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token          TEXT    NOT NULL,
    created_ms          INTEGER NOT NULL,
    last_seen_ms        INTEGER NOT NULL,
    idle_expires_ms     INTEGER NOT NULL,
    absolute_expires_ms INTEGER NOT NULL,
    ip                  TEXT    NOT NULL,
    user_agent          TEXT    NOT NULL
) STRICT;

CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE setup_token (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    token_hash TEXT    NOT NULL,
    expires_ms INTEGER NOT NULL
) STRICT;
