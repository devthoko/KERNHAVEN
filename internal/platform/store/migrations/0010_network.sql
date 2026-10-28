-- Reverse proxy routes and the Kernhaven sign-in gate (M12).

CREATE TABLE proxy_routes (
    id            INTEGER PRIMARY KEY,
    host          TEXT    NOT NULL,
    path_prefix   TEXT    NOT NULL DEFAULT '',
    strip_prefix  INTEGER NOT NULL DEFAULT 0 CHECK (strip_prefix IN (0, 1)),
    upstream_port INTEGER NOT NULL CHECK (upstream_port BETWEEN 1024 AND 65535),
    app           TEXT,                              -- installed app the route belongs to
    sso           INTEGER NOT NULL DEFAULT 0 CHECK (sso IN (0, 1)),
    sso_min_role  TEXT    NOT NULL DEFAULT 'viewer' CHECK (sso_min_role IN ('owner', 'admin', 'operator', 'viewer')),
    lan_only      INTEGER NOT NULL DEFAULT 0 CHECK (lan_only IN (0, 1)),
    allow_cidrs   TEXT    NOT NULL DEFAULT '[]',     -- JSON array of canonical prefixes
    created_by    TEXT    NOT NULL,
    created_ms    INTEGER NOT NULL,
    updated_ms    INTEGER NOT NULL,
    UNIQUE (host, path_prefix)
) STRICT;

CREATE INDEX proxy_routes_app ON proxy_routes (app);

-- Last apply: what Caddy runs (hash, for the Kernhaven host it was built
-- for) and the last error. Route IDs come from next_id and are never reused:
-- an ID is taken before Caddy sees the route, the row is written after.
CREATE TABLE proxy_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    next_id    INTEGER NOT NULL DEFAULT 1,
    hash       TEXT    NOT NULL DEFAULT '',
    kh_host    TEXT    NOT NULL DEFAULT '',
    applied_ms INTEGER NOT NULL DEFAULT 0,
    https_port INTEGER NOT NULL DEFAULT 443,
    error      TEXT    NOT NULL DEFAULT '',
    error_ms   INTEGER NOT NULL DEFAULT 0
) STRICT;
INSERT INTO proxy_state (id) VALUES (1);

-- One-time codes that carry a Kernhaven session to an app's host (60 s).
CREATE TABLE proxy_gate_codes (
    code_hash  TEXT    PRIMARY KEY,                   -- SHA-256 of the code
    route_id   INTEGER NOT NULL REFERENCES proxy_routes (id) ON DELETE CASCADE,
    session_id TEXT    NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    expires_ms INTEGER NOT NULL
) STRICT;

-- Gate cookies on app hosts; they end with the Kernhaven session.
CREATE TABLE proxy_gate_sessions (
    token_hash TEXT    PRIMARY KEY,                   -- SHA-256 of the cookie value
    route_id   INTEGER NOT NULL REFERENCES proxy_routes (id) ON DELETE CASCADE,
    session_id TEXT    NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    created_ms INTEGER NOT NULL
) STRICT;
CREATE INDEX proxy_gate_sessions_session ON proxy_gate_sessions (session_id);
