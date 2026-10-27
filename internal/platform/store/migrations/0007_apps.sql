-- App store sources, catalog entries and installed apps (M8).

-- '' for stacks the user manages, 'app' for stacks of installed apps.
ALTER TABLE stacks ADD COLUMN managed_by TEXT NOT NULL DEFAULT '' CHECK (managed_by IN ('', 'app'));

CREATE TABLE catalog_sources (
    id             INTEGER PRIMARY KEY,
    name           TEXT    NOT NULL UNIQUE,
    url            TEXT    NOT NULL DEFAULT '',      -- '' = upload only
    public_key     TEXT    NOT NULL,                 -- base64 Ed25519 (ADR-0020)
    serial         INTEGER NOT NULL DEFAULT 0,       -- last accepted serial
    payload_sha256 TEXT    NOT NULL DEFAULT '',
    catalog_name   TEXT    NOT NULL DEFAULT '',
    expires_ms     INTEGER NOT NULL DEFAULT 0,
    synced_ms      INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT    NOT NULL DEFAULT '',
    created_by     INTEGER NOT NULL,
    created_ms     INTEGER NOT NULL
) STRICT;

CREATE TABLE catalog_apps (
    source_id  INTEGER NOT NULL REFERENCES catalog_sources (id) ON DELETE CASCADE,
    app_id     TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    version    TEXT    NOT NULL,
    summary    TEXT    NOT NULL,
    categories TEXT    NOT NULL,                     -- JSON array
    entry      TEXT    NOT NULL,                     -- JSON of the verified entry
    PRIMARY KEY (source_id, app_id)
) STRICT;

CREATE TABLE apps (
    stack_id    INTEGER PRIMARY KEY REFERENCES stacks (id) ON DELETE CASCADE,
    source_id   INTEGER REFERENCES catalog_sources (id) ON DELETE SET NULL,
    source_name TEXT    NOT NULL,
    app_id      TEXT    NOT NULL,
    app_name    TEXT    NOT NULL,
    created_by  INTEGER NOT NULL,
    created_ms  INTEGER NOT NULL
) STRICT;

-- The catalog entry each stack revision of an app was created from. The
-- installed version is the one of the deployed revision.
CREATE TABLE app_versions (
    stack_id INTEGER NOT NULL REFERENCES stacks (id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    version  TEXT    NOT NULL,
    entry    TEXT    NOT NULL,
    PRIMARY KEY (stack_id, revision)
) STRICT;
