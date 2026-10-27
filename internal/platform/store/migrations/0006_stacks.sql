-- Compose stacks, immutable revisions and encrypted variables (M7).
CREATE TABLE stacks (
    id                INTEGER PRIMARY KEY,
    name              TEXT    NOT NULL UNIQUE,
    latest_revision   INTEGER NOT NULL DEFAULT 0,
    deployed_revision INTEGER NOT NULL DEFAULT 0,
    status            TEXT    NOT NULL DEFAULT 'new'
                      CHECK (status IN ('new', 'deploying', 'deployed', 'failed', 'stopping', 'stopped')),
    status_message    TEXT    NOT NULL DEFAULT '',
    created_by        INTEGER NOT NULL,
    created_ms        INTEGER NOT NULL,
    updated_ms        INTEGER NOT NULL
) STRICT;

CREATE TABLE stack_revisions (
    stack_id        INTEGER NOT NULL REFERENCES stacks (id) ON DELETE CASCADE,
    number          INTEGER NOT NULL CHECK (number >= 1),
    compose         TEXT    NOT NULL,
    comment         TEXT    NOT NULL DEFAULT '',
    exceptions      TEXT    NOT NULL DEFAULT '[]',   -- JSON: [{service, rule, reason, approved_by}]
    created_by      INTEGER NOT NULL,
    created_by_name TEXT    NOT NULL,
    created_ms      INTEGER NOT NULL,
    PRIMARY KEY (stack_id, number)
) STRICT;

-- Revisions are immutable.
CREATE TRIGGER stack_revisions_no_update BEFORE UPDATE ON stack_revisions
BEGIN
    SELECT RAISE(ABORT, 'stack revisions are immutable');
END;

CREATE TABLE stack_variables (
    stack_id   INTEGER NOT NULL REFERENCES stacks (id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    secret     INTEGER NOT NULL CHECK (secret IN (0, 1)),
    value      BLOB    NOT NULL,                     -- AES-256-GCM (ADR-0019)
    updated_ms INTEGER NOT NULL,
    PRIMARY KEY (stack_id, name)
) STRICT;
