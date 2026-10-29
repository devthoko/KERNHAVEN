-- M16: encrypted backups (ADR-0029, ADR-0030).

-- A repository on a target. The data key and the credentials are sealed
-- with the Core's secret key; the passphrase is never stored.
CREATE TABLE backup_repos (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL CHECK (kind IN ('local', 'sftp', 's3')),
    config          TEXT NOT NULL,
    secret          BLOB,
    repo_id         TEXT NOT NULL,
    data_key        BLOB NOT NULL,
    verify_schedule TEXT NOT NULL,
    verify_next_ms  INTEGER,
    verify_job      INTEGER,
    verified_ms     INTEGER,
    verify_ok       INTEGER,
    verify_msg      TEXT NOT NULL DEFAULT '',
    created_ms      INTEGER NOT NULL,
    updated_ms      INTEGER NOT NULL
);

CREATE TABLE backup_plans (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    repo       INTEGER NOT NULL REFERENCES backup_repos(id) ON DELETE RESTRICT,
    schedule   TEXT NOT NULL,
    platform   INTEGER NOT NULL,
    stacks     TEXT NOT NULL,      -- JSON list of stack names, ["*"] for all
    quiesce    INTEGER NOT NULL,
    retention  TEXT NOT NULL,      -- JSON Retention
    enabled    INTEGER NOT NULL,
    next_ms    INTEGER,
    last_job   INTEGER,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);

-- Snapshots the Core knows of; the target is the source of truth, this
-- table detects snapshots that disappeared from it (AT-F14-06).
CREATE TABLE backup_snapshots (
    repo        INTEGER NOT NULL REFERENCES backup_repos(id) ON DELETE CASCADE,
    id          TEXT NOT NULL,
    plan        INTEGER,
    plan_name   TEXT NOT NULL DEFAULT '',
    created_ms  INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    objects     INTEGER NOT NULL,
    platform    INTEGER NOT NULL,
    stacks      TEXT NOT NULL,     -- JSON list of stack names
    verified_ms INTEGER,
    verify_ok   INTEGER,
    verify_msg  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (repo, id)
);

-- The Core's own SSH key for SFTP targets (sealed).
CREATE TABLE backup_settings (
    k TEXT PRIMARY KEY,
    v BLOB NOT NULL
);

-- Written by `kernhaven-core restore`: the restored Core brings back the
-- stacks' volumes from this snapshot on its first start.
CREATE TABLE backup_restore_pending (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    repo       INTEGER NOT NULL,
    snapshot   TEXT NOT NULL,
    created_ms INTEGER NOT NULL
);
