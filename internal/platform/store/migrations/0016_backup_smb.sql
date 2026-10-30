-- SMB file shares as backup targets (ADR-0036).
--
-- SQLite cannot change a CHECK constraint, so the repository table is
-- rebuilt with 'smb' allowed. Its children are rebuilt as well and dropped
-- first: dropping the parent while they exist would run their ON DELETE
-- actions (CASCADE would empty backup_snapshots). Renaming the new parent
-- updates the children's REFERENCES clauses. Rows and ids are kept.

CREATE TABLE backup_repos_new (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL CHECK (kind IN ('local', 'sftp', 's3', 'smb')),
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
INSERT INTO backup_repos_new SELECT id, name, kind, config, secret, repo_id, data_key, verify_schedule, verify_next_ms, verify_job,
    verified_ms, verify_ok, verify_msg, created_ms, updated_ms FROM backup_repos;

CREATE TABLE backup_plans_new (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    repo       INTEGER NOT NULL REFERENCES backup_repos_new(id) ON DELETE RESTRICT,
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
INSERT INTO backup_plans_new SELECT id, name, repo, schedule, platform, stacks, quiesce, retention, enabled, next_ms, last_job,
    created_ms, updated_ms FROM backup_plans;

CREATE TABLE backup_snapshots_new (
    repo        INTEGER NOT NULL REFERENCES backup_repos_new(id) ON DELETE CASCADE,
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
INSERT INTO backup_snapshots_new SELECT repo, id, plan, plan_name, created_ms, size, objects, platform, stacks, verified_ms,
    verify_ok, verify_msg FROM backup_snapshots;

DROP TABLE backup_snapshots;
DROP TABLE backup_plans;
DROP TABLE backup_repos;
ALTER TABLE backup_repos_new RENAME TO backup_repos;
ALTER TABLE backup_plans_new RENAME TO backup_plans;
ALTER TABLE backup_snapshots_new RENAME TO backup_snapshots;
