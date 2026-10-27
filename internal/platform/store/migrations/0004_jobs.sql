-- Persistent jobs with a step journal (M3, AT-F18-01/02). Times are Unix ms.
CREATE TABLE jobs (
    id               INTEGER PRIMARY KEY,
    kind             TEXT    NOT NULL,
    state            TEXT    NOT NULL CHECK (state IN ('queued', 'running', 'compensating', 'succeeded', 'failed', 'cancelled')),
    outcome          TEXT    NOT NULL DEFAULT '' CHECK (outcome IN ('', 'failed', 'cancelled')),
    payload          TEXT    NOT NULL,
    dedupe_key       TEXT,
    created_by       INTEGER NOT NULL,          -- user id, 0 = system
    attempts         INTEGER NOT NULL DEFAULT 0,
    max_attempts     INTEGER NOT NULL CHECK (max_attempts >= 1),
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
    needs_attention  INTEGER NOT NULL DEFAULT 0 CHECK (needs_attention IN (0, 1)),
    error            TEXT    NOT NULL DEFAULT '',
    lease_owner      TEXT    NOT NULL DEFAULT '',
    lease_expires_ms INTEGER NOT NULL DEFAULT 0,
    next_run_ms      INTEGER NOT NULL,
    created_ms       INTEGER NOT NULL,
    updated_ms       INTEGER NOT NULL,
    started_ms       INTEGER NOT NULL DEFAULT 0,
    finished_ms      INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX jobs_claim ON jobs (state, next_run_ms);
CREATE INDEX jobs_finished ON jobs (finished_ms) WHERE finished_ms > 0;
CREATE UNIQUE INDEX jobs_dedupe_active ON jobs (dedupe_key)
    WHERE dedupe_key IS NOT NULL AND state IN ('queued', 'running', 'compensating');

CREATE TABLE job_steps (
    job_id       INTEGER NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    idx          INTEGER NOT NULL,
    name         TEXT    NOT NULL,
    state        TEXT    NOT NULL CHECK (state IN ('pending', 'done', 'compensated')),
    outputs      TEXT    NOT NULL DEFAULT '{}',
    completed_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (job_id, idx)
) STRICT;

CREATE TABLE job_logs (
    id      INTEGER PRIMARY KEY,
    job_id  INTEGER NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    ts_ms   INTEGER NOT NULL,
    level   TEXT    NOT NULL CHECK (level IN ('info', 'warn', 'error')),
    message TEXT    NOT NULL
) STRICT;

CREATE INDEX job_logs_job ON job_logs (job_id, id);
