-- Notifications and alerts (M15, ADR-0028).

CREATE TABLE notify_channels (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    kind       TEXT    NOT NULL CHECK (kind IN ('smtp', 'webhook', 'ntfy', 'gotify')),
    config     TEXT    NOT NULL,          -- JSON without secrets
    secret     BLOB,                      -- encrypted JSON of the secrets
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_by TEXT    NOT NULL,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
) STRICT;

-- One rule per kind; params and channels are JSON.
CREATE TABLE alert_rules (
    rule       TEXT    PRIMARY KEY,
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    params     TEXT    NOT NULL DEFAULT '{}',
    channels   TEXT    NOT NULL DEFAULT '[]',
    updated_ms INTEGER NOT NULL DEFAULT 0
) STRICT;
INSERT INTO alert_rules (rule) VALUES ('service_down'), ('cpu_high'), ('memory_high'), ('disk_full'), ('smart_failed'), ('cert_expiry'), ('job_failed'), ('security');

CREATE TABLE alerts (
    id          INTEGER PRIMARY KEY,
    rule        TEXT    NOT NULL REFERENCES alert_rules (rule),
    key         TEXT    NOT NULL,
    severity    TEXT    NOT NULL CHECK (severity IN ('warning', 'critical')),
    title       TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    state       TEXT    NOT NULL CHECK (state IN ('firing', 'resolved', 'event')),
    fired_ms    INTEGER NOT NULL,
    resolved_ms INTEGER NOT NULL DEFAULT 0
) STRICT;
-- At most one firing alert per rule and key.
CREATE UNIQUE INDEX alerts_firing ON alerts (rule, key) WHERE state = 'firing';
CREATE INDEX alerts_fired ON alerts (fired_ms);

CREATE TABLE notify_deliveries (
    id         INTEGER PRIMARY KEY,
    alert_id   INTEGER REFERENCES alerts (id) ON DELETE CASCADE,    -- NULL for tests
    channel_id INTEGER NOT NULL REFERENCES notify_channels (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('fire', 'resolve', 'test')),
    status     TEXT    NOT NULL CHECK (status IN ('pending', 'sent', 'failed', 'dropped')),
    attempts   INTEGER NOT NULL DEFAULT 0,
    next_ms    INTEGER NOT NULL,
    last_error TEXT    NOT NULL DEFAULT '',
    created_ms INTEGER NOT NULL,
    sent_ms    INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX notify_deliveries_due ON notify_deliveries (status, next_ms);
CREATE INDEX notify_deliveries_channel ON notify_deliveries (channel_id, created_ms);

-- Evaluation cursors (last audit sequence, last job check, …).
CREATE TABLE alert_cursor (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
) STRICT;
