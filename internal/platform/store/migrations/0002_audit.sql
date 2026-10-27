-- Tamper-evident, append-only audit log (ADR-0016, AT-F10-01/02).
CREATE TABLE audit_events (
    seq        INTEGER PRIMARY KEY,
    ts_ms      INTEGER NOT NULL,
    actor_id   INTEGER NOT NULL,          -- 0 = anonymous or system
    actor      TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    target     TEXT    NOT NULL,
    result     TEXT    NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    request_id TEXT    NOT NULL,
    ip         TEXT    NOT NULL,
    details    TEXT    NOT NULL,          -- canonical JSON object
    prev_hash  TEXT    NOT NULL,
    hash       TEXT    NOT NULL UNIQUE
) STRICT;

CREATE INDEX audit_events_action ON audit_events (action);
CREATE INDEX audit_events_actor ON audit_events (actor);

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
