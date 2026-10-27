-- Instance identity: one row, created on first start.
CREATE TABLE instance (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    instance_id TEXT    NOT NULL CHECK (length(instance_id) = 32),
    created_at  TEXT    NOT NULL
) STRICT;
