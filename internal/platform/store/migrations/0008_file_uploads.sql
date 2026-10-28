-- Resumable upload sessions of the file manager (M10). Data is staged by the
-- storage service; this table only tracks who uploads what and how far.
CREATE TABLE file_uploads (
    id         TEXT    PRIMARY KEY,                 -- 32 hex characters
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    root       TEXT    NOT NULL,
    path       TEXT    NOT NULL,
    size       INTEGER NOT NULL CHECK (size >= 0),
    received   INTEGER NOT NULL DEFAULT 0,
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX file_uploads_expires ON file_uploads (expires_ms);
