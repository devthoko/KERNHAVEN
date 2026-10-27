-- Per-user UI preferences (M5, AT-F01-03).
CREATE TABLE user_preferences (
    user_id    INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    theme      TEXT    NOT NULL DEFAULT 'system' CHECK (theme IN ('system', 'light', 'dark')),
    updated_ms INTEGER NOT NULL
) STRICT;
