-- Monitoring history (M14, ADR-0027): 1-minute points for 24 hours and
-- 15-minute points for 7 days, at most 300 series.

CREATE TABLE metric_series (
    id      INTEGER PRIMARY KEY,
    key     TEXT    NOT NULL UNIQUE,     -- e.g. host.cpu, container.web.memory
    unit    TEXT    NOT NULL,
    last_ms INTEGER NOT NULL            -- last point; series idle for 7 days are deleted
) STRICT;

CREATE TABLE metric_points (
    series_id  INTEGER NOT NULL REFERENCES metric_series (id) ON DELETE CASCADE,
    resolution INTEGER NOT NULL CHECK (resolution IN (60, 900)),   -- seconds
    ts         INTEGER NOT NULL,                                  -- bucket start, ms
    avg        REAL    NOT NULL,
    max        REAL    NOT NULL,
    PRIMARY KEY (series_id, resolution, ts)
) STRICT, WITHOUT ROWID;
