-- BRAHMASTRA — initial PostgreSQL schema (replaces the SQLite layout in server/db.py pre-PG).
-- Applied once by server/db.py:_apply_migrations() on startup; tracked in _migrations table.

-- migrate: up
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running',
    auth_type       TEXT DEFAULT 'none',
    auth_data       JSONB DEFAULT '{}'::jsonb,
    scan_profile    TEXT DEFAULT 'full',
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    total_requests  INTEGER DEFAULT 0,
    waf_detected    BOOLEAN DEFAULT FALSE,
    waf_vendor      TEXT DEFAULT '',
    summary         JSONB DEFAULT '{}'::jsonb,
    error           TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    severity        TEXT NOT NULL,
    vuln_type       TEXT NOT NULL,
    url             TEXT,
    parameter       TEXT,
    evidence        TEXT,
    cvss            REAL DEFAULT 0.0,
    remediation     TEXT,
    waf_bypassed    BOOLEAN DEFAULT FALSE,
    bypass_method   TEXT DEFAULT '',
    payload         TEXT DEFAULT '',
    http_trace      TEXT DEFAULT '',
    think_trace     TEXT DEFAULT '',
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_events (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,
    data        JSONB DEFAULT '{}'::jsonb,
    timestamp   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_events_scan   ON scan_events(scan_id, id);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);

-- migrate: down
DROP TABLE IF EXISTS scan_events;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scans;
