-- BRAHMASTRA — Authenticated crawl persistence.
--
-- Adds the `role` dimension to the crawl pipeline:
--
--   1. findings.role (TEXT, default 'primary')
--      So the same target can be scanned and we can still group / filter
--      findings by the role that observed the issue. The column defaults
--      to 'primary' and the dashboard treats 'primary' as "all roles".
--
--   2. crawled_endpoints (new table)
--      The crawler persists every canonicalised endpoint it sees here,
--      keyed on (scan_id, role, canonical_key) so the rule engine and
--      AuthZ tester can replay the discovered surface without re-walking.
--
-- Schema notes:
--  - `parameters` is JSONB so we can index/query param presence from psql.
--  - `first_seen` is TIMESTAMPTZ for tz-correct reporting.
--  - UNIQUE (scan_id, role, canonical_key) gives us a cheap idempotent
--    upsert target so the persist path can retry without duplicates.
--  - The table references scans(id) ON DELETE CASCADE so deleting a scan
--    sweeps its crawl surface in a single statement.
--  - IF NOT EXISTS / IF EXISTS everywhere so the migration is safe to
--    re-run against partial applies.

-- migrate: up
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'primary';

CREATE INDEX IF NOT EXISTS findings_role_idx
    ON findings (scan_id, role);

CREATE TABLE IF NOT EXISTS crawled_endpoints (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         TEXT        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    role            TEXT        NOT NULL DEFAULT 'primary',
    canonical_key   TEXT        NOT NULL,
    url             TEXT        NOT NULL,
    method          TEXT        DEFAULT 'GET',
    parameters      JSONB       DEFAULT '[]'::jsonb,
    source          TEXT        DEFAULT '',
    status_code     INTEGER     DEFAULT 0,
    content_type    TEXT        DEFAULT '',
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (scan_id, role, canonical_key)
);

CREATE INDEX IF NOT EXISTS crawled_endpoints_scan_role_idx
    ON crawled_endpoints (scan_id, role);

CREATE INDEX IF NOT EXISTS crawled_endpoints_canon_idx
    ON crawled_endpoints (scan_id, canonical_key);

-- migrate: down
DROP INDEX IF EXISTS crawled_endpoints_canon_idx;
DROP INDEX IF EXISTS crawled_endpoints_scan_role_idx;
DROP TABLE IF EXISTS crawled_endpoints;
DROP INDEX IF EXISTS findings_role_idx;
ALTER TABLE findings DROP COLUMN IF EXISTS role;
