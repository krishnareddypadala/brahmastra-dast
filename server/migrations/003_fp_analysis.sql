-- BRAHMASTRA — Post-scan False-Positive Analysis columns on findings.
--
-- Adds four columns + an index so the FP-analysis phase can stamp every
-- finding with the AI verdict (CONFIRMED / FALSE_POSITIVE / INCONCLUSIVE
-- / PENDING), the AI's confidence, the structured analysis blob (verdict,
-- reason, <think> trace, retest probe results), and the number of retest
-- probes actually fired.
--
-- Schema notes:
--  - fp_status is plain TEXT, not a CHECK enum, so the migration is safe
--    to re-run and so the application can introduce new states without
--    a follow-up migration.
--  - fp_analysis is JSONB so we can index into ai_reason / probes etc.
--    from psql for ad-hoc audits without redeploying the app.
--  - All columns use ADD COLUMN IF NOT EXISTS so the file is idempotent
--    against partial applies.
--
-- See: brahmastra/fp_analyzer.py for the populator, server/api.py for
-- the wire-up between the engine findings loop and update_scan_status.

-- migrate: up
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fp_status        TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fp_confidence    INT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fp_analysis      JSONB;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fp_retest_count  INT DEFAULT 0;

CREATE INDEX IF NOT EXISTS findings_fp_status_idx
    ON findings (scan_id, fp_status);

-- migrate: down
ALTER TABLE findings DROP COLUMN IF EXISTS fp_status;
ALTER TABLE findings DROP COLUMN IF EXISTS fp_confidence;
ALTER TABLE findings DROP COLUMN IF EXISTS fp_analysis;
ALTER TABLE findings DROP COLUMN IF EXISTS fp_retest_count;
DROP INDEX IF EXISTS findings_fp_status_idx;
