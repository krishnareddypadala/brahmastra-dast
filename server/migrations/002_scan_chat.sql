-- BRAHMASTRA — per-scan AI chat guidance store.
--
-- Adds the scan_chat_messages table that backs the "Chat" tab in the
-- dashboard. Each row is one turn in a conversation the operator has
-- with the AI about an ongoing or completed scan: the operator can tell
-- the model to focus on specific URLs, try new payloads, re-authenticate,
-- or explain findings. The AI's reply is persisted alongside the user's
-- prompt so the whole thread reloads cleanly if the browser reopens.
--
-- role:
--   'user'      — message typed by the human operator
--   'assistant' — the AI's reply
--   'system'    — scan-context snapshots injected at the top of a thread
--                 (target, tech stack, findings summary) so future turns
--                 can reuse them without re-serialising the whole scan
--
-- suggested_actions: JSONB array of structured follow-up actions the model
-- wants the user to consider (probe URLs, test parameters with custom
-- payloads, trigger re-authentication, pivot to a specific rule family).
-- Rendered as clickable buttons in the dashboard.

-- migrate: up
CREATE TABLE IF NOT EXISTS scan_chat_messages (
    id                 BIGSERIAL PRIMARY KEY,
    scan_id            TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    role               TEXT NOT NULL,
    content            TEXT NOT NULL,
    suggested_actions  JSONB DEFAULT '[]'::jsonb,
    metadata           JSONB DEFAULT '{}'::jsonb,
    timestamp          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_scan ON scan_chat_messages(scan_id, id);

-- migrate: down
DROP TABLE IF EXISTS scan_chat_messages;
