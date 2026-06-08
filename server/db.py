"""
BRAHMASTRA — PostgreSQL Database Layer (asyncpg)

Tables: scans, findings, scan_events

All functions are async. The connection string is read from
`server.config.BRAHMASTRA_DB_URL`. A single module-level `asyncpg.Pool` is
created by `init_db()` (called from the FastAPI lifespan startup hook)
and torn down by `close()`.

Schema changes live in `server/migrations/*.sql` and are applied on startup
by `_apply_migrations()`, tracked in an `_migrations` bookkeeping table.
No external migration tool required.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import asyncpg

from server.config import BRAHMASTRA_DB_URL

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

_pool: Optional[asyncpg.Pool] = None


# ── Pool lifecycle ────────────────────────────────────────────────────────────

async def _init_codecs(conn: asyncpg.Connection) -> None:
    """
    Register a JSONB codec on each connection so Python `dict` values are
    serialised transparently when writing JSONB columns, and deserialised on
    read. Without this, asyncpg would hand back `str` for JSONB columns.
    """
    await conn.set_type_codec(
        "jsonb",
        encoder=json.dumps,
        decoder=json.loads,
        schema="pg_catalog",
    )


async def init_db() -> None:
    """Create the connection pool (if not already created) and apply migrations."""
    global _pool
    if _pool is not None:
        return
    _pool = await asyncpg.create_pool(
        BRAHMASTRA_DB_URL,
        min_size=4,
        max_size=20,
        command_timeout=10,
        init=_init_codecs,
    )
    await _apply_migrations()


async def close() -> None:
    """Close the pool. Safe to call multiple times."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


async def _apply_migrations() -> None:
    """
    Apply every *.sql file in server/migrations/ exactly once, in sorted
    order. Applied names are tracked in the `_migrations` table.
    Each file may contain an optional `-- migrate: down` marker; only the
    portion before the marker is executed as the up migration.
    """
    assert _pool is not None
    async with _pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS _migrations (
                name       TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ DEFAULT NOW()
            )
            """
        )

        if not MIGRATIONS_DIR.exists():
            return

        applied = {r["name"] for r in await conn.fetch("SELECT name FROM _migrations")}
        for sql_file in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if sql_file.name in applied:
                continue
            sql_text = sql_file.read_text()
            # Only run the "up" section.
            if "-- migrate: down" in sql_text:
                sql_text = sql_text.split("-- migrate: down")[0]
            async with conn.transaction():
                await conn.execute(sql_text)
                await conn.execute(
                    "INSERT INTO _migrations (name) VALUES ($1)", sql_file.name
                )


def _require_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError(
            "DB pool not initialised — did you forget to call init_db() "
            "in the FastAPI lifespan hook?"
        )
    return _pool


# ── scans ────────────────────────────────────────────────────────────────────

async def create_scan(
    target: str,
    auth_type: str = "none",
    auth_data: Optional[dict] = None,
    scan_profile: str = "full",
) -> str:
    """Insert a new scan row in the running state and return the scan_id."""
    scan_id = f"brm-{uuid.uuid4().hex[:8]}"
    pool = _require_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO scans (id, target, status, auth_type, auth_data,
                               scan_profile, started_at)
            VALUES ($1, $2, 'running', $3, $4, $5, NOW())
            """,
            scan_id,
            target,
            auth_type,
            auth_data or {},
            scan_profile,
        )
    return scan_id


async def get_scan(scan_id: str) -> Optional[dict]:
    """Return a single scan with its findings + per-severity summary, or None."""
    pool = _require_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM scans WHERE id=$1", scan_id)
        if row is None:
            return None
        d = _scan_row_to_dict(row)
        d["summary"] = await _get_summary(conn, scan_id)
        d["findings"] = await _get_findings(conn, scan_id)
    return d


async def list_scans(limit: int = 100) -> list[dict]:
    """
    List scans with per-scan severity counts in a SINGLE query.

    The old SQLite implementation called `_get_summary()` in a Python loop,
    producing an N+1 pattern (1 + 100 queries for a 100-scan dashboard load).
    Here we left-join a GROUPed subquery that builds the summary JSON object
    directly in Postgres, so the dashboard pays one round-trip regardless of
    scan history length.
    """
    query = """
    SELECT s.*,
           COALESCE(f.summary, '{}'::jsonb) AS agg_summary
      FROM scans s
      LEFT JOIN (
        SELECT scan_id,
               jsonb_build_object(
                 'CRITICAL', COUNT(*) FILTER (WHERE severity='CRITICAL'),
                 'HIGH',     COUNT(*) FILTER (WHERE severity='HIGH'),
                 'MEDIUM',   COUNT(*) FILTER (WHERE severity='MEDIUM'),
                 'LOW',      COUNT(*) FILTER (WHERE severity='LOW'),
                 'total',    COUNT(*)
               ) AS summary
          FROM findings
         GROUP BY scan_id
      ) f ON f.scan_id = s.id
     ORDER BY s.started_at DESC
     LIMIT $1
    """
    pool = _require_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, limit)

    result: list[dict] = []
    for row in rows:
        d = _scan_row_to_dict(row)
        agg = row["agg_summary"] or {}
        summary = dict(agg) if isinstance(agg, dict) else {}
        for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            summary.setdefault(k, 0)
        summary.setdefault("total", 0)
        d["summary"] = summary
        d.pop("agg_summary", None)
        result.append(d)
    return result


async def update_scan_status(
    scan_id: str,
    status: str,
    total_requests: Optional[int] = None,
    error: Optional[str] = None,
) -> None:
    """Update scan status + finished_at; optionally total_requests / error."""
    fields: list[str] = ["status=$2", "finished_at=NOW()"]
    values: list[Any] = [scan_id, status]
    next_idx = 3
    if total_requests is not None:
        fields.append(f"total_requests=${next_idx}")
        values.append(total_requests)
        next_idx += 1
    if error is not None:
        fields.append(f"error=${next_idx}")
        values.append(error)
        next_idx += 1
    sql = f"UPDATE scans SET {', '.join(fields)} WHERE id=$1"
    pool = _require_pool()
    async with pool.acquire() as conn:
        await conn.execute(sql, *values)


async def delete_scan(scan_id: str) -> None:
    """Delete a scan; findings + scan_events cascade via ON DELETE CASCADE."""
    pool = _require_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM scans WHERE id=$1", scan_id)


# ── NUL-byte sanitiser (preserves attack intent) ─────────────────────────────
#
# PostgreSQL's text and JSONB encodings reject the literal NUL byte (U+0000)
# — asyncpg raises `CharacterNotInRepertoireError: invalid byte sequence for
# encoding "UTF8": 0x00`. A single NUL in a rule's evidence / payload / body
# column would abort the whole scan.
#
# BUT NUL bytes are themselves a legitimate attack payload (null-byte
# injection for path traversal — e.g. `/etc/passwd%00.jpg` bypassing a
# `.endswith('.jpg')` filter — LDAP injection, log truncation attacks,
# filter-evasion fuzzing, etc.). We absolutely need to keep firing them
# on the wire; only the DATABASE needs them encoded.
#
# Strategy:
#   - The rule engine and httpx layer are untouched. Outgoing attack
#     payloads still travel with real \x00 bytes — that's where the
#     actual attack happens.
#   - Only at the DB persistence boundary (save_finding / save_event)
#     do we walk the finding/event dict and REPLACE every \x00 with the
#     6-char visible marker "\\x00" (literal backslash-x-0-0). The
#     payload history therefore clearly shows "this attack tested a
#     NUL byte" in the dashboard, and the row commits cleanly.
#   - Replacing-not-stripping is the important bit: if we silently
#     dropped NUL bytes, a "%00" finding would look identical to a
#     non-null-byte finding in the UI, and the operator couldn't tell
#     which payload actually triggered the bug.

# Visible marker inserted in place of a real NUL byte when writing to
# Postgres. 6 chars, easy to grep, unambiguous in the dashboard UI.
NUL_MARKER = "\\x00"


def _scrub_nul(obj):
    """
    Recursively replace NUL bytes with the visible textual marker
    `\\x00` so Postgres accepts the row without losing the attack
    payload signal. Safe to call on arbitrarily nested dict/list/str.
    """
    if obj is None:
        return obj
    if isinstance(obj, str):
        # Also handle the JSON-escaped form `\u0000` which Postgres JSONB
        # *also* rejects even though it's valid JSON on paper. Normalise
        # both representations to the visible marker.
        if "\x00" in obj or "\\u0000" in obj:
            return (obj
                    .replace("\x00", NUL_MARKER)
                    .replace("\\u0000", NUL_MARKER))
        return obj
    if isinstance(obj, bytes):
        try:
            return (obj.replace(b"\x00", NUL_MARKER.encode())
                       .decode("utf-8", errors="replace"))
        except Exception:
            return ""
    if isinstance(obj, dict):
        return {k: _scrub_nul(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_scrub_nul(v) for v in obj]
    return obj


# ── findings ─────────────────────────────────────────────────────────────────

async def save_finding(
    scan_id: str,
    finding: dict,
    role: str = "primary",
) -> int:
    """Persist a finding and return its autogenerated BIGSERIAL id.

    Every newly inserted row starts with fp_status='PENDING' so the
    dashboard can render a "pending" badge for the brief window between
    the engine producing the finding and the post-scan FP-analysis
    phase stamping it with a final verdict.

    `role` is the BRAHMASTRA crawl role the finding was observed under
    (``anonymous`` / ``user`` / ``manager`` / ``admin``). Legacy single-role
    scans pass ``'primary'`` (the schema default) and the dashboard treats
    that value as "all roles". The per-finding role is *also* allowed to
    be encoded inside the finding dict itself under the ``role`` key, for
    callers that build findings from structures where the kwarg is
    inconvenient; the kwarg wins when both are present.
    """
    pool = _require_pool()
    # Scrub NUL bytes out of every string field before sending to Postgres.
    # A single 0x00 in evidence/payload/http_trace aborts the whole scan
    # with CharacterNotInRepertoireError otherwise.
    f = _scrub_nul(finding) or {}
    # Allow role to travel inside the finding dict, but the explicit kwarg
    # always wins. Falls back to 'primary' to preserve legacy behaviour.
    resolved_role = role if role and role != "primary" else (
        f.get("role") or "primary"
    )
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO findings
                (scan_id, severity, vuln_type, url, parameter, evidence, cvss,
                 remediation, waf_bypassed, bypass_method, payload,
                 http_trace, think_trace, fp_status, role, timestamp)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW())
            RETURNING id
            """,
            scan_id,
            f.get("severity", "INFO"),
            f.get("type") or f.get("vuln_type", "Unknown"),
            f.get("url", ""),
            f.get("parameter", ""),
            f.get("evidence", ""),
            float(f.get("cvss", 0.0) or 0.0),
            f.get("remediation", ""),
            bool(f.get("waf_bypassed", False)),
            f.get("bypass_method", ""),
            f.get("payload", ""),
            f.get("http_trace", ""),
            f.get("think_trace", ""),
            "PENDING",
            resolved_role,
        )
    return int(row["id"])


# ── crawled_endpoints (multi-role authenticated crawl surface) ───────────────

async def save_crawled_endpoint(
    scan_id: str,
    role: str,
    ep: dict,
) -> None:
    """
    Idempotent upsert of one discovered endpoint into `crawled_endpoints`,
    keyed on (scan_id, role, canonical_key).

    The canonical key comes from
    ``brahmastra/garudastra/crawlers/canonicalizer.py`` so path-templated
    variants (``/user/1`` vs ``/user/2``) collapse into a single row per
    role.

    The second write of the same key updates the response observables
    (``status_code`` + ``content_type``) because the second observation
    is usually "fresher" — e.g. the first hit was a 302 to the login page
    but the retry-after-reauth got the real 200. ``first_seen`` is
    preserved so we keep the original discovery order.
    """
    pool = _require_pool()
    safe_ep = _scrub_nul(ep) or {}
    # ``parameters`` is passed as a plain Python list. The connection-level
    # JSONB codec registered in ``_init_codecs`` calls ``json.dumps`` for us.
    # Do NOT pre-stringify here — doing so produces a JSON-encoded JSON
    # string literal (``"[...]"``) instead of a proper JSON array and
    # downstream ``jsonb_array_length`` / ``->`` accessors fall over.
    params_val = safe_ep.get("parameters") or []
    if not isinstance(params_val, list):
        params_val = []
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO crawled_endpoints
                (scan_id, role, canonical_key, url, method,
                 parameters, source, status_code, content_type)
            VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
            ON CONFLICT (scan_id, role, canonical_key) DO UPDATE
               SET status_code  = EXCLUDED.status_code,
                   content_type = EXCLUDED.content_type,
                   parameters   = CASE
                       WHEN jsonb_array_length(
                           COALESCE(EXCLUDED.parameters, '[]'::jsonb)
                       ) >= jsonb_array_length(
                           COALESCE(crawled_endpoints.parameters, '[]'::jsonb)
                       )
                       THEN EXCLUDED.parameters
                       ELSE crawled_endpoints.parameters
                   END
            """,
            scan_id,
            role or "primary",
            safe_ep.get("canonical_key") or safe_ep.get("url", ""),
            safe_ep.get("url", ""),
            (safe_ep.get("method") or "GET").upper(),
            params_val,
            safe_ep.get("source", "") or "",
            int(safe_ep.get("status_code") or 0),
            safe_ep.get("content_type", "") or "",
        )


async def list_crawled_endpoints(
    scan_id: str,
    role: Optional[str] = None,
) -> list[dict]:
    """
    Return every ``crawled_endpoints`` row for a scan, optionally filtered
    to a single role. Ordered by ``first_seen`` so the dashboard can render
    the discovery timeline in-order. JSONB parameter blobs are decoded to
    Python lists by the connection-level JSONB codec.
    """
    pool = _require_pool()
    async with pool.acquire() as conn:
        if role:
            rows = await conn.fetch(
                """
                SELECT id, scan_id, role, canonical_key, url, method,
                       parameters, source, status_code, content_type,
                       first_seen
                  FROM crawled_endpoints
                 WHERE scan_id=$1 AND role=$2
                 ORDER BY first_seen, id
                """,
                scan_id,
                role,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT id, scan_id, role, canonical_key, url, method,
                       parameters, source, status_code, content_type,
                       first_seen
                  FROM crawled_endpoints
                 WHERE scan_id=$1
                 ORDER BY first_seen, id
                """,
                scan_id,
            )
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        ts = d.get("first_seen")
        if isinstance(ts, datetime):
            d["first_seen"] = ts.isoformat()
        # JSONB codec returned a list already, but defend against legacy
        # string rows just in case.
        params = d.get("parameters")
        if isinstance(params, str):
            try:
                d["parameters"] = json.loads(params)
            except Exception:
                d["parameters"] = []
        elif not isinstance(params, list):
            d["parameters"] = []
        out.append(d)
    return out


async def update_finding_fp(
    finding_id: int,
    fp_status: str,
    fp_confidence: int,
    fp_analysis: dict,
    fp_retest_count: int,
) -> None:
    """
    Patch the four FP-related columns on an existing finding after the
    post-scan FP-analysis phase has reached a verdict for it.

    Called by brahmastra.fp_analyzer.FPAnalyzer once per finding. The
    fp_analysis dict is dumped to JSONB and NUL-scrubbed via the same
    helper as save_finding / save_event so a stray 0x00 inside an AI
    reasoning trace or retest probe payload doesn't abort the row.
    """
    pool = _require_pool()
    safe_analysis = _scrub_nul(fp_analysis) or {}
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE findings
               SET fp_status       = $1,
                   fp_confidence   = $2,
                   fp_analysis     = $3,
                   fp_retest_count = $4
             WHERE id = $5
            """,
            fp_status,
            int(fp_confidence),
            safe_analysis,
            int(fp_retest_count),
            int(finding_id),
        )


# ── scan_events (SSE replay store) ───────────────────────────────────────────

async def save_event(scan_id: str, event_type: str, data: dict) -> None:
    """Append an SSE event to scan_events.data (JSONB)."""
    pool = _require_pool()
    # Scrub NUL bytes from every nested string — JSONB rejects them just
    # like text columns do, and a single 0x00 in a crawl_active url or
    # probe body would crash the scan task via CharacterNotInRepertoireError.
    safe_data = _scrub_nul(data) or {}
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO scan_events (scan_id, event_type, data, timestamp)
            VALUES ($1, $2, $3, NOW())
            """,
            scan_id,
            event_type,
            safe_data,
        )


async def get_events(scan_id: str, after_id: int = 0) -> list[dict]:
    """
    Replay all events for a scan with id > after_id, ordered by id.

    The SSE endpoint in server/api.py interpolates `ev['data']` directly into
    the SSE body as a pre-serialised JSON string, so we re-serialise the dict
    here to preserve the old SQLite layer's return shape. Timestamps are
    returned as ISO strings for the same reason.
    """
    pool = _require_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, scan_id, event_type, data, timestamp
              FROM scan_events
             WHERE scan_id=$1 AND id>$2
             ORDER BY id
            """,
            scan_id,
            after_id,
        )
    out: list[dict] = []
    for r in rows:
        data_val = r["data"]
        if isinstance(data_val, (dict, list)):
            data_str = json.dumps(data_val)
        else:
            data_str = data_val if data_val is not None else "{}"
        out.append(
            {
                "id": r["id"],
                "scan_id": r["scan_id"],
                "event_type": r["event_type"],
                "data": data_str,
                "timestamp": r["timestamp"].isoformat() if r["timestamp"] else "",
            }
        )
    return out


# ── scan_chat_messages (AI guidance chat) ────────────────────────────────────

async def save_chat_message(
    scan_id: str,
    role: str,
    content: str,
    suggested_actions: Optional[list] = None,
    metadata: Optional[dict] = None,
) -> int:
    """
    Persist one turn of the per-scan chat thread and return its BIGSERIAL id.

    role is one of 'user' | 'assistant' | 'system'. suggested_actions is
    the structured list the AI returns (probe/test/reauth actions); it's
    stored as JSONB so the dashboard can render each entry as a clickable
    button without re-parsing text. metadata is a free-form dict for
    future telemetry (tokens used, model, latency) — currently unused
    but reserved so we don't need a schema change later.

    NUL-byte scrub is applied exactly like save_finding / save_event —
    Postgres text+JSONB reject 0x00, and a single one in the model's
    reply would abort the whole INSERT otherwise.
    """
    pool = _require_pool()
    safe_content  = _scrub_nul(content) or ""
    safe_actions  = _scrub_nul(suggested_actions or []) or []
    safe_metadata = _scrub_nul(metadata or {}) or {}
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO scan_chat_messages
                (scan_id, role, content, suggested_actions, metadata, timestamp)
            VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING id
            """,
            scan_id,
            role,
            safe_content,
            safe_actions,
            safe_metadata,
        )
    return int(row["id"])


async def get_chat_history(scan_id: str, limit: int = 200) -> list[dict]:
    """
    Return the full chat thread for a scan, oldest first, as a list of
    {id, role, content, suggested_actions, metadata, timestamp (ISO)}.
    Used both by GET /api/scans/{id}/chat for replay and by the chat
    handler itself to build the multi-turn prompt context.
    """
    pool = _require_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, role, content, suggested_actions, metadata, timestamp
              FROM scan_chat_messages
             WHERE scan_id=$1
             ORDER BY id
             LIMIT $2
            """,
            scan_id,
            limit,
        )
    out: list[dict] = []
    for r in rows:
        ts = r["timestamp"]
        actions = r["suggested_actions"]
        if not isinstance(actions, list):
            # asyncpg JSONB codec returns whatever was stored; coerce.
            actions = []
        meta = r["metadata"]
        if not isinstance(meta, dict):
            meta = {}
        out.append({
            "id":                int(r["id"]),
            "role":              r["role"],
            "content":           r["content"] or "",
            "suggested_actions": actions,
            "metadata":          meta,
            "timestamp":         ts.isoformat() if ts else "",
        })
    return out


# ── Helpers ──────────────────────────────────────────────────────────────────

def _scan_row_to_dict(row: asyncpg.Record) -> dict:
    """Convert a scans row to a plain dict, normalising timestamps and JSONB."""
    d = dict(row)
    for key in ("started_at", "finished_at"):
        val = d.get(key)
        if isinstance(val, datetime):
            d[key] = val.isoformat()
    if d.get("auth_data") is None:
        d["auth_data"] = {}
    if d.get("summary") is None:
        d["summary"] = {}
    return d


async def _get_findings(conn: asyncpg.Connection, scan_id: str) -> list[dict]:
    rows = await conn.fetch(
        "SELECT * FROM findings WHERE scan_id=$1 ORDER BY id", scan_id
    )
    result: list[dict] = []
    for r in rows:
        d = dict(r)
        # Caller code expects the legacy "type" key, not "vuln_type".
        d["type"] = d.pop("vuln_type", "Unknown")
        d["waf_bypassed"] = bool(d.get("waf_bypassed"))
        # `role` is added by migration 004; default to 'primary' for any
        # row that predates the migration.
        d["role"] = d.get("role") or "primary"
        ts = d.get("timestamp")
        if isinstance(ts, datetime):
            d["timestamp"] = ts.isoformat()
        result.append(d)
    return result


async def _get_summary(conn: asyncpg.Connection, scan_id: str) -> dict:
    rows = await conn.fetch(
        "SELECT severity, COUNT(*) AS cnt FROM findings "
        "WHERE scan_id=$1 GROUP BY severity",
        scan_id,
    )
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
    for r in rows:
        sev = (r["severity"] or "INFO").upper()
        if sev in summary:
            summary[sev] = r["cnt"]
        summary["total"] += r["cnt"]
    return summary
