"""
BRAHMASTRA Web Dashboard — FastAPI Backend
Serves the dashboard + REST API + SSE live scan feed.

Run: uvicorn server.api:app --host 0.0.0.0 --port 8888 --reload
     (from /home/krishna/brahmastra/)

v2: Engine layer added on top of naive scanner.
    use_engine=True  → ScanEngine (rules + crawler + authz + AI bridge)
    use_engine=False → legacy naive scanner (backward compat)
"""

import asyncio
import json
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator

import httpx
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from server.db import (
    init_db, close as close_db, create_scan, get_scan, list_scans,
    update_scan_status, delete_scan, save_finding, save_event, get_events,
    save_chat_message, get_chat_history,
)
from brahmastra.ai_bridge import AIBridge

# ── App setup ─────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Initialise the asyncpg pool + apply migrations, then mark any orphaned
    'running' scans as failed (server restart recovery). On shutdown, close
    the pool cleanly so no connections are left dangling.
    """
    await init_db()
    for s in await list_scans():
        if s.get("status") == "running":
            await update_scan_status(
                s["id"], "failed",
                error="Server restarted — scan interrupted",
            )
    try:
        yield
    finally:
        await close_db()

app = FastAPI(title="BRAHMASTRA Dashboard", version="0.2.0", lifespan=lifespan)

# Gzip everything over 1 KB — the dashboard HTML alone is 92 KB uncompressed,
# and SSE replay payloads for a completed scan can be ~900 KB. Enabling gzip
# typically drops both by 8–10×, which directly cuts time-to-first-render on
# slow links and shrinks the firehose when a completed scan is reopened.
app.add_middleware(GZipMiddleware, minimum_size=1024)

DASHBOARD_DIR = Path("/home/krishna/brahmastra/dashboard")

# Event types that are pure live-progress noise and have no value during
# replay of a finished scan. Skipping them trims the 3k-event firehose
# down to ~500 meaningful state events and unfreezes the browser.
_LIGHT_REPLAY_SKIP = {
    "probe",          # 2700+ per scan — already summarized in rule_progress
    "crawl_active",   # live current-URL pulse; no persistent meaning
    "concurrency",    # semaphore snapshot
    "rule_progress",  # intermediate counters; final state is in scan summary
}
# On top of _LIGHT_REPLAY_SKIP, completed scans also skip `finding` events
# because the dashboard already loaded them via GET /api/scans/{id}.
_LIGHT_REPLAY_SKIP_COMPLETED = _LIGHT_REPLAY_SKIP | {"finding"}

# Per-scan SSE queues: scan_id → list of asyncio.Queue (one per connected client)
_sse_queues: dict[str, list[asyncio.Queue]] = {}
# Pause flags: scan_id → asyncio.Event (set = running, clear = paused)
_pause_flags: dict[str, asyncio.Event] = {}
# Stop flags: scan_id → bool
_stop_flags: dict[str, bool] = {}
# Engine instances: scan_id → ScanEngine
_engines: dict = {}

# Model backends
MODEL_BACKENDS = {
    "heuristic":     {"type": "none",   "label": "Heuristic Only (No AI)",          "needs_key": False},
    "brahmastra":    {"type": "ollama", "url": "http://localhost:11434/api/chat", "model": "brahmastra:0.3", "label": "BRAHMASTRA 0.3 (32B, cleaned + DAST synth)", "needs_key": False},
    "brahmastra_02": {"type": "ollama", "url": "http://localhost:11434/api/chat", "model": "brahmastra:0.2", "label": "BRAHMASTRA 0.2 (32B, baseline)", "needs_key": False},
    "ollama_llama33":{"type": "ollama", "url": "http://localhost:11434/api/chat", "model": "llama3.3:70b-instruct-q4_0", "label": "Llama 3.3 70B (Ollama)", "needs_key": False},
    "gemini_flash":  {"type": "gemini", "model": "gemini-2.0-flash",              "label": "Gemini 2.0 Flash (Google)",  "needs_key": True},
    "gemini_pro":    {"type": "gemini", "model": "gemini-1.5-pro",                "label": "Gemini 1.5 Pro (Google)",    "needs_key": True},
    "claude_haiku":  {"type": "claude", "model": "claude-haiku-4-5-20251001",     "label": "Claude Haiku (Anthropic)",   "needs_key": True},
    "claude_sonnet": {"type": "claude", "model": "claude-sonnet-4-6",             "label": "Claude Sonnet (Anthropic)",  "needs_key": True},
    "openai_gpt4o":  {"type": "openai", "model": "gpt-4o-mini",                   "label": "GPT-4o Mini (OpenAI)",       "needs_key": True},
}
DEFAULT_BACKEND = "heuristic"

def get_model_cfg(backend: str = DEFAULT_BACKEND) -> dict:
    return MODEL_BACKENDS.get(backend, MODEL_BACKENDS[DEFAULT_BACKEND])


# init_db() is now awaited from the FastAPI lifespan hook above (asyncpg pool
# cannot be created at module import time — there is no running event loop).


# ── Static files ──────────────────────────────────────────────────────────────

# Mount /assets so the dashboard can serve the brahmastra logo, favicon,
# and any future static images. The directory ships in the repo at
# dashboard/assets/. The mount is wrapped in a guard so dev environments
# without an assets dir don't crash on import.
_assets_dir = DASHBOARD_DIR / "assets"
if _assets_dir.is_dir():
    app.mount("/assets", StaticFiles(directory=str(_assets_dir)), name="assets")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index = DASHBOARD_DIR / "index.html"
    return HTMLResponse(index.read_text(encoding="utf-8"))


@app.get("/favicon.ico")
async def serve_favicon():
    """Browsers ask for /favicon.ico unconditionally — serve the PNG logo."""
    from fastapi.responses import FileResponse
    fav = _assets_dir / "brahmastra-logo.png"
    if fav.is_file():
        return FileResponse(str(fav), media_type="image/png")
    return JSONResponse(status_code=404, content={"error": "no favicon"})


# ── Models ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:       str
    auth_type:    str  = "none"
    auth_data:    dict = {}
    scan_profile: str  = "full"          # full | quick | stealth | api_only | auth_only
    cookies:      str  = ""
    username:     str  = ""
    password:     str  = ""
    model_backend:str  = DEFAULT_BACKEND
    api_key:      str  = ""

    # ── Engine v2 fields ──────────────────────────────────────────────────────
    use_engine:   bool = True            # True = use ScanEngine; False = legacy naive scanner
    ai_mode:      str  = "disabled"      # disabled | brahmastra | gemini_flash | claude_haiku | openai
    source_type:  str  = "url"           # url | openapi | postman | har | burp | graphql
    source_content: str = ""             # file content for spec/HAR/Burp import
    authz_testing:  bool = True          # run IDOR + privesc + forced browsing
    scan_depth:     int  = 2             # crawler depth 1–3
    auth_config_full: dict = {}          # full auth config for AuthManager (16 types)
    second_auth_config: dict = {}        # optional second auth for horizontal IDOR

    # ── Concurrency tuning ────────────────────────────────────────────────────
    concurrency_mode: str   = "balanced" # polite | balanced | aggressive | adaptive | fixed
    max_concurrency:  int   = 20         # hard ceiling for adaptive modes; literal in fixed
    request_delay:    float = 0.0        # per-request sleep (default 0; AdaptiveSemaphore handles politeness)


# ── REST API ──────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    """Check all model backends."""
    status = {}
    for key, cfg in MODEL_BACKENDS.items():
        ptype = cfg.get("type", "none")
        if ptype == "none":
            status[key] = {"online": True, "label": cfg["label"], "needs_key": False}
        elif ptype == "ollama":
            try:
                base = cfg["url"].rsplit("/api/", 1)[0]
                want_model = cfg.get("model", "")
                async with httpx.AsyncClient(timeout=8.0) as client:
                    r = await client.get(f"{base}/api/tags")
                if r.status_code == 200 and want_model:
                    # Confirm the specific model is actually registered in this Ollama instance
                    names = [m.get("name", "") for m in r.json().get("models", [])]
                    online = any(n == want_model or n.split(":")[0] == want_model.split(":")[0] for n in names)
                else:
                    online = r.status_code == 200
                status[key] = {"online": online, "label": cfg["label"], "needs_key": False}
            except Exception:
                status[key] = {"online": False, "label": cfg["label"], "needs_key": False}
        else:
            status[key] = {"online": True, "label": cfg["label"], "needs_key": True}
    any_online = any(v["online"] for v in status.values())
    return {"status": "ok", "model_online": any_online, "backends": status}


@app.get("/api/scans")
async def get_scans():
    return await list_scans(limit=100)


@app.get("/api/scans/{scan_id}")
async def get_scan_detail(scan_id: str):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


# ── Per-scan AI guidance chat ─────────────────────────────────────────────────

class ChatRequest(BaseModel):
    """POST /api/scans/{id}/chat body."""
    message:       str
    ai_mode:       str = ""   # override the scan's stored ai_mode for this turn
    api_key:       str = ""   # for commercial backends that need a key


@app.get("/api/scans/{scan_id}/chat")
async def get_scan_chat(scan_id: str):
    """
    Return the full chat thread for this scan, oldest first. Used by the
    dashboard to replay the conversation when the user reopens a scan.
    """
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    messages = await get_chat_history(scan_id)
    return {"scan_id": scan_id, "messages": messages}


@app.post("/api/scans/{scan_id}/chat")
async def post_scan_chat(scan_id: str, req: ChatRequest):
    """
    Send a user message to the per-scan AI guidance chat. Pipeline:

      1. Load the scan so the AI has real context (target, findings,
         tech stack, current status).
      2. Persist the user message so the thread never loses a turn even
         if the AI call crashes.
      3. Build a compact scan-context bundle from what we already have
         in the DB (no extra HTTP to the target — the scan's own event
         stream + findings are enough).
      4. Call AIBridge.chat_guide() with the full prior history + the
         new message. The bridge handles backend dispatch, JSON parsing,
         and action validation.
      5. Persist the assistant reply + any structured suggested_actions.
      6. Return both messages so the dashboard can append them locally
         without a follow-up GET.

    The AI backend is chosen in priority order:
      - req.ai_mode (explicit override sent by the dashboard)
      - scan.auth_data.ai_mode (the mode the scan was started with)
      - "brahmastra" default (local Ollama, no key required)
    The old scan.auth_data dict is also where the api_key for commercial
    backends lives, so if the operator is on a completed scan started
    with Claude + an API key, their chat turns will transparently use
    that same key.
    """
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    user_text = (req.message or "").strip()
    if not user_text:
        raise HTTPException(400, "message must not be empty")

    # 1. Persist the user turn first — we'd rather have a half-completed
    #    thread in the DB than lose the user's prompt if the model call
    #    times out.
    user_id = await save_chat_message(scan_id, "user", user_text)

    # 2. Resolve backend + key.
    auth_data = scan.get("auth_data") or {}
    ai_mode = (req.ai_mode or auth_data.get("ai_mode") or "brahmastra").strip() or "brahmastra"
    api_key = (req.api_key or auth_data.get("api_key") or "").strip()

    bridge = AIBridge(mode=ai_mode, api_key=api_key)
    if not bridge.enabled:
        # Fallback: still persist a placeholder so the UI shows SOMETHING.
        fallback = (
            "AI chat is disabled for this scan (no model backend selected). "
            "Restart the scan with an AI mode (BRAHMASTRA p6, Llama 3.3, "
            "Gemini, Claude, or GPT) to enable guidance."
        )
        asst_id = await save_chat_message(scan_id, "assistant", fallback)
        return {
            "scan_id":   scan_id,
            "user":      {"id": user_id, "role": "user", "content": user_text},
            "assistant": {
                "id":                asst_id,
                "role":              "assistant",
                "content":           fallback,
                "suggested_actions": [],
            },
            "backend": "disabled",
        }

    # 3. Build scan_context from the already-loaded scan + derived endpoint list.
    findings = scan.get("findings") or []
    tech_stack: list[str] = []
    # Try to pull tech_stack out of the events firehose (spider emits it in
    # the crawl_done event). Falls back to [] if we can't find it — cheap
    # scan of the first ~300 events, not a hot path.
    try:
        events = await get_events(scan_id, after_id=0)
        for ev in events[-400:]:  # look at the tail; crawl_done is near end of crawl
            if ev.get("event_type") == "crawl_done":
                payload = ev.get("data")
                try:
                    pj = json.loads(payload) if isinstance(payload, str) else (payload or {})
                except Exception:
                    pj = {}
                ts = pj.get("tech_stack") or []
                if isinstance(ts, list):
                    tech_stack = [str(t) for t in ts]
                    break
    except Exception:
        pass

    # Endpoint sample: unique URLs from findings (cheap, no extra query).
    seen: set[str] = set()
    endpoints: list[str] = []
    for f in findings:
        u = f.get("url") or ""
        if u and u not in seen:
            seen.add(u)
            endpoints.append(u)
        if len(endpoints) >= 20:
            break

    scan_context = {
        "target":     scan.get("target", ""),
        "status":     scan.get("status", ""),
        "profile":    scan.get("scan_profile", ""),
        "tech_stack": tech_stack,
        "summary":    scan.get("summary") or {},
        "findings":   [
            {
                "severity":  f.get("severity"),
                "type":      f.get("type") or f.get("vuln_type"),
                "url":       f.get("url"),
                "parameter": f.get("parameter"),
                "evidence":  (f.get("evidence") or "")[:200],
            }
            for f in findings[:20]
        ],
        "endpoints":  endpoints,
    }

    # 4. Load prior history (excluding the user message we just saved — we
    #    pass it separately via the user_message arg).
    history = await get_chat_history(scan_id)
    history = [h for h in history if h["id"] != user_id]

    # 5. Ask the AI.
    try:
        result = await bridge.chat_guide(
            scan_context = scan_context,
            history      = history,
            user_message = user_text,
        )
    except Exception as e:
        result = {}
        error_reply = f"AI call failed: {str(e)[:300]}"
        asst_id = await save_chat_message(scan_id, "assistant", error_reply)
        return {
            "scan_id":   scan_id,
            "user":      {"id": user_id, "role": "user", "content": user_text},
            "assistant": {
                "id":                asst_id,
                "role":              "assistant",
                "content":           error_reply,
                "suggested_actions": [],
            },
            "backend": ai_mode,
            "error":   str(e)[:300],
        }

    reply_raw = (result.get("reply") or "").strip()
    if not reply_raw or reply_raw == "(no reply)":
        reply = (
            f"The {ai_mode} backend returned an empty response. "
            "This usually means the model timed out or produced "
            "unparseable JSON. Try a shorter prompt, or switch AI "
            "mode to gemini_flash / claude_haiku for faster turnaround."
        )
    else:
        reply = reply_raw
    actions = result.get("suggested_actions") or []

    # 6. Persist + return.
    asst_id = await save_chat_message(
        scan_id, "assistant", reply,
        suggested_actions=actions,
        metadata={"backend": ai_mode, "think_trace_len": len(result.get("think_trace") or "")},
    )
    return {
        "scan_id":   scan_id,
        "user":      {"id": user_id, "role": "user", "content": user_text},
        "assistant": {
            "id":                asst_id,
            "role":              "assistant",
            "content":           reply,
            "suggested_actions": actions,
        },
        "backend": ai_mode,
    }


@app.delete("/api/scans/{scan_id}")
async def remove_scan(scan_id: str):
    await delete_scan(scan_id)
    return {"ok": True}


@app.post("/api/scans")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan. Returns scan_id immediately; scan runs in background."""
    target = req.target.rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target

    scan_id = await create_scan(
        target=target,
        auth_type=req.auth_type,
        auth_data={
            "username":  req.username,
            "password":  req.password,
            "cookies":   req.cookies,
            "ai_mode":   req.ai_mode,
            "api_key":   req.api_key,
            "use_engine": req.use_engine,
            **req.auth_data,
        },
        scan_profile=req.scan_profile,
    )
    _sse_queues[scan_id] = []
    flag = asyncio.Event()
    flag.set()
    _pause_flags[scan_id] = flag
    _stop_flags[scan_id]  = False

    if req.use_engine:
        background_tasks.add_task(run_scan_engine, scan_id, target, req)
    else:
        background_tasks.add_task(run_scan, scan_id, target, req)

    return {"scan_id": scan_id, "status": "running"}


@app.post("/api/scans/{scan_id}/pause")
async def pause_scan(scan_id: str):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan_id in _pause_flags:
        _pause_flags[scan_id].clear()
        await update_scan_status(scan_id, "paused")
        await save_event(scan_id, "paused", {"msg": "Scan paused by user"})
        for q in _sse_queues.get(scan_id, []):
            try: q.put_nowait(("paused", {"msg": "Scan paused by user"}))
            except: pass
    return {"status": "paused"}


@app.post("/api/scans/{scan_id}/resume")
async def resume_scan(scan_id: str):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan_id in _pause_flags:
        _pause_flags[scan_id].set()
        await update_scan_status(scan_id, "running")
        await save_event(scan_id, "resumed", {"msg": "Scan resumed"})
        for q in _sse_queues.get(scan_id, []):
            try: q.put_nowait(("resumed", {"msg": "Scan resumed"}))
            except: pass
    return {"status": "running"}


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    _stop_flags[scan_id] = True
    if scan_id in _pause_flags:
        _pause_flags[scan_id].set()
    # Stop engine if running
    if scan_id in _engines:
        _engines[scan_id].stop()
    await save_event(scan_id, "log", {"msg": "Scan stopped by user", "level": "warn"})
    for q in _sse_queues.get(scan_id, []):
        try: q.put_nowait(("log", {"msg": "Scan stopped by user", "level": "warn"}))
        except: pass
    return {"status": "stopped"}


# ── SSE ───────────────────────────────────────────────────────────────────────

@app.get("/api/scans/{scan_id}/events")
async def scan_events(scan_id: str, request: Request, light: bool = False):
    """
    Server-Sent Events stream for live scan updates.

    Query params:
      light=true — skip high-volume progress events (probe, crawl_active,
                   concurrency, rule_progress, and — for completed scans —
                   finding) during replay. Used by the dashboard when
                   reopening a finished scan, where those events would
                   otherwise flood the browser's main thread (a 369-finding
                   scan emits 3k+ replay events) and trigger the
                   "Page Unresponsive" dialog.
    """
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    is_done = scan["status"] in ("complete", "failed")
    if light:
        skip = _LIGHT_REPLAY_SKIP_COMPLETED if is_done else _LIGHT_REPLAY_SKIP
    else:
        skip = set()

    async def event_stream() -> AsyncGenerator[str, None]:
        past = await get_events(scan_id, after_id=0)
        for ev in past:
            if ev["event_type"] in skip:
                continue
            yield f"event: {ev['event_type']}\ndata: {ev['data']}\n\n"

        if is_done:
            yield "event: done\ndata: {}\n\n"
            return

        q: asyncio.Queue = asyncio.Queue()
        _sse_queues.setdefault(scan_id, []).append(q)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event_type, data = await asyncio.wait_for(q.get(), timeout=25.0)
                    yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
                    if event_type == "done":
                        break
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            if scan_id in _sse_queues and q in _sse_queues[scan_id]:
                _sse_queues[scan_id].remove(q)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Engine Scan Runner (v2) ───────────────────────────────────────────────────

async def run_scan_engine(scan_id: str, target: str, req: ScanRequest):
    import logging; logging.warning(f"run_scan_engine ENTERED: scan={scan_id} target={target} ai={req.ai_mode}")
    """
    Rule engine + crawler + authz scan.
    Runs ScanEngine on top of (and in addition to) the naive scanner.
    """
    from brahmastra.engine import ScanEngine, ScanConfig
    from brahmastra.garudastra.auth.manager import AuthConfig
    logging.warning(f"run_scan_engine IMPORTS OK: {scan_id}")

    async def emit(event_type: str, data: dict):
        logging.warning(f"emit: {event_type}")
        await save_event(scan_id, event_type, data)
        for q in _sse_queues.get(scan_id, []):
            try: q.put_nowait((event_type, data))
            except asyncio.QueueFull: pass

    try:
        await emit("log", {"msg": f"BRAHMASTRA v2 engine started — {target}", "level": "info"})
        await emit("log", {"msg": f"Profile: {req.scan_profile} | AI: {req.ai_mode} | AuthZ: {req.authz_testing}", "level": "info"})
        key_msg = f"present ({len(req.api_key)} chars)" if req.api_key else "NOT SET"
        await emit("log", {"msg": f"AI API key: {key_msg}", "level": "info"})

        # Build AuthConfig from request
        auth_cfg = None
        if req.auth_config_full:
            auth_cfg = AuthConfig(**{k: v for k, v in req.auth_config_full.items() if hasattr(AuthConfig, k)})
        elif req.auth_type != "none":
            auth_cfg = AuthConfig(
                auth_type      = req.auth_type,
                username       = req.username,
                password       = req.password,
                token          = req.auth_data.get("token", ""),
                login_url      = req.auth_data.get("login_url", ""),
                custom_headers = {k: v for k, v in req.auth_data.items() if k not in ("token", "login_url")},
            )
            if req.cookies:
                auth_cfg.token = req.cookies
                auth_cfg.auth_type = "cookie"

        second_auth_cfg = None
        if req.second_auth_config:
            second_auth_cfg = AuthConfig(**{k: v for k, v in req.second_auth_config.items() if hasattr(AuthConfig, k)})

        config = ScanConfig(
            target             = target,
            scan_profile       = req.scan_profile,
            ai_mode            = req.ai_mode,
            ai_api_key         = req.api_key,
            auth_config        = auth_cfg,
            second_auth_config = second_auth_cfg,
            source_type        = req.source_type,
            source_content     = req.source_content,
            authz_testing      = req.authz_testing,
            scan_depth         = req.scan_depth,
            concurrency_mode   = req.concurrency_mode,
            max_concurrency    = req.max_concurrency,
            request_delay      = req.request_delay,
        )

        engine = ScanEngine()
        _engines[scan_id] = engine

        result = await engine.run(scan_id, config, emit_fn=emit)

        # Save all findings to DB and capture (id, dict) pairs so the
        # post-scan FP-analysis phase can update them in place.
        findings_with_ids: list[tuple[int, dict]] = []
        for f in result.findings:
            fdict = {
                "severity":     f.severity,
                "type":         f.vuln_type,
                "url":          f.url,
                "parameter":    f.parameter,
                "evidence":     f.evidence,
                "cvss":         f.cvss,
                "remediation":  f.remediation,
                "payload":      f.payload,
                "http_trace":   f.http_trace,
                "think_trace":  f.think_trace,
                "waf_bypassed": f.waf_bypassed,
                "bypass_method": f.bypass_method,
            }
            fid = await save_finding(scan_id, fdict)
            findings_with_ids.append((fid, fdict))

        # ── Post-scan False-Positive Analysis phase ─────────────────
        # Walks every finding via brahmastra:p6, judging real-vs-FP and
        # firing up to 5 retest probes per finding for confirmation.
        # Wrapped in try/except so an AI / network failure NEVER blocks
        # the scan from transitioning to "complete".
        if findings_with_ids:
            try:
                from brahmastra.fp_analyzer import FPAnalyzer
                await update_scan_status(scan_id, "analyzing_fp")
                fp_bridge = AIBridge(
                    mode    = (req.ai_mode or "brahmastra"),
                    api_key = req.api_key or "",
                )
                fp = FPAnalyzer(
                    ai   = fp_bridge,
                    emit = emit,
                    max_probes_per_finding = 5,
                )
                await fp.analyze_all(scan_id, findings_with_ids)
            except Exception as e:
                import traceback
                await emit("fp_analysis_done", {
                    "error": f"{type(e).__name__}: {e}"[:300],
                })
                await emit("log", {
                    "level": "warn",
                    "msg":   f"FP phase aborted: {type(e).__name__}: {e}",
                    "trace": traceback.format_exc()[:2000],
                })

        await update_scan_status(scan_id, "complete", total_requests=result.total_requests)

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        await update_scan_status(scan_id, "failed", error=str(e))
        await emit("error", {"msg": str(e), "trace": tb})
        await emit("done", {"error": str(e)})
    finally:
        _engines.pop(scan_id, None)


# ── Legacy Naive Scan Runner ──────────────────────────────────────────────────

async def run_scan(scan_id: str, target: str, req: ScanRequest):
    """Legacy naive scanner (kept for backward compatibility)."""

    async def emit(event_type: str, data: dict):
        logging.warning(f"emit: {event_type}")
        await save_event(scan_id, event_type, data)
        for q in _sse_queues.get(scan_id, []):
            try: q.put_nowait((event_type, data))
            except asyncio.QueueFull: pass

    try:
        await emit("log", {"msg": f"BRAHMASTRA scan started — {target}", "level": "info"})
        await emit("log", {"msg": f"Profile: {req.scan_profile} | Auth: {req.auth_type}", "level": "info"})
        key_msg = f"present ({len(req.api_key)} chars)" if req.api_key else "NOT SET"
        await emit("log", {"msg": f"AI API key: {key_msg}", "level": "info"})

        headers = {"User-Agent": "BRAHMASTRA/1.0 Security Scanner"}
        cookies = {}

        if req.cookies:
            for part in req.cookies.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()

        if req.username and req.password and req.auth_type == "form":
            await emit("log", {"msg": f"Performing form login as {req.username}...", "level": "info"})
            login_cookies = await do_form_login(target, req.username, req.password)
            if login_cookies:
                cookies.update(login_cookies)
                await emit("log", {"msg": "Login successful — session cookies captured", "level": "success"})
            else:
                await emit("log", {"msg": "Login failed — continuing unauthenticated", "level": "warn"})

        await emit("log", {"msg": "Garudastra — crawling target...", "level": "info"})
        test_points = await crawl(target, headers, cookies)
        await emit("log", {"msg": f"Found {len(test_points)} test points", "level": "info"})

        if not test_points:
            await emit("log", {"msg": "No test points found — using defaults", "level": "warn"})
            test_points = [
                {"path": "/", "param": "q", "method": "GET"},
                {"path": "/login.php", "param": "uname", "method": "POST"},
                {"path": "/login.php", "param": "password", "method": "POST"},
            ]

        vuln_types = get_vuln_types(req.scan_profile)
        findings_count = 0
        total_requests = 0
        tested = set()
        pause_flag = _pause_flags.get(scan_id)
        stopped = False
        # Capture every persisted finding so the post-scan FP phase can
        # walk them in the same shape the engine path uses.
        findings_with_ids: list[tuple[int, dict]] = []

        for tp in test_points:
            if _stop_flags.get(scan_id):
                stopped = True
                break

            if pause_flag and not pause_flag.is_set():
                await emit("log", {"msg": "⏸ Scan paused — waiting for resume...", "level": "warn"})
                await pause_flag.wait()
                if _stop_flags.get(scan_id):
                    stopped = True
                    break
                await emit("log", {"msg": "▶ Scan resumed", "level": "success"})

            path   = tp["path"]
            param  = tp["param"]
            method = tp.get("method", "GET")
            key    = f"{method}:{path}:{param}"
            if key in tested:
                continue
            tested.add(key)

            await emit("probe", {"path": path, "param": param, "method": method,
                                 "msg": f"Testing {method} {path} — param: {param}"})

            for vuln_type, payloads in vuln_types:
                if _stop_flags.get(scan_id):
                    stopped = True
                    break
                if pause_flag and not pause_flag.is_set():
                    await emit("log", {"msg": "⏸ Paused mid-test — waiting...", "level": "warn"})
                    await pause_flag.wait()
                    if _stop_flags.get(scan_id):
                        stopped = True
                        break
                    await emit("log", {"msg": "▶ Resumed", "level": "success"})

                for payload in payloads:
                    total_requests += 1
                    finding = await test_payload(
                        target, path, param, method, vuln_type, payload,
                        headers, cookies, emit,
                        backend=req.model_backend, api_key=req.api_key
                    )
                    if finding:
                        fid = await save_finding(scan_id, finding)
                        finding["id"] = fid
                        findings_with_ids.append((fid, finding))
                        findings_count += 1
                        await emit("finding", finding)
                        break
                if stopped:
                    break

        if stopped:
            await emit("log", {"msg": f"Scan stopped — {findings_count} findings, {total_requests} requests", "level": "warn"})
        else:
            await emit("log", {"msg": f"Scan complete — {findings_count} findings, {total_requests} requests", "level": "success"})

        # ── Post-scan False-Positive Analysis phase (legacy path) ──
        # Mirrors the engine path: walks every finding via brahmastra:p6,
        # judges real-vs-FP, fires up to 5 retest probes per finding.
        # Skipped if the scan was stopped early or there are no findings.
        if findings_with_ids and not stopped:
            try:
                from brahmastra.fp_analyzer import FPAnalyzer
                await update_scan_status(scan_id, "analyzing_fp")
                fp_bridge = AIBridge(
                    mode    = (req.ai_mode or "brahmastra"),
                    api_key = req.api_key or "",
                )
                fp = FPAnalyzer(
                    ai   = fp_bridge,
                    emit = emit,
                    max_probes_per_finding = 5,
                )
                await fp.analyze_all(scan_id, findings_with_ids)
            except Exception as e:
                import traceback
                await emit("fp_analysis_done", {
                    "error": f"{type(e).__name__}: {e}"[:300],
                })
                await emit("log", {
                    "level": "warn",
                    "msg":   f"FP phase aborted: {type(e).__name__}: {e}",
                    "trace": traceback.format_exc()[:2000],
                })

        await update_scan_status(scan_id, "complete", total_requests=total_requests)
        await emit("done", {"findings": findings_count, "requests": total_requests, "stopped": stopped})

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        await update_scan_status(scan_id, "failed", error=str(e))
        await emit("error", {"msg": str(e), "trace": tb})
        await emit("done", {"error": str(e)})


# ── Crawl ─────────────────────────────────────────────────────────────────────

async def crawl(base_url: str, headers: dict, cookies: dict) -> list[dict]:
    targets = []
    visited = set()

    async def crawl_page(url: str, depth: int = 0):
        if depth > 2 or url in visited:
            return
        visited.add(url)
        try:
            async with httpx.AsyncClient(
                timeout=10.0, verify=False, follow_redirects=True,
                headers=headers, cookies=cookies
            ) as client:
                r = await client.get(url)
                body = r.text

            forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)
            for form_html in forms:
                action_m = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                action = action_m.group(1) if action_m else "/"
                method_m = re.search(r'method=["\'](\w+)["\']', form_html, re.IGNORECASE)
                method = method_m.group(1).upper() if method_m else "POST"

                if not action.startswith("http"):
                    from urllib.parse import urljoin
                    action = urljoin(base_url, action)
                    action = action.replace(base_url, "")
                    if not action.startswith("/"):
                        action = "/" + action

                inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                selects = re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                for name in inputs + selects:
                    if name.lower() not in ("submit", "button", "csrf_token", "_token", "token", "nonce", "captcha"):
                        targets.append({"path": action, "param": name, "method": method})

            links = re.findall(r'href=["\']([^"\'#]+)["\']', body, re.IGNORECASE)
            for link in links[:20]:
                from urllib.parse import urljoin, urlparse, parse_qs
                full = urljoin(base_url, link)
                if not full.startswith(base_url):
                    continue
                parsed = urlparse(full)
                path_only = parsed.path
                for param in parse_qs(parsed.query):
                    targets.append({"path": path_only, "param": param, "method": "GET"})
                if depth < 1 and "?" not in link:
                    await crawl_page(full, depth + 1)

        except Exception:
            pass

    await crawl_page(base_url)
    return targets


# ── Form login ────────────────────────────────────────────────────────────────

async def do_form_login(base_url: str, username: str, password: str) -> dict:
    login_paths = ["/login.php", "/login", "/signin", "/admin/login", "/user/login", "/"]
    for lpath in login_paths:
        url = base_url + lpath
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
                r = await client.get(url)
                body = r.text
                form_match = re.search(r'<form[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)
                if not form_match:
                    continue
                form_html = form_match.group(1)
                action_m = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
                action = action_m.group(1) if action_m else lpath
                if not action.startswith("http"):
                    from urllib.parse import urljoin
                    action = urljoin(base_url, action)
                inputs = re.findall(
                    r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
                    form_html, re.IGNORECASE
                )
                data = {}
                for name, value in inputs:
                    if "user" in name.lower() or "email" in name.lower() or "login" in name.lower():
                        data[name] = username
                    elif "pass" in name.lower():
                        data[name] = password
                    elif name.lower() not in ("submit", "button"):
                        data[name] = value
                if not data:
                    continue
                post_r = await client.post(action, data=data, follow_redirects=True)
                if post_r.status_code in (200, 302) and "login" not in post_r.url.path.lower():
                    return dict(client.cookies)
        except Exception:
            continue
    return {}


# ── Payload definitions ───────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "admin'--",
    "' AND SLEEP(3)--", "' UNION SELECT NULL,NULL,NULL--",
    "1 OR 1=1", "' OR 'x'='x",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert(document.cookie)</script>",
    "<svg onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
]
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
LFI_PAYLOADS  = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
]
CMDI_PAYLOADS = ["; id", "| id", "`id`", "$(id)", "; cat /etc/passwd", "| whoami"]
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:22/",
    "http://localhost:80/",
]
OPEN_REDIRECT = ["https://evil.com", "//evil.com", "/\\evil.com"]

QUICK_PROFILE   = [("SQL Injection", SQLI_PAYLOADS[:3]), ("XSS", XSS_PAYLOADS[:2])]
FULL_PROFILE    = [
    ("SQL Injection",    SQLI_PAYLOADS),
    ("XSS",             XSS_PAYLOADS),
    ("SSTI",            SSTI_PAYLOADS),
    ("Path Traversal",  LFI_PAYLOADS[:3]),
    ("Command Injection", CMDI_PAYLOADS[:3]),
    ("SSRF",            SSRF_PAYLOADS),
]
STEALTH_PROFILE = [("SQL Injection", SQLI_PAYLOADS[:2]), ("XSS", XSS_PAYLOADS[:1])]

def get_vuln_types(profile: str):
    return {"quick": QUICK_PROFILE, "stealth": STEALTH_PROFILE}.get(profile, FULL_PROFILE)


# ── Payload tester ────────────────────────────────────────────────────────────

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-0", "pg_query", "sqlite_",
    "unclosed quotation", "syntax error", "you have an error in your sql",
    "warning: mysql", "invalid query", "microsoft ole db",
    "odbc drivers", "sql server", "division by zero",
]
XSS_REFLECTED  = ["<script>alert(1)</script>", "onerror=alert(1)", "onload=alert(1)"]
SSTI_CONFIRMED = ["49", "7777777"]
LFI_CONFIRMED  = ["root:x:", "bin:x:", "[boot loader]", "daemon:x:"]
CMDI_CONFIRMED = ["uid=", "root:", "/bin/bash", "total 0"]

SYSTEM_PROMPT = """You are BRAHMASTRA, an elite DAST security scanner.
You are given an HTTP response from a payload injection test.
Analyze it and respond with EXACTLY one of these two tool calls:

  report_finding(severity="CRITICAL", type="SQL Injection", url="/path", parameter="param", evidence="exact proof from response", cvss=9.0, remediation="Use parameterized queries")
  mark_clean(url="/path", parameter="param", reason="No evidence in response")

Rules:
- Only report if you see DIRECT EVIDENCE in the response body (error message, reflected payload, file content, command output)
- Do NOT report speculation — only confirmed vulnerabilities
- severity must be: CRITICAL, HIGH, MEDIUM, or LOW
- Always respond in English only
"""

ANALYSIS_TMPL = """Payload injected: {payload}
Vulnerability class: {vuln_type}
Target: {method} {url} (parameter: {param})

HTTP Response:
  Status: {status}
  Headers: {headers}
  Body (first 800 chars):
{body}

Is parameter "{param}" vulnerable? Output report_finding() or mark_clean() only."""


async def test_payload(
    base_url: str, path: str, param: str, method: str,
    vuln_type: str, payload: str,
    headers: dict, cookies: dict,
    emit, backend: str = DEFAULT_BACKEND, api_key: str = ""
) -> dict | None:
    url = base_url + path
    status = 0
    body   = ""
    resp_headers = {}

    try:
        async with httpx.AsyncClient(
            timeout=10.0, verify=False, follow_redirects=True,
            headers=headers, cookies=cookies
        ) as client:
            if method == "POST":
                r = await client.post(url, data={param: payload})
            else:
                r = await client.get(url, params={param: payload})
            status       = r.status_code
            body         = r.text[:2000]
            resp_headers = dict(r.headers)
    except Exception as e:
        await emit("log", {"msg": f"Request error: {type(e).__name__}: {e or repr(e)}", "level": "warn"})
        return None

    body_lower = body.lower()
    heuristic_vuln = False
    if vuln_type == "SQL Injection" and any(e in body_lower for e in SQLI_ERRORS):
        heuristic_vuln = True
    elif vuln_type == "XSS" and any(p.lower() in body_lower for p in XSS_REFLECTED):
        heuristic_vuln = True
    elif vuln_type == "SSTI" and any(c in body for c in SSTI_CONFIRMED):
        heuristic_vuln = True
    elif vuln_type == "Path Traversal" and any(c in body for c in LFI_CONFIRMED):
        heuristic_vuln = True
    elif vuln_type == "Command Injection" and any(c in body for c in CMDI_CONFIRMED):
        heuristic_vuln = True
    elif vuln_type == "SSRF" and status == 200 and "169.254" in payload:
        heuristic_vuln = True

    if backend == "heuristic":
        if heuristic_vuln:
            return make_heuristic_finding(vuln_type, url, path, param, payload, body, status)
        return None

    model_response = ""
    try:
        model_response = await call_model(
            path, param, method, payload, vuln_type, status, body, resp_headers, backend, api_key
        )
    except Exception:
        if not heuristic_vuln:
            return None

    finding = parse_finding(model_response, vuln_type, url, path, param, payload, body)
    if finding is None and heuristic_vuln:
        finding = make_heuristic_finding(vuln_type, url, path, param, payload, body, status)
    return finding


async def call_model(path, param, method, payload, vuln_type, status, body, headers,
                    backend: str = DEFAULT_BACKEND, api_key: str = "") -> str:
    cfg = get_model_cfg(backend)
    user_msg = ANALYSIS_TMPL.format(
        payload=payload, vuln_type=vuln_type, method=method,
        url=path, param=param, status=status,
        headers=str(dict(list(headers.items())[:5])),
        body=body[:800]
    )
    ptype = cfg.get("type", "none")

    if ptype == "none":
        return ""

    if ptype == "ollama":
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(cfg["url"], json={
                "model": cfg["model"],
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 400},
            })
            return r.json().get("message", {}).get("content", "")

    elif ptype == "gemini":
        key = api_key or ""
        if not key:
            raise ValueError("Gemini API key required")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{cfg['model']}:generateContent?key={key}"
        body_json = {
            "contents": [{"role": "user", "parts": [{"text": SYSTEM_PROMPT + "\n\n" + user_msg}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 400},
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(url, json=body_json)
            r.raise_for_status()
            candidates = r.json().get("candidates", [])
            if candidates:
                return candidates[0]["content"]["parts"][0]["text"]
            return ""

    elif ptype == "claude":
        key = api_key or ""
        if not key:
            raise ValueError("Anthropic API key required")
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={
                    "model": cfg["model"], "max_tokens": 400,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": user_msg}],
                },
            )
            r.raise_for_status()
            return r.json()["content"][0]["text"]

    elif ptype == "openai":
        key = api_key or ""
        if not key:
            raise ValueError("OpenAI API key required")
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": cfg["model"],
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": user_msg},
                    ],
                    "temperature": 0.1, "max_tokens": 400,
                },
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]

    return ""


SEVERITY_MAP = {
    "SQL Injection":    ("CRITICAL", 9.0),
    "XSS":             ("HIGH",     6.1),
    "SSTI":            ("CRITICAL", 9.8),
    "Command Injection":("CRITICAL", 9.8),
    "Path Traversal":  ("HIGH",     8.8),
    "SSRF":            ("CRITICAL", 9.0),
    "Open Redirect":   ("MEDIUM",   6.1),
}

REMEDIATION_MAP = {
    "SQL Injection":    "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    "XSS":             "HTML-encode output. Use Content-Security-Policy header.",
    "SSTI":            "Avoid rendering user input in templates. Sandbox template engines.",
    "Command Injection":"Never pass user input to shell commands. Use allow-lists.",
    "Path Traversal":  "Validate and canonicalize file paths. Use allow-lists.",
    "SSRF":            "Validate and block internal IP ranges. Use allow-list for external URLs.",
    "Open Redirect":   "Validate redirect targets against allow-list of trusted domains.",
}


def parse_finding(model_resp: str, vuln_type: str, full_url: str, path: str,
                  param: str, payload: str, body: str) -> dict | None:
    if not model_resp or "mark_clean" in model_resp.lower():
        return None
    m = re.search(r'report_finding\((.+?)\)', model_resp, re.DOTALL)
    if not m:
        return None
    args_str = m.group(1)

    def extract(key):
        km = re.search(rf'{key}=["\']([^"\']*)["\']', args_str)
        return km.group(1) if km else ""

    def extract_float(key, default):
        km = re.search(rf'{key}=([\d.]+)', args_str)
        return float(km.group(1)) if km else default

    severity    = extract("severity") or SEVERITY_MAP.get(vuln_type, ("HIGH", 7.0))[0]
    cvss        = extract_float("cvss", SEVERITY_MAP.get(vuln_type, ("HIGH", 7.0))[1])
    vtype       = extract("type") or vuln_type
    evidence    = extract("evidence") or body[:200]
    remediation = extract("remediation") or REMEDIATION_MAP.get(vuln_type, "Apply vendor patch.")

    if severity.upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity = "HIGH"

    think_m    = re.search(r'<think>(.*?)</think>', model_resp, re.DOTALL)
    think_trace = think_m.group(1).strip() if think_m else ""

    return {
        "severity":      severity.upper(),
        "type":          vtype,
        "url":           full_url,
        "parameter":     param,
        "evidence":      evidence,
        "cvss":          cvss,
        "remediation":   remediation,
        "payload":       payload,
        "http_trace":    f"Response body preview:\n{body[:500]}",
        "think_trace":   think_trace,
        "waf_bypassed":  False,
        "bypass_method": "",
    }


def make_heuristic_finding(vuln_type, url, path, param, payload, body, status) -> dict:
    sev, cvss = SEVERITY_MAP.get(vuln_type, ("HIGH", 7.0))
    remediation = REMEDIATION_MAP.get(vuln_type, "Apply vendor patch.")

    if vuln_type == "SQL Injection":
        matching = [e for e in SQLI_ERRORS if e in body.lower()]
        evidence = f"SQL error in response: {', '.join(matching[:3])}"
    elif vuln_type == "XSS":
        evidence = "Payload reflected unescaped in response body"
    elif vuln_type == "SSTI":
        evidence = "Template expression evaluated: '{{7*7}}' returned '49' in response"
    elif vuln_type == "Path Traversal":
        matching = [c for c in LFI_CONFIRMED if c in body]
        evidence = f"File content in response: {', '.join(matching[:2])}"
    elif vuln_type == "Command Injection":
        matching = [c for c in CMDI_CONFIRMED if c in body]
        evidence = f"Command output in response: {', '.join(matching[:2])}"
    else:
        evidence = f"Heuristic match in HTTP {status} response"

    return {
        "severity":      sev,
        "type":          vuln_type,
        "url":           url,
        "parameter":     param,
        "evidence":      evidence,
        "cvss":          cvss,
        "remediation":   remediation,
        "payload":       payload,
        "http_trace":    f"HTTP {status}\n{body[:500]}",
        "think_trace":   "",
        "waf_bypassed":  False,
        "bypass_method": "",
    }


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.api:app", host="0.0.0.0", port=8888, reload=True)
