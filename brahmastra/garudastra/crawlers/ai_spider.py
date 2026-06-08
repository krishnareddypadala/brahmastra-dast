"""
BRAHMASTRA — Garudastra: AI-driven Spider

A second, parallel crawler that runs alongside the structural `Spider`.
Where `Spider` walks the link graph with regex extractors + wordlist fuzz,
`AISpider` feeds every fetched response to the BRAHMASTRA model (or any
configured AI backend) and asks it to extract:

  - new URLs worth crawling
  - parameters (query / body / header)
  - forms (action, method, fields)
  - a flag on whether the response looks like a session-expired login page

It then:

  1. BFS-crawls the URLs the AI returned, respecting a page budget (each
     page costs one AI call, so the budget is small — 40 by default).
  2. Merges every discovered parameter/form back into a `ScanTarget` so
     the rule engine can attack them.
  3. Detects session drops mid-crawl via three heuristics (status 401/403,
     redirect into a /login-shaped URL, response body containing a
     password input) AND the AI's own `auth_lost` flag. On drop it calls
     `auth_manager.get_headers()` to re-run the form-login flow (which
     already has its own AI self-heal path for broken login forms) and
     retries the current page ONCE with the fresh headers.
  4. Uses the same shared httpx.AsyncClient + global semaphore pattern as
     the structural spider, so the whole crawl pipeline shares one TCP
     pool and one backpressure point.

Why separate from `Spider` and not a new phase inside it:
  - `Spider` is intentionally AI-free on its hot path so the AI planner
    gets clean evidence. Tangling AI into the middle of it would muddy
    that contract and double the token bill.
  - AISpider is budget-bounded and runs AFTER the structural crawl has
    built an initial target list, so the two never race on dedup.
  - Keeps the AI cost explicit: one Phase, one knob, easy to disable.
"""

from __future__ import annotations

import asyncio
from typing import Optional, TYPE_CHECKING
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from brahmastra.sudarshana.base import ScanTarget
from brahmastra.garudastra.crawlers.canonicalizer import (
    PathTemplateTracker,
    canonical_key,
)

if TYPE_CHECKING:
    from brahmastra.ai_bridge import AIBridge
    from brahmastra.garudastra.auth.manager import AuthManager


# Path substrings that log the user out if visited with a session cookie.
# Mirrored in spider.py / url_parser.py / engine._build_post_auth_seeds —
# keep all four lists in sync.
_SESSION_DESTROYING_TOKENS = (
    "logout", "log-out", "log_out",
    "signout", "sign-out", "sign_out",
    "destroy", "kill_session", "killsession",
    "/end_session", "endsession",
)

# Path substrings that make us suspect we've been bounced to the login page
# mid-crawl (used by the session-drop heuristic, not the destroy filter).
_LOGIN_PATH_TOKENS = (
    "login", "signin", "sign-in", "sign_in",
    "/auth/", "/session/new", "authenticate",
)


class AISpider:
    """
    BFS crawler whose next-hop decisions come from an AI model reading
    each fetched response.

    Budget-bounded: `max_pages` is the HARD cap on AI calls — one call per
    page visited, so setting this too high is an expensive mistake.
    """

    def __init__(
        self,
        ai_bridge: "AIBridge",
        auth_manager: Optional["AuthManager"] = None,
        max_pages: int       = 40,
        max_concurrency: int = 6,
        max_reauth: int      = 3,
    ):
        self.ai              = ai_bridge
        # AuthManager is optional — when supplied, we can call
        # get_headers() again mid-crawl to refresh expired cookies.
        # When None, session drops are detected but the crawl just stops
        # hitting authed pages (it doesn't crash).
        self.auth_manager    = auth_manager
        self.max_pages       = max(1, int(max_pages))
        self.max_concurrency = max(2, int(max_concurrency))
        self._max_reauth     = max(0, int(max_reauth))

        # Shared HTTP client + global semaphore — same pattern as Spider.
        # Both are owned by crawl() inside a try/finally.
        self._http: Optional[httpx.AsyncClient] = None
        self._sem:  Optional[asyncio.Semaphore] = None

        # Crawl state (reset at the top of every crawl() call).
        self.visited: set[str]             = set()
        self.canon_visited: set[str]       = set()
        self.targets: list[ScanTarget]     = []
        self._base_netloc: str             = ""
        self._base_scheme: str             = "http"
        self._authed: bool                 = False
        self._emit_fn                      = None
        self._reauth_count: int            = 0
        self._path_tracker: PathTemplateTracker = PathTemplateTracker()
        # Progress counters for the dashboard's "NOW CRAWLING" card.
        self._in_flight: int               = 0
        self._pages_analysed: int          = 0
        self._auth_lost_events: int        = 0

    # ── Scope / session helpers ───────────────────────────────────────────

    def _kills_session(self, url: str) -> bool:
        """True iff fetching `url` while authenticated would log us out."""
        if not self._authed:
            return False
        try:
            path = (urlparse(url).path or "").lower()
        except Exception:
            return False
        return any(tok in path for tok in _SESSION_DESTROYING_TOKENS)

    def _same_host(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self._base_netloc
        except Exception:
            return False

    def _normalize(self, raw: str, base: str) -> str:
        """Make an AI-emitted URL absolute, clean, and same-host-safe.
        Returns '' if it should be dropped."""
        if not raw:
            return ""
        raw = raw.strip().strip("'\"` ")
        if not raw:
            return ""
        if raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
            return ""
        # Drop template placeholders the model might hallucinate.
        if "{" in raw or "}" in raw or "${" in raw or "<" in raw:
            return ""
        try:
            full = urljoin(base, raw)
            p    = urlparse(full)
            if p.scheme not in ("http", "https"):
                return ""
            # Strip fragment; keep query (so /search?q=foo stays distinct).
            return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
        except Exception:
            return ""

    # ── Public entry point ────────────────────────────────────────────────

    async def crawl(
        self,
        start_url: str,
        auth_headers: Optional[dict] = None,
        emit_fn=None,
    ) -> list[ScanTarget]:
        """
        Run the AI-driven crawl starting from `start_url`.

        Returns the list of ScanTargets discovered. The engine is expected
        to dedup these against the structural Spider's output via
        canonical_key() before handing them to the rule engine.

        This is a no-op (returns []) when the AI bridge is disabled — we
        refuse to do a silent "dumb" fallback crawl because the whole
        point of this phase is AI-driven analysis.
        """
        if not self.ai or not getattr(self.ai, "enabled", False):
            return []

        # Reset per-call state.
        auth_headers          = dict(auth_headers or {})
        self._authed          = bool(auth_headers)
        self.visited          = set()
        self.canon_visited    = set()
        self.targets          = []
        self._path_tracker    = PathTemplateTracker()
        self._reauth_count    = 0
        self._in_flight       = 0
        self._pages_analysed  = 0
        self._auth_lost_events= 0
        self._emit_fn         = emit_fn

        parsed              = urlparse(start_url)
        self._base_netloc   = parsed.netloc
        self._base_scheme   = parsed.scheme

        # Build the shared client + semaphore.
        limits = httpx.Limits(
            max_connections           = self.max_concurrency * 2,
            max_keepalive_connections = self.max_concurrency,
            keepalive_expiry          = 30.0,
        )
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self._http = httpx.AsyncClient(
            verify          = False,
            follow_redirects= True,
            timeout         = httpx.Timeout(15.0, connect=8.0),
            limits          = limits,
            headers         = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )

        try:
            await self._emit("phase", {
                "phase":   "ai_crawl",
                "message": f"AI spider analysing pages (budget={self.max_pages}, "
                           f"backend={self.ai.mode})...",
            })
            await self._bfs([start_url], auth_headers)
        finally:
            try:
                await self._http.aclose()
            except Exception:
                pass
            self._http = None
            self._sem  = None

        await self._emit("ai_crawl_done", {
            "endpoints":       len(self.targets),
            "pages_analyzed":  self._pages_analysed,
            "reauth_count":    self._reauth_count,
            "auth_lost_events": self._auth_lost_events,
            "backend":         self.ai.mode,
        })
        return self.targets

    # ── BFS driver ────────────────────────────────────────────────────────

    async def _bfs(self, seeds: list[str], auth_headers: dict) -> None:
        """Breadth-first walk. Each level's URLs are fetched + AI-analysed
        in parallel (bounded by the global semaphore). Newly discovered
        URLs are enqueued for the next level until the page budget is hit."""
        queue: list[str] = []
        for s in seeds:
            nu = self._normalize(s, s)
            if nu and self._same_host(nu) and not self._kills_session(nu):
                queue.append(nu)
        if not queue:
            return

        while queue and self._pages_analysed < self.max_pages:
            # Pull a chunk up to max_concurrency size (or fewer if queue empties).
            chunk: list[str] = []
            while queue and len(chunk) < self.max_concurrency:
                u = queue.pop(0)
                if u in self.visited:
                    continue
                if not self._same_host(u):
                    continue
                if self._kills_session(u):
                    continue
                ck = canonical_key(u, "GET", self._path_tracker)
                if ck in self.canon_visited:
                    continue
                self.canon_visited.add(ck)
                self.visited.add(u)
                chunk.append(u)
                if self._pages_analysed + len(chunk) >= self.max_pages:
                    break
            if not chunk:
                continue

            results = await asyncio.gather(
                *(self._visit_and_analyse(u, auth_headers) for u in chunk),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, list):
                    for new_url in r:
                        if new_url in self.visited:
                            continue
                        if not self._same_host(new_url):
                            continue
                        if self._kills_session(new_url):
                            continue
                        queue.append(new_url)

    # ── Per-page pipeline ─────────────────────────────────────────────────

    async def _visit_and_analyse(
        self,
        url: str,
        auth_headers: dict,
    ) -> list[str]:
        """Fetch url, hand response to AI, register findings, return the
        newly discovered URLs for the next BFS level."""
        assert self._http is not None and self._sem is not None

        await self._emit("crawl_active", {
            "phase":      "ai_crawl",
            "url":        url,
            "method":     "GET",
            "in_flight":  self._in_flight,
            "discovered": len(self.targets),
            "failed":     0,
        })

        # Initial fetch.
        try:
            async with self._sem:
                self._in_flight += 1
                try:
                    resp = await self._http.get(url, headers=auth_headers)
                finally:
                    self._in_flight = max(0, self._in_flight - 1)
        except Exception:
            return []

        html       = resp.text or ""
        status     = resp.status_code
        ctype      = resp.headers.get("content-type", "")
        final_url  = str(resp.url)

        # Session-drop heuristic (status+URL+password-input). We run this
        # BEFORE the AI call because a bounced-to-login response is usually
        # small and cheap to re-fetch with fresh headers — no reason to
        # burn an AI call analysing the login page.
        if self._authed and self._looks_like_auth_lost(status, final_url, html):
            if await self._attempt_reauth(
                auth_headers,
                reason=f"pre-AI heuristic status={status} final={final_url}",
            ):
                try:
                    async with self._sem:
                        self._in_flight += 1
                        try:
                            resp = await self._http.get(url, headers=auth_headers)
                        finally:
                            self._in_flight = max(0, self._in_flight - 1)
                    html      = resp.text or ""
                    status    = resp.status_code
                    ctype     = resp.headers.get("content-type", "")
                    final_url = str(resp.url)
                except Exception:
                    return []

        # Cheap body-type guard — no point asking the model to "extract
        # endpoints" from a 2 MB binary or an image.
        if not _body_is_worth_analysing(ctype, html):
            await self._register_page_target(url, auth_headers, [])
            return []

        # AI call — extract URLs/params/forms + auth_lost signal.
        try:
            extraction = await self.ai.extract_endpoints(
                url         = url,
                html_sample = html,
                status_code = status,
                content_type= ctype,
            )
        except Exception:
            extraction = {}
        self._pages_analysed += 1

        # The model may also flag auth loss from semantic cues we missed
        # (e.g. "your session has expired" banner on an otherwise 200 OK
        # response). If so, trigger re-auth and re-fetch ONCE — we only
        # burn extra budget when the AI is sure.
        if (
            extraction
            and extraction.get("auth_lost")
            and self._authed
        ):
            self._auth_lost_events += 1
            if await self._attempt_reauth(
                auth_headers,
                reason="AI flagged auth_lost in response body",
            ):
                try:
                    async with self._sem:
                        self._in_flight += 1
                        try:
                            resp = await self._http.get(url, headers=auth_headers)
                        finally:
                            self._in_flight = max(0, self._in_flight - 1)
                    html   = resp.text or ""
                    status = resp.status_code
                    ctype  = resp.headers.get("content-type", "")
                    final_url = str(resp.url)
                    # Re-analyse the fresh page so we don't lose its targets.
                    extraction = await self.ai.extract_endpoints(
                        url=url, html_sample=html,
                        status_code=status, content_type=ctype,
                    ) or {}
                    self._pages_analysed += 1
                except Exception:
                    pass

        # Extract AI-reported parameters for *this* URL and register as a target.
        page_params = _coerce_params(extraction.get("parameters") or [])
        await self._register_page_target(url, auth_headers, page_params)

        # Enqueue URLs the model spotted in the body.
        new_urls: list[str] = []
        for raw in (extraction.get("urls") or []):
            abs_url = self._normalize(str(raw), final_url)
            if not abs_url:
                continue
            if not self._same_host(abs_url):
                continue
            if self._kills_session(abs_url):
                continue
            ck = canonical_key(abs_url, "GET", self._path_tracker)
            if ck in self.canon_visited:
                continue
            # We DO add it as a target here (even before visiting) so the
            # rule engine can attack URLs that might fall outside the BFS
            # page budget. The canonical dedup key is the same one the
            # BFS loop will check, so double-enqueue is free.
            await self._add_target(ScanTarget(
                url        = abs_url,
                method     = "GET",
                parameters = [],
                headers    = dict(auth_headers),
                source     = "ai_crawl",
            ))
            new_urls.append(abs_url)

        # Register forms the model found.
        for f in (extraction.get("forms") or []):
            if not isinstance(f, dict):
                continue
            action_raw = f.get("action") or ""
            action     = self._normalize(str(action_raw), final_url)
            method     = str(f.get("method") or "POST").upper()
            if not action or not self._same_host(action):
                continue
            if self._kills_session(action):
                continue
            form_params = _coerce_form_fields(f.get("fields") or f.get("params") or [])
            fk = canonical_key(action, method, self._path_tracker)
            if fk in self.canon_visited:
                continue
            self.canon_visited.add(fk)
            await self._add_target(ScanTarget(
                url        = action,
                method     = method,
                parameters = form_params,
                headers    = dict(auth_headers),
                source     = "ai_form",
            ))

        await self._emit("ai_crawl_page", {
            "url":           url,
            "status":        status,
            "urls_found":    len(extraction.get("urls")       or []),
            "params_found":  len(extraction.get("parameters") or []),
            "forms_found":   len(extraction.get("forms")      or []),
            "auth_lost":     bool(extraction.get("auth_lost", False)),
            "reasoning":     (extraction.get("reasoning") or "")[:200],
            "pages_analysed":self._pages_analysed,
            "total_targets": len(self.targets),
        })

        return new_urls

    async def _register_page_target(
        self,
        url: str,
        auth_headers: dict,
        params: list[dict],
    ) -> None:
        """Record `url` itself as a ScanTarget (with any AI-extracted params
        attached). Deduplicated against targets already registered in this
        crawl via canonical_key."""
        ck = canonical_key(url, "GET", self._path_tracker)
        # If we already have a target for this canonical key, just merge
        # the new params into it instead of pushing a duplicate.
        for t in self.targets:
            if canonical_key(t.url, t.method or "GET", self._path_tracker) == ck:
                if params:
                    existing = {p.get("name") for p in (t.parameters or [])}
                    for p in params:
                        if p["name"] and p["name"] not in existing:
                            t.parameters.append(p)
                            existing.add(p["name"])
                return
        await self._add_target(ScanTarget(
            url        = url,
            method     = "GET",
            parameters = list(params),
            headers    = dict(auth_headers),
            source     = "ai_crawl",
        ))

    async def _add_target(self, t: ScanTarget) -> None:
        if self._kills_session(t.url):
            return
        self.targets.append(t)
        await self._emit("crawl_progress", {
            "url":             t.url,
            "method":          (t.method or "GET").upper(),
            "parameters":      t.parameters or [],
            "source":          t.source or "ai_crawl",
            "endpoints_found": len(self.targets),
        })

    # ── Session-drop detection + re-auth ──────────────────────────────────

    def _looks_like_auth_lost(
        self,
        status: int,
        final_url: str,
        html: str,
    ) -> bool:
        """Heuristic check fired BEFORE we spend an AI call on a response.

        Three signals, any of which fires is enough:

          1. Status code is 401 or 403 — the server explicitly told us we
             don't have access.
          2. We landed on a URL whose path looks like /login, /signin,
             /auth/... — server bounced us to the login page.
          3. A 2xx/3xx response body contains a password <input> even
             though we weren't asking for a login page. Ignores the case
             where the crawler itself is fetching the login URL (too
             many false positives), which is why we also require that
             the final URL does NOT contain one of the login tokens —
             otherwise we'd infinite-loop re-authing on /login itself.
        """
        if status in (401, 403):
            return True

        try:
            path = (urlparse(final_url).path or "").lower()
        except Exception:
            path = ""

        # Case 2: redirected to a login-shaped URL.
        if any(tok in path for tok in _LOGIN_PATH_TOKENS):
            return True

        # Case 3: OK response body with a password input (but final URL
        # is NOT a login URL — we're on a page that shouldn't be a login
        # form but has one).
        if status in (200, 302) and "<input" in html.lower():
            lower = html.lower()
            if 'type="password"' in lower or "type='password'" in lower:
                if not any(tok in path for tok in _LOGIN_PATH_TOKENS):
                    return True

        return False

    async def _attempt_reauth(
        self,
        auth_headers: dict,    # mutable — we update in place on success
        reason: str,
    ) -> bool:
        """Call AuthManager.get_headers() to refresh the session. On
        success, mutate `auth_headers` in place so every in-flight task
        picks up the fresh Cookie/Authorization on its next request.

        Returns True if re-auth produced non-empty headers, False otherwise.

        Budget-capped by self._max_reauth — we refuse to loop forever
        trying to re-login on a broken target. Relies on AuthManager's
        own AI self-heal path (diagnose_auth_failure) to fix broken
        login forms, so calling get_headers() here transparently
        triggers that loop too."""
        if self._reauth_count >= self._max_reauth:
            return False
        if not self.auth_manager:
            return False

        self._reauth_count += 1
        await self._emit("ai_crawl_reauth", {
            "attempt":   self._reauth_count,
            "max":       self._max_reauth,
            "reason":    reason,
            "backend":   self.ai.mode,
        })

        try:
            fresh = await self.auth_manager.get_headers()
        except Exception as e:
            await self._emit("ai_crawl_reauth", {
                "attempt": self._reauth_count,
                "ok":      False,
                "error":   str(e)[:200],
            })
            return False

        if not fresh:
            await self._emit("ai_crawl_reauth", {
                "attempt": self._reauth_count,
                "ok":      False,
                "error":   "AuthManager returned empty headers",
            })
            return False

        # Replace headers in place so the shared dict used by every
        # concurrent task sees the fresh Cookie immediately. We clear
        # first so stale cookies don't linger next to the new ones.
        auth_headers.clear()
        auth_headers.update(fresh)
        self._authed = True
        await self._emit("ai_crawl_reauth", {
            "attempt":     self._reauth_count,
            "ok":          True,
            "header_keys": list(fresh.keys()),
            "has_cookie":  "Cookie" in fresh,
        })
        return True

    # ── Event emission ────────────────────────────────────────────────────

    async def _emit(self, event_type: str, data: dict) -> None:
        if not self._emit_fn:
            return
        try:
            await self._emit_fn(event_type, data)
        except Exception:
            # Swallow — SSE downlinks must never break the crawl.
            pass


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _body_is_worth_analysing(content_type: str, body: str) -> bool:
    """Cheap filter to avoid spending AI calls on binary/empty responses."""
    if not body or len(body) < 20:
        return False
    ct = (content_type or "").lower()
    if ct.startswith((
        "image/", "audio/", "video/", "font/",
        "application/octet-stream", "application/pdf",
        "application/zip", "application/x-",
    )):
        return False
    return True


def _coerce_params(raw: list) -> list[dict]:
    """Convert the AI's `parameters` field into our internal schema.
    Accepts both {'name': ..., 'in': ...} dicts and bare string lists."""
    out: list[dict] = []
    seen: set[str]  = set()
    for p in raw[:20]:
        if isinstance(p, dict):
            name = str(p.get("name") or "").strip()
            loc  = str(p.get("in") or p.get("location") or "query").strip().lower()
            if loc not in ("query", "body", "header", "path", "cookie"):
                loc = "query"
        elif isinstance(p, str):
            name = p.strip()
            loc  = "query"
        else:
            continue
        if not name or name in seen:
            continue
        seen.add(name)
        out.append({"name": name, "location": loc, "type": "string"})
    return out


def _coerce_form_fields(raw: list) -> list[dict]:
    """Convert the AI's form `fields` list into our internal parameter
    schema (location=body, type preserved when the model provides it)."""
    out: list[dict] = []
    seen: set[str]  = set()
    for f in raw[:20]:
        if isinstance(f, dict):
            name = str(f.get("name") or "").strip()
            typ  = str(f.get("type") or "text").strip().lower() or "text"
        elif isinstance(f, str):
            name = f.strip()
            typ  = "text"
        else:
            continue
        if not name or name in seen:
            continue
        seen.add(name)
        out.append({
            "name":     name,
            "location": "body",
            "type":     typ,
            "value":    "",
        })
    return out
