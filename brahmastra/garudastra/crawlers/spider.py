"""
BRAHMASTRA — Garudastra: Enhanced Spider Crawler
Extends URLParser with:
  - JS endpoint extraction (fetch/axios/XMLHttpRequest)
  - sitemap.xml + robots.txt parsing
  - Tech fingerprinting (framework detection)
  - Common endpoint fuzzing (/api/, /graphql, /swagger, etc.)
  - JSON response crawling (URLs inside API responses)
  - Hidden form field extraction

Returns list[ScanTarget] ready for rule engine.
"""

from __future__ import annotations
import asyncio
import re
from urllib.parse import urlparse, urljoin, urlunparse
from typing import Optional

import httpx

from brahmastra.sudarshana.base import ScanTarget
from brahmastra.garudastra.input.url_parser import URLParser, _extract_forms, _extract_links
from brahmastra.garudastra.crawlers.canonicalizer import (
    canonical_key,
    PathTemplateTracker,
)
from brahmastra.garudastra.crawlers.form_filler import submit_form, should_submit
from brahmastra.garudastra.crawlers.passive_scanner import PassiveScanner


COMMON_ENDPOINTS = [
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/graphql", "/graphql/", "/graph",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/docs",
    "/.well-known/", "/.well-known/openid-configuration",
    "/admin", "/admin/", "/manage", "/dashboard",
    "/health", "/metrics", "/status", "/ping",
    "/actuator", "/actuator/env", "/actuator/health",
    "/.git/config", "/.env", "/config", "/config.json",
    "/robots.txt", "/sitemap.xml",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/debug", "/test", "/dev",
    "/wp-admin", "/wp-login.php", "/wp-json/",
    "/xmlrpc.php",
]

TECH_SIGNATURES: dict[str, list[str]] = {
    "WordPress":    ["wp-content", "wp-includes", "wp-login", "PHPSESSID"],
    "Laravel":      ["laravel_session", "XSRF-TOKEN", "laravel"],
    "Django":       ["csrftoken", "Django", "djdt"],
    "Rails":        ["_session_id", "X-Request-Id", "ruby"],
    "React":        ["react", "__react", "_next", "Next.js"],
    "Angular":      ["ng-version", "ng-app", "angular"],
    "Vue":          ["__vue__", "vue-meta"],
    "Express":      ["X-Powered-By: Express"],
    "PHP":          ["PHPSESSID", "X-Powered-By: PHP", ".php"],
    "ASP.NET":      ["ASP.NET_SessionId", "X-Powered-By: ASP.NET", ".aspx"],
    "Spring":       ["JSESSIONID", "X-Application-Context"],
    "FastAPI":      ["application/json", "openapi"],
    "Nginx":        ["nginx"],
    "Apache":       ["Apache"],
    "Tomcat":       ["Apache-Coyote", "JSESSIONID"],
    "Cloudflare":   ["cf-ray", "cloudflare"],
    "AWS":          ["x-amz-request-id", "x-amzn-requestid", "awselb"],
}


class Spider:
    """
    Enhanced crawler that extends URLParser with JS extraction,
    tech fingerprinting, sitemap/robots parsing, and endpoint fuzzing.
    """

    # Path substrings whose visit, while holding a session cookie, will
    # log us out — must never be followed during an authenticated crawl.
    _SESSION_DESTROYING_TOKENS = (
        "logout", "log-out", "log_out",
        "signout", "sign-out", "sign_out",
        "destroy", "kill_session", "killsession",
        "/end_session", "endsession",
    )

    def _kills_session(self, url: str) -> bool:
        """True if visiting `url` while authenticated would terminate the
        session. Only honoured when the spider is running with auth_headers
        that contain a Cookie — unauthenticated scans still need to discover
        logout endpoints normally."""
        if not getattr(self, "_authed", False):
            return False
        try:
            path = (urlparse(url).path or "").lower()
        except Exception:
            return False
        return any(tok in path for tok in self._SESSION_DESTROYING_TOKENS)

    def __init__(self, max_pages: int = 300, max_depth: int = 3, max_concurrency: int = 50):
        self.max_pages       = max_pages
        self.max_depth       = max_depth
        self.max_concurrency = max(4, int(max_concurrency))
        self._authed: bool   = False  # set by crawl() based on auth_headers
        # Shared HTTP client + global concurrency ceiling. The client is
        # lazily created at the top of crawl() and torn down in the finally
        # block. Using ONE client across all crawl phases gives us TCP/TLS
        # keep-alive (massive latency win on HTTPS targets), a single
        # connection pool, and well-defined backpressure via the shared
        # semaphore below. Previously every phase spun up its own throwaway
        # client, forcing a TLS handshake per URL and letting URLParser
        # schedule unbounded coroutines during recursive link-walk.
        self._http: Optional[httpx.AsyncClient] = None
        self._sem:  Optional[asyncio.Semaphore] = None
        self.visited:   set[str]        = set()
        self.targets:   list[ScanTarget] = []
        self.tech_stack: list[str]      = []
        self.js_endpoints: list[str]    = []
        self._base_netloc: str          = ""
        self._base_scheme: str          = "http"
        self._emit_fn                   = None
        self._ai_seed_set: set[str]     = set()
        # Evidence captured during the crawl so the AI planner can reason
        # about real state instead of guessing generic paths.
        self.landing_html: str          = ""
        self.landing_status: int        = 0
        self.failed_paths: list[str]    = []   # COMMON_ENDPOINTS that returned 404/410
        # Live progress tracking for the dashboard's "NOW CRAWLING" card.
        # _phase is the current crawl stage ("robots", "sitemap", "html",
        # "fingerprint", "js_extract", "fuzz", "api_walk", "ai_walk") and
        # _in_flight is the number of HTTP requests currently live.
        self._phase: str                = "idle"
        self._in_flight: int            = 0
        # ZAP-inspired dedup + passive analysis. Canonicalizer strips
        # session IDs/tracking params and collapses /user/1 + /user/2 +
        # /user/3 into a single /user/{id} slot so we don't waste the
        # scan budget walking the same template with different IDs.
        # Passive scanner runs on every response we already fetched.
        self._canon_visited: set[str]   = set()
        self._path_tracker: PathTemplateTracker = PathTemplateTracker()
        self._passive: PassiveScanner   = PassiveScanner()
        # Per-node child cap — a single URL cannot spawn more than this
        # many sibling children. Prevents runaway on crawl-listings
        # that expose hundreds of per-entity rows (comments, products).
        self.max_children_per_node: int = 40
        self._child_counts: dict[str, int] = {}
        # Passive findings collected during the crawl for the engine to
        # persist & emit. We don't emit here because passive_scanner is
        # sync and save_finding() is async — the engine batches them.
        self.passive_findings: list[dict] = []

    async def _emit_active(self, url: str, method: str = "GET") -> None:
        """Fire a `crawl_active` SSE event so the dashboard can show the
        URL we're fetching *right now*, plus counters. Safe to call from
        any phase; silently no-ops if no emit_fn was wired."""
        if not self._emit_fn:
            return
        try:
            await self._emit_fn("crawl_active", {
                "phase":      self._phase,
                "url":        url,
                "method":     (method or "GET").upper(),
                "in_flight":  self._in_flight,
                "discovered": len(self.targets),
                "failed":     len(self.failed_paths),
            })
        except Exception:
            pass

    async def _add_target(self, t: ScanTarget):
        """Append a target (dedup via canonicalizer) and emit a crawl_progress
        event so the dashboard's Crawl tab sees every endpoint, regardless of
        which phase produced it (URL parse, sitemap, fuzz, JS extract, ai_seed).

        Dedup uses the ZAP-style canonical_key():
          - strips session IDs + utm_* tracking params
          - sorts query keys so ?a=1&b=2 == ?b=2&a=1
          - collapses /user/1 + /user/2 + /user/3 into /user/{id}
            once the path template tracker has seen enough siblings
        """
        # Never queue a logout/signout/destroy URL while authenticated —
        # visiting it would drop the session and break the rest of the crawl.
        if self._kills_session(t.url):
            return
        key = canonical_key(t.url, t.method or "GET", self._path_tracker)
        if key in self._canon_visited:
            return
        self._canon_visited.add(key)
        # Override source for AI-seeded entry points so they're visibly tagged
        if t.url in self._ai_seed_set:
            t.source = "ai_seed"
        self.targets.append(t)
        self.visited.add(t.url)
        if self._emit_fn:
            try:
                await self._emit_fn("crawl_progress", {
                    "url":             t.url,
                    "method":          (t.method or "GET").upper(),
                    "parameters":      t.parameters or [],
                    "source":          t.source or "crawl",
                    "endpoints_found": len(self.targets),
                })
            except Exception:
                pass

    async def crawl(
        self,
        url: str,
        auth_headers: Optional[dict] = None,
        depth: int = 2,
        emit_fn=None,
        extra_seeds: Optional[list[str]] = None,
    ) -> list[ScanTarget]:
        """
        Full structural crawl pipeline. Returns all discovered ScanTargets.
        This is intentionally AI-free — the engine drives AI-assisted
        exploration as a separate phase AFTER this returns, using
        get_evidence_bundle() + probe_and_walk() so the AI reasons about
        real crawl state instead of guessing blind.

        extra_seeds — additional URLs to walk alongside `url`. Used to feed
        the post-login landing page (e.g. /profile.php) and a heuristic
        list of common authenticated paths so the spider actually reaches
        the authenticated surface instead of stopping at the public
        homepage.  Without these, a login-gated app like ntr.army would
        only reveal the public login form even though auth cookies are
        already resolved and attached.
        """
        auth_headers = auth_headers or {}
        # Mark this scan as "authenticated" so the session-destroying URL
        # filter actually fires. We treat any non-empty auth_headers (Cookie,
        # Authorization, custom header, ...) as auth. Without this flag the
        # _kills_session() check is a no-op so unauthenticated scans still
        # crawl logout pages normally.
        self._authed = bool(auth_headers)
        self.visited    = set()
        self.targets    = []
        self.tech_stack = []
        self.js_endpoints = []
        self._emit_fn    = emit_fn
        self._ai_seed_set = set()
        self.landing_html = ""
        self.landing_status = 0
        self.failed_paths = []
        self._phase = "idle"
        self._in_flight = 0
        # Reset per-scan dedup & passive state.
        self._canon_visited = set()
        self._path_tracker = PathTemplateTracker()
        self._passive = PassiveScanner()
        self._child_counts = {}
        self.passive_findings = []

        parsed = urlparse(url)
        self._base_netloc  = parsed.netloc
        self._base_scheme  = parsed.scheme
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # ── Build the shared HTTP client + concurrency ceiling ──────────────
        # max_keepalive_connections = max_concurrency so every in-flight
        # request can hold a keep-alive slot; setting keepalive lower than
        # max_connections causes httpx to silently close+reopen sockets
        # under load, throwing away most of the TLS keep-alive win.
        limits = httpx.Limits(
            max_connections           = self.max_concurrency * 2,
            max_keepalive_connections = self.max_concurrency,
            keepalive_expiry          = 30.0,
        )
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self._http = httpx.AsyncClient(
            verify          = False,
            follow_redirects= True,
            timeout         = httpx.Timeout(10.0, connect=6.0),
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
            return await self._run_phases(url, base_url, auth_headers, emit_fn, extra_seeds)
        finally:
            try:
                await self._http.aclose()
            except Exception:
                pass
            self._http = None
            self._sem = None

    async def _run_phases(
        self,
        url: str,
        base_url: str,
        auth_headers: dict,
        emit_fn,
        extra_seeds: Optional[list[str]],
    ) -> list[ScanTarget]:
        """The actual phase pipeline. Split out of crawl() so the client
        lifecycle (open/close) is a single try/finally around it."""

        # Phase 1: robots.txt + sitemap + fingerprint run IN PARALLEL —
        # they're independent probes against the target root. Previously
        # they ran sequentially, wasting ~3× RTT at crawl startup.
        self._phase = "recon"
        await self._emit_active(f"{base_url}/robots.txt")
        await asyncio.gather(
            self._parse_robots(base_url, auth_headers),
            self._parse_sitemap(base_url, auth_headers),
            self._fingerprint(url, auth_headers),
            return_exceptions=True,
        )

        # Phase 2: HTML spider from the user-supplied URL (no blind AI seeds).
        # Include any extra_seeds (post-login landing page, common
        # authenticated paths) so the spider walks the logged-in surface
        # instead of just the public homepage.
        self._phase = "html"
        await self._emit_active(url)
        parser = URLParser()
        parser.max_pages = self.max_pages
        parser.max_depth = self.max_depth
        seed_list: list[str] = [url]
        if extra_seeds:
            # De-dupe while preserving order, only keep same-host seeds, and
            # drop session-destroying URLs (logout/signout/destroy/...) when
            # we're running with auth — otherwise the spider would walk
            # /logout.php with the captured cookie and immediately destroy
            # the session, leaving every subsequent authed request to be
            # bounced to the login page.
            seen_seed = {url}
            for s in extra_seeds:
                if not s or s in seen_seed:
                    continue
                try:
                    sp = urlparse(s)
                    if sp.netloc and sp.netloc != self._base_netloc:
                        continue
                except Exception:
                    continue
                if self._kills_session(s):
                    continue
                seed_list.append(s)
                seen_seed.add(s)
        if emit_fn and len(seed_list) > 1:
            await emit_fn("log", {
                "msg": f"Spider seeds: {len(seed_list)} URLs "
                       f"(root + {len(seed_list)-1} post-auth hints)",
                "level": "info",
            })
        # Pass the shared client + semaphore so URLParser reuses the same
        # connection pool (TCP/TLS keep-alive) and respects the global
        # concurrency ceiling. Without this, URLParser would create a new
        # httpx.AsyncClient per URL and schedule unbounded coroutines.
        html_targets = await parser.parse_many(
            seed_list,
            auth_headers,
            client    = self._http,
            semaphore = self._sem,
        )
        for t in html_targets:
            await self._add_target(t)

        # Phase 2b: auto-fill and SUBMIT every form we found, then walk
        # the post-submission HTML for any additional paths (success
        # pages, redirects after login, search results, etc.) that were
        # invisible to the passive HTML spider.
        self._phase = "form_fill"
        await self._submit_discovered_forms(auth_headers)

        # (Phase 3 fingerprint already ran in parallel with robots/sitemap
        # at the top of _run_phases — no second pass needed.)

        # Phase 4: extract JS endpoints from discovered JS files
        self._phase = "js_extract"
        js_urls = [t.url for t in self.targets if t.url.endswith(".js")]
        js_tasks = [self._extract_js_endpoints(js_url, auth_headers) for js_url in js_urls[:50]]
        await asyncio.gather(*js_tasks)

        # Phase 5: fuzz common endpoints
        self._phase = "fuzz"
        await self._fuzz_common_endpoints(base_url, auth_headers, emit_fn)

        # Phase 6: crawl JS-discovered API paths
        self._phase = "api_walk"
        new_api_paths = [
            urljoin(base_url, ep) for ep in self.js_endpoints
            if ep not in self.visited
        ]
        api_tasks = [self._probe_endpoint(path, auth_headers) for path in new_api_paths[:100]]
        await asyncio.gather(*api_tasks)

        self._phase = "done"
        if emit_fn:
            await emit_fn("crawl_done", {
                "total_endpoints": len(self.targets),
                "tech_stack": self.tech_stack,
                "js_endpoints_found": len(self.js_endpoints),
            })

        return self.targets

    async def _get(self, url: str, auth_headers: dict, **kw):
        """Thin wrapper around self._http.get that respects the global
        semaphore AND increments the in-flight counter. Returns the response
        or raises. Used by every phase that issues a single GET so we get
        uniform backpressure without sprinkling semaphore code everywhere."""
        assert self._http is not None and self._sem is not None, "crawl() must own the client"
        async with self._sem:
            self._in_flight += 1
            try:
                return await self._http.get(url, headers=auth_headers, **kw)
            finally:
                self._in_flight = max(0, self._in_flight - 1)

    async def _parse_robots(self, base_url: str, auth_headers: dict):
        """Parse robots.txt for additional paths."""
        try:
            resp = await self._get(f"{base_url}/robots.txt", auth_headers)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            path = parts[1].strip()
                            if path and path != "/" and "*" not in path:
                                full = urljoin(base_url, path)
                                if full not in self.visited:
                                    self.js_endpoints.append(path)
        except Exception:
            pass

    async def _parse_sitemap(self, base_url: str, auth_headers: dict):
        """Parse sitemap.xml for URLs."""
        try:
            resp = await self._get(f"{base_url}/sitemap.xml", auth_headers)
            if resp.status_code == 200:
                urls = re.findall(r"<loc>(https?://[^<]+)</loc>", resp.text)
                for u in urls[:100]:
                    parsed = urlparse(u)
                    if parsed.netloc == self._base_netloc and u not in self.visited:
                        await self._add_target(ScanTarget(
                            url    = u,
                            method = "GET",
                            source = "sitemap",
                        ))
        except Exception:
            pass

    async def _submit_discovered_forms(self, auth_headers: dict) -> None:
        """
        Phase 2b — OWASP ZAP style. Take every form we discovered during
        the HTML spider, auto-fill type-aware values, POST/GET-submit it,
        and walk the response body for new links/forms the scanner would
        otherwise never see. Skips logout/delete forms (see form_filler
        `should_submit`).

        Parallelised: forms are fetched + submitted via `asyncio.gather`
        over the shared semaphore, so up to `max_concurrency` form flows
        run in parallel. Previously this was a for-loop, serialising 20
        forms × 2 RTTs each = ~40 round-trips serialised.

        We reparse the forms out of the landing HTML because ScanTarget
        objects don't carry the full input list the form_filler needs.
        """
        # Collect all form targets we've already queued. Their actions
        # should be fetched fresh so we have the latest CSRF tokens.
        form_actions = {t.url for t in self.targets if (t.source or "") == "form"}
        if not form_actions:
            return

        submitted_count = 0

        async def handle_one(action: str) -> int:
            nonlocal submitted_count
            local = 0
            try:
                await self._emit_active(action, "GET")
                page = await self._get(action, auth_headers)
                # Passive scan the form page while we have it.
                try:
                    for finding in self._passive.scan_response(
                        action, page.status_code, page.headers, page.text or ""
                    ):
                        self.passive_findings.append(finding)
                except Exception:
                    pass
            except Exception:
                return 0

            forms = _extract_forms(page.text or "", action)
            for form in forms:
                if not should_submit(form):
                    continue
                await self._emit_active(form.get("action", action), form.get("method", "POST"))
                # submit_form owns its own HTTP call (separate module with
                # type-aware value filling). We gate it on the shared
                # semaphore to preserve the global concurrency ceiling.
                try:
                    assert self._sem is not None
                    async with self._sem:
                        self._in_flight += 1
                        try:
                            body, status, final_url = await submit_form(form, auth_headers)
                        finally:
                            self._in_flight = max(0, self._in_flight - 1)
                except Exception:
                    continue
                if not body:
                    continue
                local += 1
                # Passive-scan the submission response too.
                try:
                    for f_ in self._passive.scan_response(final_url, status, {}, body):
                        self.passive_findings.append(f_)
                except Exception:
                    pass
                # Walk the response for new links.
                for link in _extract_links(body, final_url, self._base_netloc):
                    if link in self.visited:
                        continue
                    await self._add_target(ScanTarget(
                        url     = link,
                        method  = "GET",
                        headers = auth_headers.copy(),
                        source  = "form_submit",
                    ))
                # And pull any NEW forms the success page exposes.
                for new_form in _extract_forms(body, final_url):
                    if new_form["action"] not in self.visited:
                        await self._add_target(ScanTarget(
                            url        = new_form["action"],
                            method     = new_form["method"],
                            parameters = new_form["params"],
                            headers    = auth_headers.copy(),
                            source     = "form_submit",
                        ))
            return local

        results = await asyncio.gather(
            *(handle_one(a) for a in list(form_actions)[:20]),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, int):
                submitted_count += r

        if self._emit_fn and submitted_count:
            try:
                await self._emit_fn("crawl_progress", {
                    "url":             f"(submitted {submitted_count} forms)",
                    "method":          "POST",
                    "parameters":      [],
                    "source":          "form_submit",
                    "endpoints_found": len(self.targets),
                })
            except Exception:
                pass

    async def _fingerprint(self, url: str, auth_headers: dict):
        """Detect tech stack from response headers and HTML. Also captures
        a sample of the landing page so the AI explorer has real evidence."""
        try:
            resp = await self._get(url, auth_headers)
            # Stash landing page for AI evidence bundle
            self.landing_html   = resp.text[:3000]
            self.landing_status = resp.status_code
            # Passive scan this response — fire-and-forget findings
            # collected for the engine to persist after crawl ends.
            try:
                for f_ in self._passive.scan_response(
                    url, resp.status_code, resp.headers, resp.text or ""
                ):
                    self.passive_findings.append(f_)
            except Exception:
                pass
            headers_str  = str(dict(resp.headers)).lower()
            body_lower   = resp.text[:5000].lower()
            combined     = headers_str + body_lower

            for tech, sigs in TECH_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in combined:
                        if tech not in self.tech_stack:
                            self.tech_stack.append(tech)
                        break
        except Exception:
            pass

    async def _extract_js_endpoints(self, js_url: str, auth_headers: dict):
        """Extract API routes from a JavaScript file."""
        await self._emit_active(js_url)
        try:
            resp = await self._get(js_url, auth_headers)
            if resp.status_code != 200:
                return
            js_body = resp.text

            # Pattern: fetch('/api/...') or axios.get('/api/...')
            patterns = [
                r"""fetch\s*\(\s*['"`]([/][^'"`\s]+)['"`]""",
                r"""axios\.[a-z]+\s*\(\s*['"`]([/][^'"`\s]+)['"`]""",
                r"""(?:get|post|put|delete|patch)\s*\(\s*['"`]([/][^'"`\s]+)['"`]""",
                r"""(?:url|path|endpoint)\s*[:=]\s*['"`]([/api][^'"`\s]+)['"`]""",
                r"""['"](/api/v\d[^'"]{1,80})['"]""",
                r"""route\s*\(\s*['"`]([/][^'"`\s]+)['"`]""",
            ]
            found = set()
            for pattern in patterns:
                for match in re.findall(pattern, js_body):
                    if match.startswith("/") and len(match) > 2:
                        found.add(match.split("?")[0].rstrip("/") or "/")

            self.js_endpoints.extend(found)

        except Exception:
            pass

    async def _fuzz_common_endpoints(self, base_url: str, auth_headers: dict, emit_fn=None):
        """Try common admin/API/debug endpoints. Uses the shared semaphore
        so we respect one global concurrency ceiling across phases —
        previously every phase had its own semaphore and they could stack
        up, sending 150+ concurrent requests against a tiny target."""
        found = 0

        async def probe(path: str):
            nonlocal found
            url = urljoin(base_url, path)
            if url in self.visited:
                return
            self.visited.add(url)
            await self._emit_active(url)
            try:
                # _get already wraps the semaphore + in_flight bookkeeping
                resp = await self._get(url, auth_headers)
                # Passive scan every response, even 401/403 —
                # those often carry the same security headers as 200s.
                try:
                    for f_ in self._passive.scan_response(
                        url, resp.status_code, resp.headers, resp.text or ""
                    ):
                        self.passive_findings.append(f_)
                except Exception:
                    pass
                if resp.status_code not in (404, 410):
                    params = _get_json_keys(resp.text) if "json" in resp.headers.get("content-type", "") else []
                    await self._add_target(ScanTarget(
                        url        = url,
                        method     = "GET",
                        parameters = params,
                        headers    = auth_headers.copy(),
                        source     = "fuzz",
                    ))
                    found += 1
                else:
                    # Record as evidence so the AI explorer doesn't
                    # re-suggest paths we've already proven don't exist.
                    self.failed_paths.append(path)
            except Exception:
                pass

        tasks = [probe(ep) for ep in COMMON_ENDPOINTS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_endpoint(self, url: str, auth_headers: dict):
        """Probe a single discovered endpoint."""
        if url in self.visited:
            return
        self.visited.add(url)
        await self._emit_active(url)
        try:
            resp = await self._get(url, auth_headers)
            try:
                for f_ in self._passive.scan_response(
                    url, resp.status_code, resp.headers, resp.text or ""
                ):
                    self.passive_findings.append(f_)
            except Exception:
                pass
            if resp.status_code not in (404, 410):
                params = _get_json_keys(resp.text) if "json" in resp.headers.get("content-type", "") else []
                await self._add_target(ScanTarget(
                    url        = url,
                    method     = "GET",
                    parameters = params,
                    headers    = auth_headers.copy(),
                    source     = "js_extracted",
                ))
        except Exception:
            pass

    # ── Evidence-driven AI exploration ────────────────────────────────────

    def get_evidence_bundle(self) -> dict:
        """Snapshot of the crawl state for an AI planner. Uses data the
        spider has already captured during Phase 1-6 so there's no extra
        HTTP cost. Returned dict matches AIBridge.explore_paths() contract."""
        forms = [
            {"action": t.url, "method": (t.method or "POST").upper()}
            for t in self.targets if (t.source or "") == "form"
        ][:10]
        discovered = [
            {
                "url":    t.url,
                "method": (t.method or "GET").upper(),
                "source": t.source or "?",
            }
            for t in self.targets[:30]
        ]
        return {
            "html_sample":  self.landing_html,
            "discovered":   discovered,
            "failed_paths": self.failed_paths[:15],
            "forms":        forms,
            "tech_stack":   list(self.tech_stack),
        }

    async def probe_and_walk(
        self,
        paths: list[str],
        auth_headers: Optional[dict] = None,
        emit_fn=None,
    ) -> list[ScanTarget]:
        """Evidence-driven exploration: HEAD-probe each AI-suggested path,
        keep only the ones that actually respond (2xx/3xx/401/403), then
        recursively walk the live ones through URLParser so their child
        pages get discovered too. Drops dead guesses instead of padding the
        scan target list with 404s. Returns the list of new targets added."""
        if not paths:
            return []
        auth_headers = auth_headers or {}
        self._phase = "ai_walk"
        base_url = f"{self._base_scheme}://{self._base_netloc}"
        before_count = len(self.targets)

        live_seeds: list[str] = []
        live_count = 0
        dead_count = 0

        async def probe(path: str):
            nonlocal live_count, dead_count
            full = urljoin(base_url, path) if path.startswith("/") else path
            if urlparse(full).netloc != self._base_netloc:
                return
            if full in self.visited:
                return
            await self._emit_active(full, "HEAD")
            try:
                assert self._http is not None and self._sem is not None
                async with self._sem:
                    self._in_flight += 1
                    try:
                        try:
                            resp = await self._http.head(full, headers=auth_headers)
                            # Some servers 405/501 on HEAD — fall through to GET.
                            if resp.status_code in (405, 501):
                                resp = await self._http.get(full, headers=auth_headers)
                        except Exception:
                            resp = await self._http.get(full, headers=auth_headers)
                    finally:
                        self._in_flight = max(0, self._in_flight - 1)
                status = resp.status_code
                # Keep pages that exist in any form — 200/201 (public),
                # 3xx (usually login redirects), 401/403 (auth-gated).
                if status in (200, 201, 301, 302, 303, 307, 308, 401, 403):
                    live_seeds.append(full)
                    live_count += 1
                    if emit_fn:
                        await emit_fn("ai_probe", {
                            "url": full, "status": status, "result": "live"
                        })
                else:
                    dead_count += 1
                    if path.startswith("/"):
                        self.failed_paths.append(path)
                    if emit_fn:
                        await emit_fn("ai_probe", {
                            "url": full, "status": status, "result": "dead"
                        })
            except Exception:
                dead_count += 1
                if emit_fn:
                    await emit_fn("ai_probe", {
                        "url": full, "status": 0, "result": "error"
                    })

        await asyncio.gather(*(probe(p) for p in paths), return_exceptions=True)

        if emit_fn:
            await emit_fn("ai_probe_summary", {
                "suggested": len(paths),
                "live":      live_count,
                "dead":      dead_count,
            })

        if not live_seeds:
            return []

        # Tag live seeds so _add_target marks them as source="ai_seed"
        self._ai_seed_set.update(live_seeds)

        # Recursively walk each live seed through URLParser at depth 0 so
        # child pages discovered via links/forms get picked up too. Reuse
        # the shared client + semaphore so this phase also gets keep-alive
        # and respects the global concurrency ceiling.
        parser = URLParser()
        parser.max_pages = self.max_pages
        parser.max_depth = self.max_depth
        html_targets = await parser.parse_many(
            live_seeds,
            auth_headers,
            client    = self._http,
            semaphore = self._sem,
        )
        for t in html_targets:
            await self._add_target(t)

        return self.targets[before_count:]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_json_keys(body: str) -> list[dict]:
    """Extract top-level keys from a JSON response as parameters."""
    try:
        import json
        data = json.loads(body)
        if isinstance(data, dict):
            return [{"name": k, "location": "query", "type": "string"} for k in list(data.keys())[:20]]
    except Exception:
        pass
    return []
