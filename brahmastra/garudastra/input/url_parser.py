"""
BRAHMASTRA — Garudastra: URL Parser
Given a base URL, crawls the target and discovers endpoints + parameters.
Returns a list of ScanTarget objects ready for the agent.

Crawl strategy:
  1. HTML link/form spider (html_crawler)
  2. JavaScript API route extraction (js_crawler)
  3. Endpoint wordlist fuzzing (wordlist_crawler) if depth requested
"""

import asyncio
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from typing import Optional

import httpx

from brahmastra.sudarshana.base import ScanTarget


# Path substrings that, if visited while authenticated, will log us out.
# Mirrored in spider.py and engine.py — keep all three lists in sync.
_SESSION_DESTROYING_TOKENS = (
    "logout", "log-out", "log_out",
    "signout", "sign-out", "sign_out",
    "destroy", "kill_session", "killsession",
    "/end_session", "endsession",
)


class URLParser:
    """Parse a base URL and discover all testable endpoints."""

    def __init__(self):
        self.visited: set[str]    = set()
        self.targets: list[ScanTarget] = []
        self.max_pages: int       = 200
        self.max_depth: int       = 3
        # Set True by parse_many() when auth_headers is non-empty so the
        # session-destroying URL guard fires only on authenticated crawls.
        self._authed: bool        = False
        # Shared HTTP client + global concurrency ceiling, injected from
        # Spider.crawl() when URLParser is embedded in the full pipeline.
        # When either is None we fall back to per-URL throwaway clients
        # (kept for standalone usage / unit tests). Using a shared client
        # is a large speedup on HTTPS targets — previously _crawl_url()
        # created a brand-new httpx.AsyncClient on every hop, forcing a
        # fresh TCP+TLS handshake for each page. With the shared client we
        # also respect one global concurrency limit across every phase
        # of the spider instead of each recursion level doing unbounded
        # asyncio.gather fan-outs.
        self._http: Optional["httpx.AsyncClient"] = None
        self._sem:  Optional[asyncio.Semaphore]   = None

    def _kills_session(self, url: str) -> bool:
        if not self._authed:
            return False
        try:
            path = (urlparse(url).path or "").lower()
        except Exception:
            return False
        return any(tok in path for tok in _SESSION_DESTROYING_TOKENS)

    async def parse(
        self,
        url: str,
        auth_headers: Optional[dict] = None,
        *,
        client: Optional[httpx.AsyncClient] = None,
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> list[ScanTarget]:
        """
        Entry point: crawl from URL and return discovered ScanTargets.
        auth_headers: optional dict of Authorization/Cookie headers.
        """
        return await self.parse_many(
            [url], auth_headers, client=client, semaphore=semaphore
        )

    async def parse_many(
        self,
        seed_urls: list[str],
        auth_headers: Optional[dict] = None,
        *,
        client: Optional[httpx.AsyncClient] = None,
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> list[ScanTarget]:
        """
        Crawl from multiple seed URLs in parallel — same logic as parse(),
        but lets the engine inject AI-suggested entry points alongside the
        base URL so the spider walks each one recursively.

        Optional kwargs:
          client    — a shared httpx.AsyncClient whose connection pool and
                      keep-alive slots are reused across every GET. Spider
                      passes its own pool here so one TLS handshake covers
                      the whole crawl.
          semaphore — global concurrency ceiling. Every GET issued by this
                      parser acquires the semaphore before firing, giving
                      the whole Spider pipeline a single backpressure point
                      instead of each recursion level fanning out unbounded.
        """
        self.visited = set()
        self.targets = []
        self.global_headers = auth_headers or {}
        self._http = client
        self._sem  = semaphore
        # Mark this crawl as authenticated so _kills_session() actually
        # rejects logout/signout/destroy URLs. Without this guard, the
        # spider would happily walk /logout.php with the captured cookie
        # and immediately invalidate the session, leaving every other
        # authenticated request bouncing back to the login page.
        self._authed = bool(self.global_headers)

        if not seed_urls:
            return self.targets

        # Strip session-destroying seeds up-front (defence in depth — the
        # caller already filters them, but if anyone bypasses parse_many()
        # this still keeps an authenticated crawl alive).
        seed_urls = [u for u in seed_urls if not self._kills_session(u)]
        if not seed_urls:
            return self.targets

        # Base scope is taken from the first seed (always the user-supplied target)
        base = urlparse(seed_urls[0])
        self.base_scheme = base.scheme
        self.base_netloc = base.netloc

        # Walk all seeds at depth 0 in parallel. Caller is responsible for
        # passing same-domain absolute URLs (engine.py urljoin's AI-suggested
        # paths against the base before handing them in).
        await asyncio.gather(
            *(self._crawl_url(u, depth=0) for u in seed_urls),
            return_exceptions=True,
        )
        return self.targets

    async def _fetch(self, url: str):
        """Issue a GET through the shared client+semaphore if Spider gave us
        one, otherwise fall back to a throwaway per-call client. Centralised
        here so _crawl_url() stays readable and every code path respects the
        global concurrency ceiling when it exists."""
        if self._http is not None and self._sem is not None:
            async with self._sem:
                return await self._http.get(url, headers=self.global_headers)
        # Standalone fallback — URLParser used outside the Spider pipeline.
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=10
        ) as client:
            return await client.get(url, headers=self.global_headers)

    async def _crawl_url(self, url: str, depth: int):
        if url in self.visited or len(self.visited) >= self.max_pages or depth > self.max_depth:
            return
        # Hard-block logout/signout/destroy URLs while authenticated. The
        # check is duplicated in spider._add_target() and engine seed
        # builder so a careless edit to one layer can never silently
        # destroy a session mid-crawl.
        if self._kills_session(url):
            return
        self.visited.add(url)

        try:
            resp = await self._fetch(url)
        except Exception:
            return

        # Add this URL as a scan target (GET with query params)
        parsed = urlparse(url)
        params = _parse_query_params(parsed.query)
        if params or not self.targets:   # Always add the base URL
            self.targets.append(ScanTarget(
                url        = url,
                method     = "GET",
                parameters = params,
                headers    = self.global_headers.copy(),
                source     = "url",
            ))

        # Extract forms (POST targets)
        forms = _extract_forms(resp.text, url)
        for form in forms:
            if form["action"] not in self.visited:
                self.visited.add(form["action"])
                self.targets.append(ScanTarget(
                    url        = form["action"],
                    method     = form["method"],
                    parameters = form["params"],
                    headers    = self.global_headers.copy(),
                    source     = "form",
                ))

        if depth < self.max_depth:
            # Follow links on the same domain — slice URLs first so we never
            # create coroutine objects that go unawaited (RuntimeWarning).
            # Skip logout/signout/destroy links during authed crawls.
            links = [
                link for link in _extract_links(resp.text, url, self.base_netloc)
                if link not in self.visited and not self._kills_session(link)
            ][:30]
            await asyncio.gather(*(self._crawl_url(link, depth + 1) for link in links))


# ─── HTML parsing helpers ────────────────────────────────────────────────────

def _parse_query_params(query_string: str) -> list[dict]:
    """Parse query string into list of parameter dicts."""
    if not query_string:
        return []
    params = parse_qs(query_string, keep_blank_values=True)
    return [{"name": k, "location": "query", "type": "string"} for k in params]


def _extract_links(html: str, base_url: str, base_netloc: str) -> list[str]:
    """
    Extract same-domain links from an HTML/JS/CSS response.

    Beyond the classic `href="..."` extractor, this now pulls:
      - `src="..."` (scripts, images, iframes → reveal SPA bundles)
      - `action="..."` (form actions, in case they escape _extract_forms)
      - `data-*` attributes holding URLs (Alpine.js / HTMX / Vue bindings)
      - URLs inside HTML comments (often leak staging paths)
      - JS string literals that look like paths (`/api/...`, `'/admin/...'`)
      - CSS `url(...)` references
      - JSON-embedded paths in `<script type="application/json">`

    The goal matches OWASP ZAP's DefaultParser: miss as few same-domain
    URLs as possible so downstream phases (passive scan, rule engine,
    AI strategist) get the widest crawl surface we can build.
    """
    import re
    links: set[str] = set()

    def _accept(raw: str) -> None:
        raw = (raw or "").strip().strip("'\"")
        if not raw:
            return
        if raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
            return
        # Skip obvious non-URLs (template placeholders, format strings)
        if "{" in raw or "}" in raw or "${" in raw:
            return
        full = urljoin(base_url, raw)
        parsed = urlparse(full)
        if parsed.netloc != base_netloc or parsed.scheme not in ("http", "https"):
            return
        clean = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, "")
        )
        links.add(clean)

    # Classic attribute extractors (href/src/action/formaction/poster).
    for attr in ("href", "src", "action", "formaction", "poster"):
        for m in re.finditer(
            rf'{attr}=["\']([^"\']+)["\']', html, re.IGNORECASE
        ):
            _accept(m.group(1))

    # HTML5 data-* attributes holding URLs (HTMX, Alpine, Vue).
    for m in re.finditer(
        r'data-(?:url|src|href|endpoint|api|action)=["\']([^"\']+)["\']',
        html, re.IGNORECASE,
    ):
        _accept(m.group(1))

    # URLs leaked in HTML comments (first 10 kB to keep it cheap).
    for comment in re.findall(r"<!--(.*?)-->", html[:10000], re.DOTALL):
        for m in re.finditer(r"""['\"]?(/[A-Za-z0-9_\-./]{2,})['\"]?""", comment):
            _accept(m.group(1))

    # CSS url(...) references.
    for m in re.finditer(r"url\(\s*['\"]?([^)'\"]+)['\"]?\s*\)", html, re.IGNORECASE):
        _accept(m.group(1))

    # JS string literals that look like site paths. Scope this to inline
    # <script> blocks so we don't accidentally match arbitrary strings
    # in the surrounding markup.
    for script in re.findall(
        r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
        html, re.IGNORECASE | re.DOTALL,
    )[:20]:
        for m in re.finditer(r"""['"`](/[A-Za-z0-9_\-./]{2,})['"`]""", script):
            _accept(m.group(1))

    # application/json script blocks (e.g. Next.js __NEXT_DATA__).
    for block in re.findall(
        r'<script[^>]*type=["\']application/(?:json|ld\+json)["\'][^>]*>(.*?)</script>',
        html, re.IGNORECASE | re.DOTALL,
    )[:5]:
        for m in re.finditer(r'"(/[A-Za-z0-9_\-./]{2,})"', block):
            _accept(m.group(1))

    return list(links)


def _extract_forms(html: str, base_url: str) -> list[dict]:
    """Extract form actions and inputs from HTML."""
    import re
    forms = []

    # Find all <form> blocks
    form_blocks = re.findall(r"<form[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
    form_tags   = re.findall(r"<form([^>]*)>", html, re.IGNORECASE)

    for i, (tag, block) in enumerate(zip(form_tags, form_blocks)):
        # Get action
        action_match = re.search(r'action=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        action = urljoin(base_url, action_match.group(1)) if action_match else base_url

        # Get method
        method_match = re.search(r'method=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        method = (method_match.group(1).upper() if method_match else "GET")

        # Get inputs — also capture the value= attribute so form_filler
        # can preserve CSRF tokens / hidden nonces when resubmitting.
        inputs = []
        for inp in re.finditer(r'<input([^>]*)>', block, re.IGNORECASE):
            inp_attrs = inp.group(1)
            name_m  = re.search(r'name=["\']([^"\']+)["\']',  inp_attrs, re.IGNORECASE)
            type_m  = re.search(r'type=["\']([^"\']+)["\']',  inp_attrs, re.IGNORECASE)
            value_m = re.search(r'value=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
            if name_m:
                inputs.append({
                    "name":     name_m.group(1),
                    "type":     type_m.group(1) if type_m else "text",
                    "value":    value_m.group(1) if value_m else "",
                    "location": "body" if method == "POST" else "query",
                })

        # Also pick up <textarea> and <select>
        for inp in re.finditer(r'<(?:textarea|select)[^>]*name=["\']([^"\']+)["\']', block, re.IGNORECASE):
            inputs.append({
                "name":     inp.group(1),
                "type":     "string",
                "value":    "",
                "location": "body",
            })

        if inputs:
            forms.append({"action": action, "method": method, "params": inputs})

    return forms
