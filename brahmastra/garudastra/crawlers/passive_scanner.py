"""
BRAHMASTRA — Garudastra: Passive Scanner

OWASP ZAP-inspired passive scan rules. Runs on EVERY crawler response
(no extra HTTP cost) and emits low-noise findings about:

  - Missing or misconfigured security headers
      Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
      X-Content-Type-Options, Referrer-Policy, Permissions-Policy
  - Insecure cookies
      Missing Secure / HttpOnly / SameSite attributes
  - Server/tech fingerprint disclosure
      Server, X-Powered-By, X-AspNet-Version, X-Runtime headers
  - HTML comments containing "TODO", "FIXME", "DEBUG", "password",
    "apikey", credentials, internal IPs
  - Obvious error pages / stack traces leaked into the body
      Java/PHP/Python/ASP.NET tracebacks

Passive scan findings are always LOW or INFO severity — they're
configuration hygiene issues, not exploitable bugs. The active rule
engine (sudarshana) still runs independently; this module just
opportunistically harvests the crawl traffic that's already happening
for findings the spider would otherwise throw away.

Usage contract:
  scanner = PassiveScanner()
  findings = scanner.scan_response(url, status, headers, body)
  for f in findings:
      await emit("finding", f)
      await save_finding(scan_id, f)

Each finding is a dict shaped for server/db.py:save_finding().
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlparse


# ─── Header checks ───────────────────────────────────────────────────────────

# header-name → (severity, vuln_type, remediation) for MISSING headers.
_REQUIRED_HEADERS: dict[str, tuple[str, str, str]] = {
    "content-security-policy": (
        "LOW", "Missing Content-Security-Policy",
        "Set a restrictive CSP header to mitigate XSS and data injection. "
        "Start with `default-src 'self'; object-src 'none'; base-uri 'self'`.",
    ),
    "strict-transport-security": (
        "LOW", "Missing HSTS header",
        "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses.",
    ),
    "x-frame-options": (
        "LOW", "Missing X-Frame-Options (clickjacking)",
        "Set `X-Frame-Options: DENY` or use `frame-ancestors 'none'` in CSP.",
    ),
    "x-content-type-options": (
        "LOW", "Missing X-Content-Type-Options",
        "Set `X-Content-Type-Options: nosniff` to block MIME sniffing.",
    ),
    "referrer-policy": (
        "LOW", "Missing Referrer-Policy",
        "Set `Referrer-Policy: strict-origin-when-cross-origin` to limit referer leakage.",
    ),
}

# Fingerprint-disclosure headers — server tells attackers what it's running.
_FINGERPRINT_HEADERS: set[str] = {
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-runtime", "x-generator", "x-drupal-cache", "x-varnish",
}


def _check_headers(url: str, status: int, headers: dict[str, str]) -> Iterable[dict[str, Any]]:
    """
    Inspect the response headers for missing/extra disclosures.

    `headers` keys are assumed case-insensitive (httpx.Headers already is)
    but we normalize for safety.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    scheme = urlparse(url).scheme

    # Missing required headers
    for h_name, (sev, vtype, remedy) in _REQUIRED_HEADERS.items():
        # HSTS is only meaningful on HTTPS responses
        if h_name == "strict-transport-security" and scheme != "https":
            continue
        if h_name not in lowered:
            yield {
                "severity":    sev,
                "type":        vtype,
                "url":         url,
                "parameter":   "",
                "evidence":    f"Response from {url} did not include {h_name} header.",
                "cvss":        2.6,
                "remediation": remedy,
                "payload":     "",
                "source":      "passive",
            }

    # Tech fingerprint disclosure
    for h_name in _FINGERPRINT_HEADERS:
        if h_name in lowered:
            yield {
                "severity":    "LOW",
                "type":        "Server/tech fingerprint disclosure",
                "url":         url,
                "parameter":   h_name,
                "evidence":    f"{h_name}: {lowered[h_name]}",
                "cvss":        1.9,
                "remediation": (
                    f"Remove or obfuscate the `{h_name}` response header to prevent "
                    "attackers from fingerprinting the server stack."
                ),
                "payload":     "",
                "source":      "passive",
            }


# ─── Cookie checks ───────────────────────────────────────────────────────────

def _check_cookies(url: str, headers: dict[str, str]) -> Iterable[dict[str, Any]]:
    """
    Flag cookies that are missing Secure / HttpOnly / SameSite.

    httpx.Headers can carry multiple `set-cookie` values — we enumerate
    both the dict form (single header) and the multi-value form.
    """
    raw_values: list[str] = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            raw_values.append(v)
    # httpx Headers objects also support .get_list; try that as a fallback.
    get_list = getattr(headers, "get_list", None)
    if callable(get_list):
        try:
            raw_values = list(get_list("set-cookie")) or raw_values
        except Exception:
            pass

    scheme = urlparse(url).scheme
    for cookie_hdr in raw_values:
        # Cookie name = first token before '='
        name_match = re.match(r"\s*([^=;]+)=", cookie_hdr)
        if not name_match:
            continue
        cookie_name = name_match.group(1).strip()
        lower = cookie_hdr.lower()

        issues: list[str] = []
        if scheme == "https" and "secure" not in lower:
            issues.append("missing Secure")
        if "httponly" not in lower:
            issues.append("missing HttpOnly")
        if "samesite" not in lower:
            issues.append("missing SameSite")

        if issues:
            yield {
                "severity":    "LOW",
                "type":        "Insecure cookie flags",
                "url":         url,
                "parameter":   cookie_name,
                "evidence":    f"Cookie `{cookie_name}` is {', '.join(issues)}.",
                "cvss":        3.1,
                "remediation": (
                    "Set cookies with `Secure; HttpOnly; SameSite=Lax` (or Strict) so "
                    "they cannot be read by JavaScript or sent over plaintext."
                ),
                "payload":     "",
                "source":      "passive",
            }


# ─── Body checks ─────────────────────────────────────────────────────────────

# Regexes that flag things that should never appear in production HTML.
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_LEAK_IN_COMMENT = re.compile(
    r"(?i)\b("
    r"todo|fixme|hack|xxx|debug|password|passwd|api[_-]?key|"
    r"secret|token|bearer|access[_-]?key|private[_-]?key|"
    r"aws|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+"
    r")\b"
)

# Stack-trace / error-page signatures (framework-keyed).
_STACK_TRACE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Traceback \(most recent call last\):"),         "Python traceback"),
    (re.compile(r"java\.lang\.\w+Exception"),                      "Java stack trace"),
    (re.compile(r"PHP (Warning|Fatal error|Parse error|Notice)"),  "PHP error"),
    (re.compile(r"Microsoft OLE DB Provider for"),                 "ASP.NET/OLE DB error"),
    (re.compile(r"ORA-\d{5}"),                                     "Oracle DB error"),
    (re.compile(r"Warning: mysql_\w+\(\)"),                        "MySQL error"),
    (re.compile(r"System\.Web\.\w+Exception"),                     ".NET exception"),
    (re.compile(r"Ruby on Rails.{0,40}(exception|error)", re.I),   "Rails exception"),
]


def _check_body(url: str, body: str) -> Iterable[dict[str, Any]]:
    """Flag HTML-comment leaks and server stack traces in the body."""
    if not body:
        return

    # HTML comments — only take the first 20 matches so a 10MB page
    # with an absurd number of comments doesn't hog CPU.
    for m in list(_COMMENT_RE.finditer(body))[:20]:
        comment = m.group(1)
        leak = _LEAK_IN_COMMENT.search(comment)
        if leak:
            snippet = comment.strip()
            if len(snippet) > 160:
                snippet = snippet[:160] + "..."
            yield {
                "severity":    "LOW",
                "type":        "Sensitive data in HTML comment",
                "url":         url,
                "parameter":   "",
                "evidence":    f"Keyword `{leak.group(1)}` found in HTML comment: {snippet!r}",
                "cvss":        3.4,
                "remediation": (
                    "Strip HTML comments containing debug notes, TODOs, credentials, "
                    "API keys, or internal IPs before deploying to production."
                ),
                "payload":     "",
                "source":      "passive",
            }

    # Stack traces leaking into the response body.
    for pat, label in _STACK_TRACE_PATTERNS:
        m = pat.search(body)
        if m:
            yield {
                "severity":    "MEDIUM",
                "type":        "Verbose error / stack trace disclosure",
                "url":         url,
                "parameter":   "",
                "evidence":    f"{label} detected in response body near: {m.group(0)!r}",
                "cvss":        4.3,
                "remediation": (
                    "Disable verbose error output in production. Return a generic "
                    "error page and log the full stack trace server-side only."
                ),
                "payload":     "",
                "source":      "passive",
            }
            break  # one stack-trace finding per response is enough


# ─── Public API ──────────────────────────────────────────────────────────────

class PassiveScanner:
    """
    Scoped passive scanner. Deduplicates findings so we don't emit
    "missing X-Frame-Options" 500 times — once per (vuln_type, url_path)
    is enough.
    """

    def __init__(self) -> None:
        # (vuln_type, url_path, parameter) already reported in this scan
        self._seen: set[tuple[str, str, str]] = set()

    def scan_response(
        self,
        url: str,
        status: int,
        headers: dict[str, str] | Any,
        body: str,
    ) -> list[dict[str, Any]]:
        """Run all passive checks against one response. Returns list of findings."""
        # Normalize headers to a plain dict if we got httpx.Headers
        hdr_dict: dict[str, str]
        if hasattr(headers, "items"):
            hdr_dict = dict(headers)
        else:
            hdr_dict = {}

        out: list[dict[str, Any]] = []
        for f in _check_headers(url, status, hdr_dict):
            if self._dedup(f):
                out.append(f)
        # Cookie checks need the raw httpx.Headers (multi-value support)
        for f in _check_cookies(url, headers):
            if self._dedup(f):
                out.append(f)
        for f in _check_body(url, body or ""):
            if self._dedup(f):
                out.append(f)
        return out

    def _dedup(self, finding: dict[str, Any]) -> bool:
        """Return True if this finding is new (should be reported)."""
        path = urlparse(finding.get("url", "")).path or "/"
        key = (finding.get("type", ""), path, finding.get("parameter", ""))
        if key in self._seen:
            return False
        self._seen.add(key)
        return True
