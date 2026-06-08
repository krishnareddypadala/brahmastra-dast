"""
BRAHMASTRA - Passive Security Rules
====================================
Rules that analyze HTTP responses WITHOUT sending attack payloads.
These check for security misconfigurations, missing headers, info leaks.

Based on ZAP's passive scan rules (54 production rules) + industry best practices.
"""

from __future__ import annotations
import re
from brahmastra.narayanastra.rules import Rule


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CSP Analysis (ZAP: ContentSecurityPolicyScanRule 10055)
# ═══════════════════════════════════════════════════════════════════════════════

class CSPAnalysisRule(Rule):
    """Deep Content-Security-Policy analysis. Checks directive quality, not just presence."""
    def __init__(self):
        super().__init__(
            id="csp_analysis", name="Content-Security-Policy Weaknesses",
            severity="MEDIUM", cvss=5.8, category="config", payloads=[], locations=[],
            remediation="Implement strict CSP: script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        csp = (response_headers or {}).get("content-security-policy", "")
        if not csp:
            # Check HTML meta tag
            meta_match = re.search(r'<meta[^>]+content-security-policy[^>]+content=["\']([^"\']+)', response_body or "", re.I)
            csp = meta_match.group(1) if meta_match else ""
        if not csp:
            ct = (response_headers or {}).get("content-type", "")
            if "text/html" in ct.lower():
                return 0.70  # Missing CSP on HTML page
            return 0.0

        issues = []
        csp_lower = csp.lower()
        # Critical weaknesses
        if "'unsafe-inline'" in csp_lower and "script-src" in csp_lower:
            issues.append("unsafe-inline in script-src")
        if "'unsafe-eval'" in csp_lower and "script-src" in csp_lower:
            issues.append("unsafe-eval in script-src")
        if "script-src" in csp_lower and ("* " in csp or csp_lower.endswith("*")):
            issues.append("wildcard in script-src")
        if "data:" in csp_lower and "script-src" in csp_lower:
            issues.append("data: in script-src")
        if "object-src" not in csp_lower:
            issues.append("missing object-src (defaults to allowing plugins)")
        if "base-uri" not in csp_lower:
            issues.append("missing base-uri (allows base tag injection)")
        if "frame-ancestors" not in csp_lower:
            issues.append("missing frame-ancestors (clickjacking risk)")

        if len(issues) >= 3:
            return 0.85
        elif len(issues) >= 1:
            return 0.65
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 2. HSTS Validation (ZAP: StrictTransportSecurityScanRule 10035)
# ═══════════════════════════════════════════════════════════════════════════════

class HSTSValidationRule(Rule):
    """Validate HSTS header presence and configuration quality."""
    MIN_MAX_AGE = 31536000  # 1 year

    def __init__(self):
        super().__init__(
            id="hsts_validation", name="HTTP Strict Transport Security Issues",
            severity="MEDIUM", cvss=5.4, category="config", payloads=[], locations=[],
            remediation="Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        hsts = (response_headers or {}).get("strict-transport-security", "")
        if not hsts:
            return 0.70  # Missing HSTS entirely

        issues = []
        # Check max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts, re.I)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < self.MIN_MAX_AGE:
                issues.append(f"max-age too low ({max_age} < {self.MIN_MAX_AGE})")
            if max_age == 0:
                issues.append("max-age=0 effectively disables HSTS")
        else:
            issues.append("missing max-age directive")

        if "includesubdomains" not in hsts.lower():
            issues.append("missing includeSubDomains")

        if len(issues) >= 2:
            return 0.75
        elif issues:
            return 0.50
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Anti-Clickjacking (ZAP: AntiClickjackingScanRule 10020)
# ═══════════════════════════════════════════════════════════════════════════════

class AntiClickjackingRule(Rule):
    """Check X-Frame-Options and CSP frame-ancestors for clickjacking protection."""
    def __init__(self):
        super().__init__(
            id="anti_clickjacking", name="Missing Anti-Clickjacking Protection",
            severity="MEDIUM", cvss=4.7, category="config", payloads=[], locations=[],
            remediation="Set X-Frame-Options: DENY (or SAMEORIGIN). Also add CSP frame-ancestors 'self'.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        headers = response_headers or {}
        ct = headers.get("content-type", "").lower()
        if "text/html" not in ct:
            return 0.0  # Only relevant for HTML pages

        xfo = headers.get("x-frame-options", "").upper()
        csp = headers.get("content-security-policy", "").lower()
        has_xfo = xfo in ("DENY", "SAMEORIGIN") or xfo.startswith("ALLOW-FROM")
        has_csp_fa = "frame-ancestors" in csp

        if not has_xfo and not has_csp_fa:
            return 0.80  # Neither protection present
        if has_xfo and xfo not in ("DENY", "SAMEORIGIN"):
            return 0.50  # Invalid X-Frame-Options value
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Insecure Authentication (ZAP: InsecureAuthenticationScanRule 10105)
# ═══════════════════════════════════════════════════════════════════════════════

class InsecureAuthRule(Rule):
    """Detect Basic/Digest authentication credentials sent over unencrypted HTTP."""
    def __init__(self):
        super().__init__(
            id="insecure_auth", name="Credentials Sent Over Unencrypted Channel",
            severity="HIGH", cvss=7.5, category="auth", payloads=[], locations=[],
            remediation="Always use HTTPS for authentication. Redirect HTTP to HTTPS before auth.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        headers = response_headers or {}
        # Check if server requests Basic/Digest auth (WWW-Authenticate header)
        www_auth = headers.get("www-authenticate", "").lower()
        if ("basic" in www_auth or "digest" in www_auth):
            return 0.85  # Server requesting cleartext auth
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Session ID in URL (ZAP: InfoSessionIdUrlScanRule 3)
# ═══════════════════════════════════════════════════════════════════════════════

class SessionIdInUrlRule(Rule):
    """Detect session tokens exposed in URLs (leaks via Referer header, logs, bookmarks)."""
    _PATTERNS = [
        re.compile(r'[?&;](jsessionid|phpsessid|sessionid|session_id|sid|ASPSESSIONID|cftoken|cfid)=\w+', re.I),
        re.compile(r';jsessionid=\w+', re.I),  # Java URL rewriting
        re.compile(r'[?&](token|auth_token|access_token)=[a-zA-Z0-9._-]{20,}', re.I),
    ]

    def __init__(self):
        super().__init__(
            id="session_id_url", name="Session ID Exposed in URL",
            severity="MEDIUM", cvss=5.3, category="config", payloads=[], locations=[],
            remediation="Use cookies for session management, not URL parameters. Set Cookie flags properly.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Check response body for links containing session IDs
        for pat in self._PATTERNS:
            if pat.search(response_body or ""):
                return 0.80
        # Check Location header for session ID in redirect
        location = (response_headers or {}).get("location", "")
        for pat in self._PATTERNS:
            if pat.search(location):
                return 0.85
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Private Address Disclosure (ZAP: InfoPrivateAddressDisclosureScanRule 2)
# ═══════════════════════════════════════════════════════════════════════════════

class PrivateAddressDisclosureRule(Rule):
    """Detect RFC 1918 private IP addresses leaked in response body."""
    _PRIVATE_IP = re.compile(
        r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3}'
        r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    )

    def __init__(self):
        super().__init__(
            id="private_address", name="Private IP Address Disclosed",
            severity="LOW", cvss=3.7, category="info", payloads=[], locations=[],
            remediation="Remove internal IP addresses from response bodies and headers. Use reverse proxy.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        matches = self._PRIVATE_IP.findall(body)
        if not matches:
            # Check headers
            for k, v in (response_headers or {}).items():
                if self._PRIVATE_IP.search(str(v)):
                    return 0.75
            return 0.0
        # Filter out common false positives (CSS, JS version numbers)
        real_matches = [m for m in matches if m not in ("127.0.0.1",)]  # localhost is expected in some contexts
        if len(real_matches) >= 2:
            return 0.80
        elif real_matches:
            return 0.60
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Cache Control (ZAP: CacheControlScanRule 10015)
# ═══════════════════════════════════════════════════════════════════════════════

class CacheControlRule(Rule):
    """Detect sensitive pages served without proper cache-control directives."""
    _SENSITIVE_INDICATORS = re.compile(
        r'(?:password|passwd|credit.?card|ssn|social.?security'
        r'|account.?number|login|sign.?in|log.?in|auth)'
        r'.*?(?:<input|<form|type=["\']password)', re.I | re.DOTALL
    )

    def __init__(self):
        super().__init__(
            id="cache_control", name="Sensitive Page Cacheable",
            severity="MEDIUM", cvss=4.3, category="config", payloads=[], locations=[],
            remediation="Add Cache-Control: no-store, no-cache, must-revalidate to sensitive pages.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        headers = response_headers or {}
        ct = headers.get("content-type", "").lower()
        if "text/html" not in ct:
            return 0.0

        # Check if page has sensitive content
        if not self._SENSITIVE_INDICATORS.search(response_body or ""):
            return 0.0

        cc = headers.get("cache-control", "").lower()
        if "no-store" in cc:
            return 0.0  # Properly configured
        if "no-cache" in cc and "must-revalidate" in cc:
            return 0.0  # Acceptable

        pragma = headers.get("pragma", "").lower()
        if "no-cache" in pragma:
            return 0.30  # Legacy but weak

        return 0.70  # Sensitive page without cache protection


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Mixed Content (ZAP: MixedContentScanRule 10001)
# ═══════════════════════════════════════════════════════════════════════════════

class MixedContentRule(Rule):
    """Detect HTTP resources loaded on HTTPS pages (active and passive mixed content)."""
    _HTTP_RESOURCE = re.compile(
        r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']', re.I
    )
    _ACTIVE_MIXED = re.compile(
        r'<(?:script|iframe|object|embed|applet)[^>]+src\s*=\s*["\']http://', re.I
    )

    def __init__(self):
        super().__init__(
            id="mixed_content", name="Mixed Content (HTTP on HTTPS)",
            severity="MEDIUM", cvss=5.0, category="config", payloads=[], locations=[],
            remediation="Use protocol-relative URLs (//) or HTTPS for all resources on HTTPS pages.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        # Active mixed content (scripts/iframes over HTTP) - higher severity
        if self._ACTIVE_MIXED.search(body):
            return 0.85

        # Passive mixed content (images/CSS over HTTP)
        matches = self._HTTP_RESOURCE.findall(body)
        if len(matches) >= 3:
            return 0.65
        elif matches:
            return 0.45
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Hash Disclosure (ZAP: HashDisclosureScanRule 10097)
# ═══════════════════════════════════════════════════════════════════════════════

class HashDisclosureRule(Rule):
    """Detect password hashes leaked in HTTP responses."""
    _PATTERNS = [
        (re.compile(r'\b[a-f0-9]{32}\b'), "MD5"),
        (re.compile(r'\b[a-f0-9]{40}\b'), "SHA-1"),
        (re.compile(r'\b[a-f0-9]{64}\b'), "SHA-256"),
        (re.compile(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'), "bcrypt"),
        (re.compile(r'\$(?:5|6)\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43,86}'), "SHA-crypt"),
    ]
    # False positive patterns (UUIDs, Git SHAs in context, hex colors)
    _UUID_PATTERN = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', re.I)
    _HEX_COLOR = re.compile(r'#[a-f0-9]{6}\b', re.I)

    def __init__(self):
        super().__init__(
            id="hash_disclosure", name="Password Hash Disclosed",
            severity="HIGH", cvss=7.5, category="info", payloads=[], locations=[],
            remediation="Remove password hashes from responses. Never expose hashed credentials to clients.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        if len(body) < 32:
            return 0.0

        for pattern, hash_type in self._PATTERNS:
            matches = pattern.findall(body)
            if not matches:
                continue

            # Filter false positives
            real = []
            for m in matches:
                # Skip UUIDs
                if self._UUID_PATTERN.search(body[max(0, body.index(m)-10):body.index(m)+len(m)+10]):
                    continue
                # Skip hex colors
                if self._HEX_COLOR.search(body[max(0, body.index(m)-1):body.index(m)+len(m)+1]):
                    continue
                # Skip if in baseline (not caused by injection)
                if m in (baseline_body or ""):
                    continue
                real.append(m)

            if hash_type == "bcrypt" and real:
                return 0.90  # bcrypt is definitely a password hash
            if hash_type in ("SHA-crypt",) and real:
                return 0.85
            if len(real) >= 2:
                return 0.70  # Multiple hashes = likely credential dump
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 10. PII Disclosure (ZAP: PiiScanRule 10062)
# ═══════════════════════════════════════════════════════════════════════════════

class PIIDisclosureRule(Rule):
    """Detect credit card numbers and other PII in responses."""
    _CC_PATTERNS = [
        re.compile(r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),       # Visa
        re.compile(r'\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),  # Mastercard
        re.compile(r'\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b'),              # Amex
        re.compile(r'\b6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),  # Discover
    ]
    _SSN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

    def __init__(self):
        super().__init__(
            id="pii_disclosure", name="PII (Credit Card / SSN) Disclosed",
            severity="HIGH", cvss=7.5, category="info", payloads=[], locations=[],
            remediation="Mask or encrypt PII in all responses. Use tokenization for credit card data.",
        )

    @staticmethod
    def _luhn_check(number: str) -> bool:
        """Luhn algorithm to validate credit card numbers."""
        digits = [int(d) for d in number.replace(" ", "").replace("-", "") if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        if len(body) < 13:
            return 0.0

        # Credit card detection with Luhn validation
        for pattern in self._CC_PATTERNS:
            for match in pattern.finditer(body):
                cc_num = match.group()
                if self._luhn_check(cc_num):
                    # Verify not in baseline
                    if cc_num not in (baseline_body or ""):
                        return 0.90

        # SSN detection
        ssn_matches = self._SSN.findall(body)
        ssn_new = [s for s in ssn_matches if s not in (baseline_body or "")]
        if len(ssn_new) >= 2:
            return 0.80
        elif ssn_new:
            return 0.55  # Single SSN might be a phone number format

        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 11. Cookie SameSite (ZAP: CookieSameSiteScanRule 10054)
# ═══════════════════════════════════════════════════════════════════════════════

class CookieSameSiteRule(Rule):
    """Check Set-Cookie headers for missing or weak SameSite attribute."""
    def __init__(self):
        super().__init__(
            id="cookie_samesite", name="Cookie SameSite Missing",
            severity="MEDIUM", cvss=4.7, category="config", payloads=[], locations=[],
            remediation="Set SameSite=Strict (or Lax) on all cookies. Avoid SameSite=None without Secure.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        cookies = _get_all_set_cookies(response_headers)
        if not cookies:
            return 0.0
        issues = 0
        for cookie in cookies:
            c_lower = cookie.lower()
            if "samesite=strict" in c_lower or "samesite=lax" in c_lower:
                continue
            if "samesite=none" in c_lower:
                if "secure" not in c_lower:
                    issues += 1  # SameSite=None without Secure
            else:
                issues += 1  # Missing SameSite entirely
        if issues >= 2:
            return 0.75
        elif issues >= 1:
            return 0.60
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 12. Application Error Disclosure (ZAP: ApplicationErrorScanRule 90022)
# ═══════════════════════════════════════════════════════════════════════════════

class ApplicationErrorRule(Rule):
    """Detect stack traces, SQL errors, and debug info leaked in responses."""
    _PATTERNS = [
        re.compile(r'(?:java\.lang\.\w+Exception|at\s+[\w$.]+\([\w.]+:\d+\))', re.I),
        re.compile(r'(?:Traceback \(most recent call last\)|File ".*?", line \d+)', re.I),
        re.compile(r'(?:Fatal error|Warning):.*?(?:in|on line)\s+[\w/\\.]+(?::\d+|\s+on line \d+)', re.I),
        re.compile(r'(?:Microsoft OLE DB|ODBC|SQL Server|MySQL|PostgreSQL|Oracle).*?(?:error|warning|exception)', re.I),
        re.compile(r'(?:Unhandled Exception|Application Exception|System\.(?:Web|Data)\.\w+Exception)', re.I),
        re.compile(r'(?:syntax error|unexpected token|Parse error|SyntaxError).*?(?:at|near|in)\s+', re.I),
        re.compile(r'<b>(?:Warning|Fatal error|Notice|Parse error)</b>:.*?<b>', re.I),
        re.compile(r'(?:Debug|Stack) ?Trace:', re.I),
    ]

    def __init__(self):
        super().__init__(
            id="app_error", name="Application Error Disclosure",
            severity="MEDIUM", cvss=5.3, category="info", payloads=[], locations=[],
            remediation="Configure custom error pages. Never expose stack traces or debug info in production.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        if len(body) < 50:
            return 0.0
        matches = sum(1 for p in self._PATTERNS if p.search(body))
        if matches >= 3:
            return 0.90
        elif matches >= 2:
            return 0.75
        elif matches >= 1:
            return 0.60
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 13. Suspicious Comments (ZAP: InformationDisclosureSuspiciousComments 10027)
# ═══════════════════════════════════════════════════════════════════════════════

class SuspiciousCommentsRule(Rule):
    """Detect sensitive information in HTML/JS comments."""
    _HTML_COMMENT = re.compile(r'<!--(.*?)-->', re.DOTALL)
    _JS_COMMENT = re.compile(r'/\*\*(.*?)\*/', re.DOTALL)
    _SUSPICIOUS = re.compile(
        r'\b(?:TODO|FIXME|HACK|BUG|XXX|KLUDGE|WORKAROUND'
        r'|password|passwd|secret|admin|credentials|api.?key'
        r'|private.?key|token|debug|test.?account)\b', re.I
    )

    def __init__(self):
        super().__init__(
            id="suspicious_comments", name="Suspicious Comments in HTML",
            severity="LOW", cvss=3.1, category="info", payloads=[], locations=[],
            remediation="Remove developer comments, TODOs, and debug notes before deployment.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        ct = (response_headers or {}).get("content-type", "").lower()
        if "html" not in ct and "javascript" not in ct:
            return 0.0
        suspicious = []
        for m in self._HTML_COMMENT.finditer(body):
            if self._SUSPICIOUS.search(m.group(1)):
                suspicious.append(m.group(1)[:100])
        for m in self._JS_COMMENT.finditer(body):
            if self._SUSPICIOUS.search(m.group(1)):
                suspicious.append(m.group(1)[:100])
        if len(suspicious) >= 3:
            return 0.70
        elif len(suspicious) >= 1:
            return 0.45
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 14. Timestamp Disclosure (ZAP: TimestampDisclosureScanRule 10096)
# ═══════════════════════════════════════════════════════════════════════════════

class TimestampDisclosureRule(Rule):
    """Detect Unix timestamps that leak server time information."""
    _TIMESTAMP = re.compile(r'\b(1[4-9]\d{8}|20\d{8})\b')

    def __init__(self):
        super().__init__(
            id="timestamp_disclosure", name="Timestamp Disclosure",
            severity="LOW", cvss=2.1, category="info", payloads=[], locations=[],
            remediation="Avoid exposing server-side timestamps. Use relative times or opaque tokens.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        ct = (response_headers or {}).get("content-type", "").lower()
        # Skip CSS/JS/images where numeric values are common
        if any(t in ct for t in ("css", "image", "font", "woff")):
            return 0.0
        matches = self._TIMESTAMP.findall(body)
        # Filter: must be in reasonable epoch range (2015-2030)
        import time
        now = int(time.time())
        valid = [m for m in matches if 1420000000 < int(m) < now + 31536000]
        if len(valid) >= 3:
            return 0.50
        elif len(valid) >= 1:
            return 0.30
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 15. Content-Type Missing (ZAP: ContentTypeMissingScanRule 10019)
# ═══════════════════════════════════════════════════════════════════════════════

class ContentTypeMissingRule(Rule):
    """Detect responses without Content-Type header (MIME sniffing risk)."""
    def __init__(self):
        super().__init__(
            id="content_type_missing", name="Content-Type Header Missing",
            severity="MEDIUM", cvss=4.3, category="config", payloads=[], locations=[],
            remediation="Set Content-Type on all responses. Add X-Content-Type-Options: nosniff.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        headers = response_headers or {}
        ct = headers.get("content-type", "")
        if not ct and status_code == 200 and len(response_body or "") > 0:
            return 0.75
        # Content-Type without charset on HTML
        if "text/html" in ct.lower() and "charset" not in ct.lower():
            return 0.40
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 16. Subresource Integrity Missing (ZAP: SubResourceIntegrityAttributeScanRule 90003)
# ═══════════════════════════════════════════════════════════════════════════════

class SubResourceIntegrityRule(Rule):
    """Detect external CDN scripts/styles without SRI integrity attribute."""
    _EXTERNAL_SCRIPT = re.compile(
        r'<script[^>]+src=["\']https?://(?!(?:localhost|127\.0\.0\.1))[^"\']+["\'][^>]*>',
        re.I
    )
    _EXTERNAL_LINK = re.compile(
        r'<link[^>]+href=["\']https?://(?!(?:localhost|127\.0\.0\.1))[^"\']+["\'][^>]*rel=["\']stylesheet["\']',
        re.I
    )
    _HAS_INTEGRITY = re.compile(r'integrity=["\']sha(?:256|384|512)-', re.I)

    def __init__(self):
        super().__init__(
            id="sri_missing", name="Subresource Integrity Missing",
            severity="MEDIUM", cvss=5.3, category="config", payloads=[], locations=[],
            remediation="Add integrity attribute to all external scripts/styles: integrity='sha384-...' crossorigin='anonymous'.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        ct = (response_headers or {}).get("content-type", "").lower()
        if "html" not in ct:
            return 0.0
        missing = 0
        for m in self._EXTERNAL_SCRIPT.finditer(body):
            tag = m.group()
            if not self._HAS_INTEGRITY.search(tag):
                missing += 1
        for m in self._EXTERNAL_LINK.finditer(body):
            tag = m.group()
            if not self._HAS_INTEGRITY.search(tag):
                missing += 1
        if missing >= 3:
            return 0.70
        elif missing >= 1:
            return 0.50
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 17. Permissions-Policy (ZAP: PermissionsPolicyScanRule 10063)
# ═══════════════════════════════════════════════════════════════════════════════

class PermissionsPolicyRule(Rule):
    """Check for missing or weak Permissions-Policy header."""
    def __init__(self):
        super().__init__(
            id="permissions_policy", name="Permissions-Policy Missing",
            severity="MEDIUM", cvss=4.3, category="config", payloads=[], locations=[],
            remediation="Set Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(self).",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        headers = response_headers or {}
        ct = headers.get("content-type", "").lower()
        if "html" not in ct:
            return 0.0
        pp = headers.get("permissions-policy", "")
        fp = headers.get("feature-policy", "")  # Legacy
        if not pp and not fp:
            return 0.60
        # Check if permissive
        policy = (pp or fp).lower()
        if "camera=*" in policy or "microphone=*" in policy or "geolocation=*" in policy:
            return 0.55  # Overly permissive
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 18. Charset Mismatch (ZAP: CharsetMismatchScanRule 90011)
# ═══════════════════════════════════════════════════════════════════════════════

class CharsetMismatchRule(Rule):
    """Detect charset mismatch between HTTP header and HTML meta tag."""
    _META_CHARSET = re.compile(
        r'<meta[^>]+charset=["\']?([a-zA-Z0-9_-]+)', re.I
    )
    _META_HTTP_EQUIV = re.compile(
        r'<meta[^>]+content=["\'][^"\']*charset=([a-zA-Z0-9_-]+)', re.I
    )

    def __init__(self):
        super().__init__(
            id="charset_mismatch", name="Charset Mismatch",
            severity="LOW", cvss=3.1, category="config", payloads=[], locations=[],
            remediation="Ensure Content-Type header charset matches HTML meta charset. Prefer UTF-8.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        headers = response_headers or {}
        ct = headers.get("content-type", "").lower()
        if "html" not in ct:
            return 0.0
        # Extract charset from Content-Type header
        header_charset = ""
        if "charset=" in ct:
            header_charset = ct.split("charset=")[-1].strip().rstrip(";").strip()
        # Extract charset from HTML meta
        body = response_body or ""
        meta_match = self._META_CHARSET.search(body) or self._META_HTTP_EQUIV.search(body)
        meta_charset = meta_match.group(1).lower() if meta_match else ""
        if not header_charset or not meta_charset:
            return 0.0
        # Normalize
        h = header_charset.replace("-", "").replace("_", "").lower()
        m = meta_charset.replace("-", "").replace("_", "").lower()
        if h != m:
            return 0.60
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 19. X-Powered-By Disclosure (ZAP: XPoweredByHeaderInfoLeakScanRule 10037)
# ═══════════════════════════════════════════════════════════════════════════════

class XPoweredByRule(Rule):
    """Detect X-Powered-By and similar technology disclosure headers."""
    _TECH_HEADERS = [
        "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "x-generator", "x-drupal-cache", "x-varnish",
        "x-debug-token", "x-debug-token-link",
    ]

    def __init__(self):
        super().__init__(
            id="x_powered_by", name="X-Powered-By Disclosed",
            severity="LOW", cvss=3.7, category="info", payloads=[], locations=[],
            remediation="Remove X-Powered-By and similar technology disclosure headers from responses.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        headers = response_headers or {}
        found = []
        for h in self._TECH_HEADERS:
            val = headers.get(h, "")
            if val:
                found.append(f"{h}: {val}")
        if len(found) >= 2:
            return 0.70
        elif found:
            return 0.50
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 20. Cross-Domain Misconfiguration (ZAP: CrossDomainMisconfiguration 10098)
# ═══════════════════════════════════════════════════════════════════════════════

class CrossDomainMisconfigRule(Rule):
    """Detect permissive crossdomain.xml or clientaccesspolicy.xml."""
    _ALLOW_ALL = re.compile(r'<allow-access-from\s+domain=["\']\*["\']', re.I)
    _ALLOW_HEADERS = re.compile(r'<allow-http-request-headers-from\s+domain=["\']\*["\']', re.I)

    def __init__(self):
        super().__init__(
            id="crossdomain_misconfig", name="Cross-Domain Misconfiguration",
            severity="MEDIUM", cvss=5.3, category="config", payloads=[], locations=[],
            remediation="Restrict crossdomain.xml to specific trusted domains. Never use domain='*'.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        if status_code != 200:
            return 0.0
        if "<cross-domain-policy" not in body and "<access-policy" not in body:
            return 0.0
        if self._ALLOW_ALL.search(body):
            return 0.85
        if self._ALLOW_HEADERS.search(body):
            return 0.70
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 21. User-Controlled Cookie (ZAP: UserControlledCookieScanRule 10029)
# ═══════════════════════════════════════════════════════════════════════════════

class UserControlledCookieRule(Rule):
    """Detect user input reflected in Set-Cookie header (cookie injection)."""
    def __init__(self):
        super().__init__(
            id="user_controlled_cookie", name="User Input in Set-Cookie",
            severity="MEDIUM", cvss=5.3, category="injection", payloads=[], locations=[],
            remediation="Never reflect user input in Set-Cookie headers. Validate and sanitize cookie values server-side.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if not payload:
            return 0.0
        cookies = _get_all_set_cookies(response_headers)
        for cookie in cookies:
            if payload and len(payload) >= 4 and payload in cookie:
                # Verify not in baseline cookies
                baseline_cookies = _get_all_set_cookies({})  # empty
                if not any(payload in bc for bc in baseline_cookies):
                    return 0.70
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 22. Big Redirect (ZAP: BigRedirectsScanRule 10044)
# ═══════════════════════════════════════════════════════════════════════════════

class BigRedirectRule(Rule):
    """Detect redirect responses with unusually large bodies (potential data leak)."""
    def __init__(self):
        super().__init__(
            id="big_redirect", name="Large Redirect Body",
            severity="LOW", cvss=3.1, category="info", payloads=[], locations=[],
            remediation="Redirect responses (3xx) should have minimal or empty bodies. Remove sensitive content.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code not in (301, 302, 303, 307, 308):
            return 0.0
        body_len = len(response_body or "")
        if body_len > 2000:
            return 0.65
        elif body_len > 500:
            return 0.40
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 23. ASP.NET ViewState (ZAP: ViewStateScanRule 10032)
# ═══════════════════════════════════════════════════════════════════════════════

class ViewStateRule(Rule):
    """Detect ASP.NET ViewState without MAC protection."""
    _VIEWSTATE = re.compile(r'<input[^>]+name=["\']__VIEWSTATE["\'][^>]+value=["\']([^"\']+)', re.I)
    _VIEWSTATE_GEN = re.compile(r'<input[^>]+name=["\']__VIEWSTATEGENERATOR["\']', re.I)
    _EVENT_VALIDATION = re.compile(r'<input[^>]+name=["\']__EVENTVALIDATION["\']', re.I)

    def __init__(self):
        super().__init__(
            id="viewstate", name="ASP.NET ViewState without MAC",
            severity="HIGH", cvss=6.5, category="config", payloads=[], locations=[],
            remediation="Enable ViewState MAC validation: <pages enableViewStateMac='true' /> in web.config.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        vs_match = self._VIEWSTATE.search(body)
        if not vs_match:
            return 0.0
        vs_value = vs_match.group(1)
        # ViewState present but no MAC protection indicators
        has_generator = bool(self._VIEWSTATE_GEN.search(body))
        has_event_val = bool(self._EVENT_VALIDATION.search(body))
        if not has_generator and not has_event_val:
            # Large ViewState without protection = high risk
            if len(vs_value) > 100:
                return 0.75
            return 0.55
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 24. Referrer Policy Leak (ZAP: InformationDisclosureReferrerPolicyScanRule 10025)
# ═══════════════════════════════════════════════════════════════════════════════

class ReferrerLeakRule(Rule):
    """Detect missing Referrer-Policy allowing sensitive URL params to leak."""
    def __init__(self):
        super().__init__(
            id="referrer_leak", name="Referrer Policy Leak",
            severity="MEDIUM", cvss=4.3, category="config", payloads=[], locations=[],
            remediation="Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for sensitive pages).",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        headers = response_headers or {}
        ct = headers.get("content-type", "").lower()
        if "html" not in ct:
            return 0.0
        rp = headers.get("referrer-policy", "")
        # Check meta tag too
        body = response_body or ""
        meta_rp = re.search(r'<meta[^>]+name=["\']referrer["\'][^>]+content=["\']([^"\']+)', body, re.I)
        policy = rp or (meta_rp.group(1) if meta_rp else "")
        if not policy:
            return 0.55  # Missing entirely
        safe = ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin")
        if policy.lower().strip() not in safe:
            return 0.40  # Weak policy (e.g., "unsafe-url", "origin")
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# Helper: extract all Set-Cookie headers
# ═══════════════════════════════════════════════════════════════════════════════

def _get_all_set_cookies(headers: dict | None) -> list[str]:
    """Extract Set-Cookie values from response headers (handles multi-value)."""
    if not headers:
        return []
    cookies = []
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie":
            if isinstance(v, list):
                cookies.extend(v)
            else:
                cookies.append(str(v))
    return cookies


# ═══════════════════════════════════════════════════════════════════════════════
# EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

PASSIVE_RULES = [
    CSPAnalysisRule,
    HSTSValidationRule,
    AntiClickjackingRule,
    InsecureAuthRule,
    SessionIdInUrlRule,
    PrivateAddressDisclosureRule,
    CacheControlRule,
    MixedContentRule,
    HashDisclosureRule,
    PIIDisclosureRule,
    # New rules (11-24)
    CookieSameSiteRule,
    ApplicationErrorRule,
    SuspiciousCommentsRule,
    TimestampDisclosureRule,
    ContentTypeMissingRule,
    SubResourceIntegrityRule,
    PermissionsPolicyRule,
    CharsetMismatchRule,
    XPoweredByRule,
    CrossDomainMisconfigRule,
    UserControlledCookieRule,
    BigRedirectRule,
    ViewStateRule,
    ReferrerLeakRule,
]

def get_passive_rules() -> list[Rule]:
    return [cls() for cls in PASSIVE_RULES]
