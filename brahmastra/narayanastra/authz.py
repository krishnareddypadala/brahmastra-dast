"""
BRAHMASTRA — Narayanastra: Authorization Tester
Tests for broken authorization: IDOR, privilege escalation, forced browsing.

AuthZTester:
  - test_idor(targets, auth_headers)         → ID tampering with single auth
  - test_horizontal_idor(targets, headers_a, headers_b) → cross-user access
  - test_privilege_escalation(targets, auth_headers, admin_paths) → vertical privesc
  - test_forced_browsing(base_url, auth_headers) → common admin/debug paths
"""

from __future__ import annotations
import asyncio
import re
from urllib.parse import urlparse, parse_qs
from typing import Optional

import httpx

from brahmastra.sudarshana.base import Finding, ScanTarget


# Common admin/debug paths for forced browsing
FORCED_BROWSING_PATHS = [
    # Admin panels
    "/admin", "/admin/", "/admin/login", "/admin/users",
    "/admin/dashboard", "/admin/settings", "/admin/config",
    "/administrator", "/administrator/",
    "/superuser", "/root", "/manage", "/management",
    "/staff", "/moderator",
    # API admin
    "/api/admin", "/api/v1/admin", "/api/v2/admin",
    "/api/admin/users", "/api/admin/settings",
    # Debug / dev
    "/debug", "/dev", "/test", "/staging",
    "/console", "/shell",
    # Spring Boot Actuator
    "/actuator", "/actuator/env", "/actuator/beans",
    "/actuator/httptrace", "/actuator/logfile",
    "/actuator/shutdown",
    # PHP
    "/phpinfo.php", "/php_info.php", "/phpinfo",
    "/info.php", "/test.php",
    # Server status
    "/server-status", "/server-info", "/nginx_status",
    # Secrets
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/config.php", "/config.json", "/config.yaml",
    "/wp-config.php", "/settings.py", "/database.yml",
    # Backup files
    "/backup", "/backup.zip", "/backup.sql",
    "/db.sql", "/dump.sql",
]

ADMIN_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]


class AuthZTester:
    """
    Test authorization vulnerabilities.
    Findings returned as list[Finding].
    """

    def __init__(self, timeout: float = 8.0, concurrency: int = 10):
        self.timeout     = timeout
        self.concurrency = concurrency

    async def test_idor(
        self,
        targets: list[ScanTarget],
        auth_headers: dict,
        emit_fn=None,
    ) -> list[Finding]:
        """
        ID-tampering IDOR test.
        For each numeric ID parameter: try ±1, +10, =1, =2, =0.
        Compare response to baseline — flag if different user data returned.
        """
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        id_patterns = re.compile(
            r"^(id|user_id|account_id|order_id|profile_id|"
            r"item_id|product_id|customer_id|doc_id|"
            r"file_id|ticket_id|invoice_id|record_id)$",
            re.IGNORECASE,
        )

        for target in targets:
            for param in target.parameters:
                name = param.get("name", "")
                if not id_patterns.match(name):
                    continue
                if param.get("type", "string") not in ("string", "integer", "number"):
                    continue

                # Get baseline value (from URL if present)
                baseline_val = _extract_param_value(target.url, name) or "1"
                try:
                    baseline_int = int(baseline_val)
                except ValueError:
                    continue  # Skip non-numeric IDs

                # Test probes
                probes = [
                    str(baseline_int + 1),
                    str(baseline_int - 1),
                    str(baseline_int + 10),
                    "1", "2", "0",
                ]

                # Baseline request
                baseline_body, baseline_status = await _make_request(
                    target.url, target.method, name, baseline_val,
                    param.get("location", "query"), auth_headers, self.timeout,
                )

                for probe_val in probes:
                    if probe_val == baseline_val:
                        continue
                    async with semaphore:
                        probe_body, probe_status = await _make_request(
                            target.url, target.method, name, probe_val,
                            param.get("location", "query"), auth_headers, self.timeout,
                        )

                    if probe_status == 200 and baseline_status == 200:
                        # Bodies differ significantly — different user's data
                        similarity = _similarity(probe_body, baseline_body)
                        if 0.05 < similarity < 0.75 and len(probe_body) > 100:
                            finding = Finding(
                                severity    = "HIGH",
                                vuln_type   = "IDOR / Broken Object Level Authorization",
                                url         = target.url,
                                parameter   = name,
                                evidence    = (
                                    f"ID {probe_val} returned different content than baseline ID {baseline_val}. "
                                    f"Similarity: {similarity:.0%}. Response length: {len(probe_body)} vs {len(baseline_body)}. "
                                    f"Possible unauthorized data access."
                                ),
                                cvss        = 8.0,
                                remediation = "Implement object-level authorization for every object access. "
                                              "Verify the requesting user owns/has permission to access the requested object.",
                                payload     = f"{name}={probe_val}",
                            )
                            findings.append(finding)
                            if emit_fn:
                                await emit_fn("finding", _finding_to_event(finding))
                            break  # One finding per param is enough

        return findings

    async def test_horizontal_idor(
        self,
        targets: list[ScanTarget],
        headers_user_a: dict,
        headers_user_b: dict,
        emit_fn=None,
    ) -> list[Finding]:
        """
        Cross-user IDOR: fetch resources with User A's auth, then retry with User B's.
        Finding if User B can access User A's resources.
        """
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        for target in targets:
            # Get response with User A
            async with semaphore:
                body_a, status_a = await _raw_request(
                    target.url, target.method, headers_user_a, self.timeout
                )
            if status_a != 200 or not body_a:
                continue

            # Try same resource with User B
            body_b, status_b = await _raw_request(
                target.url, target.method, headers_user_b, self.timeout
            )

            if status_b == 200:
                similarity = _similarity(body_a, body_b)
                if similarity > 0.6 and len(body_b) > 100:
                    finding = Finding(
                        severity    = "HIGH",
                        vuln_type   = "IDOR / Horizontal Privilege Escalation",
                        url         = target.url,
                        parameter   = "(resource URL)",
                        evidence    = (
                            f"User B accessed User A's resource (similarity {similarity:.0%}). "
                            f"Status: {status_b}. Response length: {len(body_b)}."
                        ),
                        cvss        = 8.8,
                        remediation = "Enforce ownership checks at the data layer for every resource access.",
                        payload     = target.url,
                    )
                    findings.append(finding)
                    if emit_fn:
                        await emit_fn("finding", _finding_to_event(finding))

        return findings

    async def test_privilege_escalation(
        self,
        targets: list[ScanTarget],
        auth_headers: dict,
        admin_paths: Optional[list[str]] = None,
        emit_fn=None,
    ) -> list[Finding]:
        """
        Vertical privilege escalation: try admin endpoints with low-priv token.
        Also tries HTTP method override headers.
        """
        findings: list[Finding] = []
        paths = admin_paths or [
            "/admin", "/api/admin", "/api/v1/admin",
            "/admin/users", "/admin/settings",
            "/manage", "/superuser", "/dashboard/admin",
        ]
        semaphore = asyncio.Semaphore(self.concurrency)

        for path in paths:
            base = ""
            if targets:
                p = urlparse(targets[0].url)
                base = f"{p.scheme}://{p.netloc}"
            if not base:
                continue
            url = base.rstrip("/") + path

            async with semaphore:
                body, status = await _raw_request(url, "GET", auth_headers, self.timeout, follow_redirects=False)

            # Redirect to login = access control working correctly
            if status in (301, 302, 303, 307, 308):
                continue

            if status == 200 and len(body) > 100:
                finding = Finding(
                    severity    = "HIGH",
                    vuln_type   = "Broken Function Level Authorization",
                    url         = url,
                    parameter   = "(admin endpoint)",
                    evidence    = f"Admin endpoint accessible with current token. Status {status}, body length {len(body)}.",
                    cvss        = 8.1,
                    remediation = "Apply role-based access control on all admin/management endpoints. Verify user roles server-side.",
                    payload     = url,
                )
                findings.append(finding)
                if emit_fn:
                    await emit_fn("finding", _finding_to_event(finding))

            # HTTP Method Override test
            override_headers = {
                **auth_headers,
                "X-HTTP-Method-Override": "DELETE",
                "X-Method-Override": "DELETE",
            }
            body2, status2 = await _raw_request(url, "POST", override_headers, self.timeout)
            if status2 in (200, 204) and status2 != status:
                finding = Finding(
                    severity    = "HIGH",
                    vuln_type   = "HTTP Method Override Bypass",
                    url         = url,
                    parameter   = "X-HTTP-Method-Override",
                    evidence    = f"Method override accepted: POST + X-HTTP-Method-Override: DELETE → {status2}.",
                    cvss        = 7.5,
                    remediation = "Validate HTTP Method Override headers. Disable if not required.",
                    payload     = "X-HTTP-Method-Override: DELETE",
                )
                findings.append(finding)
                if emit_fn:
                    await emit_fn("finding", _finding_to_event(finding))

        return findings

    async def test_forced_browsing(
        self,
        base_url: str,
        auth_headers: dict,
        emit_fn=None,
    ) -> list[Finding]:
        """
        Try common admin/debug/backup paths. Flag those that return 200.
        """
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        async def probe(path: str):
            url = origin.rstrip("/") + path
            async with semaphore:
                body, status = await _raw_request(url, "GET", auth_headers, self.timeout, follow_redirects=False)

            # Redirect to login = access control WORKING, not a finding
            if status in (301, 302, 303, 307, 308):
                return

            if status in (200, 201) and len(body) > 50:
                severity = "MEDIUM"
                cvss = 5.3
                # Escalate if sensitive content detected
                if re.search(r"(password|secret|api.?key|private.?key|token)", body, re.IGNORECASE):
                    severity = "HIGH"
                    cvss = 7.5
                if re.search(r"(root:x:0:0|BEGIN.*(RSA|EC) PRIVATE)", body):
                    severity = "CRITICAL"
                    cvss = 9.1

                finding = Finding(
                    severity    = severity,
                    vuln_type   = "Sensitive Path Accessible (Forced Browsing)",
                    url         = url,
                    parameter   = "(path)",
                    evidence    = f"Path {path} returned HTTP {status} (body: {len(body)} chars). Possible sensitive exposure.",
                    cvss        = cvss,
                    remediation = "Restrict access to admin/debug paths. Require authentication. Remove backup files from web root.",
                    payload     = path,
                )
                findings.append(finding)
                if emit_fn:
                    await emit_fn("finding", _finding_to_event(finding))

        tasks = [probe(p) for p in FORCED_BROWSING_PATHS]
        await asyncio.gather(*tasks)
        return findings


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _raw_request(url: str, method: str, headers: dict, timeout: float, follow_redirects: bool = False) -> tuple[str, int]:
    """Make a plain HTTP request, return (body, status). Default: NO redirect following."""
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=follow_redirects, timeout=timeout) as client:
            resp = await client.request(method, url, headers=headers)
            return resp.text, resp.status_code
    except Exception:
        return "", 0


async def _make_request(
    url: str, method: str, param_name: str, param_value: str,
    location: str, headers: dict, timeout: float,
) -> tuple[str, int]:
    """Inject a parameter value and return (body, status)."""
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:
            if location == "query":
                sep = "&" if "?" in url else "?"
                full_url = f"{url}{sep}{param_name}={param_value}"
                resp = await client.request(method, full_url, headers=headers)
            elif location in ("body", "form"):
                resp = await client.request(method, url, data={param_name: param_value}, headers=headers)
            elif location == "json":
                resp = await client.request(method, url, json={param_name: param_value}, headers=headers)
            else:
                sep = "&" if "?" in url else "?"
                resp = await client.request(method, f"{url}{sep}{param_name}={param_value}", headers=headers)
            return resp.text, resp.status_code
    except Exception:
        return "", 0


def _extract_param_value(url: str, param_name: str) -> Optional[str]:
    """Extract a specific query parameter value from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    values = params.get(param_name)
    return values[0] if values else None


def _similarity(a: str, b: str) -> float:
    """Rough text similarity (0.0–1.0)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    if max(la, lb) == 0:
        return 1.0
    common = sum(1 for ca, cb in zip(a[:2000], b[:2000]) if ca == cb)
    return common / min(max(la, lb), 2000)


def _finding_to_event(f: Finding) -> dict:
    """Convert Finding to SSE event dict."""
    return {
        "severity":    f.severity,
        "type":        f.vuln_type,
        "url":         f.url,
        "parameter":   f.parameter,
        "evidence":    f.evidence,
        "cvss":        f.cvss,
        "remediation": f.remediation,
        "payload":     f.payload,
        "source":      "authz",
    }
