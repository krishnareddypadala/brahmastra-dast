"""
BRAHMASTRA Guided Scan
Instead of letting the model decide whether to test, we force it:
- Agent picks targets + payloads
- Agent calls inject_payload directly
- Model analyzes the HTTP response and decides if it's vulnerable
"""
import asyncio
import json
import httpx
import sys
import argparse
from datetime import datetime

MODEL_URL  = "http://localhost:11435/api/chat"
MODEL_NAME = "brahmastra"

# ── Payload libraries ─────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' AND SLEEP(3)--",
    "' UNION SELECT NULL,NULL--",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert(document.cookie)</script>",
    "<svg onload=alert(1)>",
]
SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
]
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:22/",
]

SYSTEM_PROMPT = """You are BRAHMASTRA, an elite DAST security scanner.
You will be given an HTTP response from a test injection. Analyze it and determine:
1. Is this response evidence of a vulnerability?
2. What type of vulnerability (SQLi, XSS, SSTI, SSRF, etc.)?
3. What is the severity (CRITICAL, HIGH, MEDIUM, LOW)?

You MUST respond with EXACTLY one of these tool calls:
  report_finding(severity="HIGH", type="SQL Injection", url="/path", parameter="param", evidence="...", cvss=8.0, remediation="Use parameterized queries")
  mark_clean(url="/path", parameter="param", reason="No evidence of vulnerability in response")

Do not explain. Just output the tool call.
Always respond in English only. Never output non-Latin characters.
"""

ANALYSIS_TMPL = """Payload injected: {payload}
Vulnerability type being tested: {vuln_type}
Target: {method} {url} (parameter: {param})

HTTP Response:
  Status: {status}
  Body preview (first 500 chars): {body}
  WAF blocked: {waf}

Based on this response, is the parameter vulnerable? Output report_finding() or mark_clean().
"""

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-0", "pg_query", "sqlite_",
    "unclosed quotation", "syntax error", "you have an error in your sql",
    "warning: mysql", "invalid query", "supplied argument is not",
    "microsoft ole db", "odbc drivers", "sql server", "division by zero",
    "quoted string not properly terminated",
]
XSS_REFLECTED = ["<script>alert(1)</script>", "onerror=alert(1)", "onload=alert(1)"]
SSTI_CONFIRMED = ["49", "7777777"]  # {{7*7}}=49, ${7*7}=49, 7*7=49


async def call_model(messages: list) -> str:
    payload = {
        "model":    MODEL_NAME,
        "messages": messages,
        "stream":   False,
        "options":  {"temperature": 0.1, "num_predict": 512},
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(MODEL_URL, json=payload)
        resp.raise_for_status()
        return resp.json()["message"]["content"]


async def inject_payload(url: str, param: str, payload_val: str, method: str = "GET",
                          verify_ssl: bool = False) -> dict:
    """Send actual HTTP request with payload."""
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=verify_ssl,
                                      follow_redirects=True) as client:
            if method.upper() == "GET":
                r = await client.get(url, params={param: payload_val})
            else:
                r = await client.post(url, data={param: payload_val})
            body = r.text[:1000]
            waf  = r.status_code in (403, 406, 429)
            return {"status": r.status_code, "body": body, "waf": waf, "ok": True}
    except Exception as e:
        return {"status": 0, "body": str(e), "waf": False, "ok": False}


def heuristic_check(payload_val: str, vuln_type: str, resp: dict) -> tuple[bool, str]:
    """Quick heuristic to detect obvious vulnerabilities without model call."""
    body_lower = resp["body"].lower()
    if vuln_type == "SQLi":
        for err in SQLI_ERRORS:
            if err in body_lower:
                return True, f"SQL error detected: '{err}' in response body"
    if vuln_type == "XSS":
        for xss in XSS_REFLECTED:
            if xss.lower() in body_lower:
                return True, f"XSS payload reflected unescaped in response"
    if vuln_type == "SSTI":
        for conf in SSTI_CONFIRMED:
            if conf in resp["body"]:
                return True, f"SSTI confirmed: expression evaluated to '{conf}'"
    return False, ""


def parse_model_finding(text: str, url: str, param: str) -> dict | None:
    """Parse report_finding() or mark_clean() from model output."""
    import re
    # Check for report_finding
    m = re.search(r'report_finding\(([^)]+)\)', text, re.DOTALL)
    if m:
        args_str = m.group(1)
        def get_arg(name):
            p = re.search(rf'{name}=["\']([^"\']+)["\']', args_str)
            if p: return p.group(1)
            p = re.search(rf'{name}=([\d.]+)', args_str)
            if p: return p.group(1)
            return ""
        return {
            "severity":    get_arg("severity") or "HIGH",
            "type":        get_arg("type") or "Unknown",
            "url":         get_arg("url") or url,
            "parameter":   get_arg("parameter") or param,
            "evidence":    get_arg("evidence") or "Detected by model",
            "cvss":        float(get_arg("cvss") or 0),
            "remediation": get_arg("remediation") or "",
            "vulnerable":  True,
        }
    return None  # mark_clean or unclear → not vulnerable


async def test_parameter(base_url: str, path: str, param: str,
                          vuln_type: str, payloads: list, method: str = "GET",
                          verbose: bool = True) -> list[dict]:
    """Test a single parameter for a single vulnerability class."""
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    findings = []

    for payload_val in payloads[:3]:  # Max 3 payloads per param per vuln type
        if verbose:
            print(f"    → {vuln_type}: {url}?{param}={payload_val[:40]!r}")

        resp = await inject_payload(url, param, payload_val, method=method)

        if not resp["ok"]:
            if verbose:
                print(f"      Request failed: {resp['body'][:100]}")
            continue

        # Heuristic fast-path
        vuln, evidence = heuristic_check(payload_val, vuln_type, resp)

        if not vuln:
            # Ask model to analyze
            analysis_msg = ANALYSIS_TMPL.format(
                payload=payload_val,
                vuln_type=vuln_type,
                method=method,
                url=url,
                param=param,
                status=resp["status"],
                body=resp["body"][:500],
                waf=resp["waf"],
            )
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": analysis_msg},
            ]
            try:
                model_output = await call_model(messages)
                if verbose:
                    print(f"      Model: {model_output[:120]}")
                finding = parse_model_finding(model_output, path, param)
                if finding:
                    vuln     = True
                    evidence = finding["evidence"]
            except Exception as e:
                if verbose:
                    print(f"      Model error: {e}")
                continue

        if vuln:
            finding_dict = {
                "severity":    "HIGH" if vuln_type == "SQLi" else "MEDIUM",
                "type":        vuln_type,
                "url":         path,
                "parameter":   param,
                "evidence":    evidence,
                "payload":     payload_val,
                "cvss":        8.0 if vuln_type == "SQLi" else 6.5,
                "remediation": {
                    "SQLi":  "Use parameterized queries/prepared statements.",
                    "XSS":   "HTML-encode all user input before rendering.",
                    "SSTI":  "Avoid passing user input to template engines.",
                    "SSRF":  "Whitelist allowed URLs; block internal ranges.",
                }.get(vuln_type, "Sanitize and validate all user input."),
                "timestamp": datetime.utcnow().isoformat(),
            }
            findings.append(finding_dict)
            print(f"  [VULN] {finding_dict['severity']} — {vuln_type} @ {path}?{param}={payload_val[:30]!r}")
            break  # One confirmed finding per param/vuln_type is enough

    return findings


async def crawl_target(target_url: str, verbose: bool = True) -> list[dict]:
    """Simple crawler to discover endpoints and parameters."""
    print(f"  [Garudastra] Crawling {target_url}...")
    targets = []
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False,
                                      follow_redirects=True) as client:
            resp = await client.get(target_url)
            body = resp.text

        # Find forms and links
        import re
        # Find form action + inputs
        forms = re.findall(r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>(.*?)</form>',
                            body, re.DOTALL | re.IGNORECASE)
        for action, form_body in forms:
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
            method = "POST"
            if re.search(r'method=["\']get["\']', form_body, re.IGNORECASE):
                method = "GET"
            if action and not action.startswith("http"):
                if not action.startswith("/"):
                    action = "/" + action
            for inp in inputs:
                if inp.lower() not in ("submit", "button", "csrf", "token", "_token"):
                    targets.append({"path": action or "/", "param": inp, "method": method})

        # Also check URL with query params in links
        links = re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']', body, re.IGNORECASE)
        for link in links[:5]:
            parts = link.split("?", 1)
            if len(parts) == 2:
                path = parts[0]
                for kv in parts[1].split("&"):
                    if "=" in kv:
                        k = kv.split("=")[0]
                        targets.append({"path": path, "param": k, "method": "GET"})

    except Exception as e:
        print(f"  Crawl error: {e}")

    # Always include / and login page
    if not any(t["path"] == "/" for t in targets):
        targets.append({"path": "/", "param": "q", "method": "GET"})

    if verbose:
        print(f"  [Garudastra] Found {len(targets)} test points")
    return targets


async def main():
    parser = argparse.ArgumentParser(description="BRAHMASTRA Guided Scan")
    parser.add_argument("--target", required=True)
    parser.add_argument("--out",    default="/tmp/guided_scan.json")
    parser.add_argument("-v", "--verbose", action="store_true", default=True)
    args = parser.parse_args()

    print("=" * 60)
    print("BRAHMASTRA — Guided DAST Scan")
    print("=" * 60)
    print(f"Target: {args.target}")

    targets = await crawl_target(args.target, verbose=args.verbose)
    if not targets:
        targets = [{"path": "/login.php", "param": "uname", "method": "POST"},
                   {"path": "/login.php", "param": "password", "method": "POST"}]

    all_findings = []
    tested = set()

    for t in targets:
        path  = t["path"]
        param = t["param"]
        method = t.get("method", "GET")
        key = f"{path}:{param}"
        if key in tested:
            continue
        tested.add(key)

        print(f"\n  Testing {method} {path} — param: {param}")

        # Test for multiple vulnerability classes
        for vuln_type, payloads in [
            ("SQLi",  SQLI_PAYLOADS),
            ("XSS",   XSS_PAYLOADS),
            ("SSTI",  SSTI_PAYLOADS),
        ]:
            findings = await test_parameter(
                args.target, path, param, vuln_type, payloads, method=method,
                verbose=args.verbose
            )
            all_findings.extend(findings)

    print(f"\n{'='*60}")
    print(f"Scan complete. Found {len(all_findings)} vulnerabilities.")

    # Severity counts
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sum(1 for f in all_findings if f.get("severity") == sev)
        if count:
            print(f"  {sev}: {count}")

    result = {
        "scan_id":     f"brahmastra-guided-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "target":      args.target,
        "timestamp":   datetime.utcnow().isoformat(),
        "findings":    all_findings,
        "total_tests": len(tested) * 3,  # 3 vuln types per param
    }
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"  Report: {args.out}")
    print("=" * 60)

    if all_findings:
        print("\nTop Findings:")
        for f in all_findings[:10]:
            print(f"  [{f['severity']}] {f['type']} @ {f['url']} param={f['parameter']}")
            print(f"         payload: {f['payload']!r}")
            print(f"         evidence: {f['evidence'][:100]}")


if __name__ == "__main__":
    asyncio.run(main())
