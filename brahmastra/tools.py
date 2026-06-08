"""
BRAHMASTRA — Tool Registry
All tools the AI agent can call during a scan.
Each tool is an async function that the agent loop can invoke via tool_call.
"""

import asyncio
import json
import time
from typing import Optional, Any
from dataclasses import dataclass, field

import httpx

from brahmastra.sudarshana.base import Finding


class ToolRegistry:
    """Registry of all tools the BRAHMASTRA agent can execute."""

    def __init__(self):
        self.http_client: Optional[httpx.AsyncClient] = None
        self.last_finding: Optional[Finding] = None
        self.request_log: list[dict] = []
        self.rate_limit_delay: float = 0.1   # seconds between requests

        # Auth headers applied to every request
        self.global_headers: dict = {}
        self.base_url: str = ""

    async def execute(self, fn_name: str, args: dict) -> str:
        """Dispatch tool call to the right handler."""
        handlers = {
            "send_request":   self._send_request,
            "inject_payload": self._inject_payload,
            "report_finding": self._report_finding,
            "mark_clean":     self._mark_clean,
            "log_info":       self._log_info,
            "crawl_done":     self._crawl_done,
        }
        handler = handlers.get(fn_name)
        if not handler:
            return f"Unknown tool: {fn_name}"
        return await handler(args)

    # ─── Tools ────────────────────────────────────────────────────────────────

    async def _send_request(self, args: dict) -> str:
        """Send an HTTP request and return the response summary."""
        method  = str(args.get("method", "GET")).upper()
        url     = str(args.get("url", ""))
        headers = dict(args.get("headers") or {})
        body    = args.get("body")
        timeout = float(args.get("timeout", 10))

        # Merge global auth headers
        merged_headers = {**self.global_headers, **headers}

        if not url:
            return '{"error": "No URL provided"}'

        await asyncio.sleep(self.rate_limit_delay)

        t0 = time.time()
        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=timeout,
            ) as client:
                if method == "GET":
                    resp = await client.get(url, headers=merged_headers)
                elif method == "POST":
                    if isinstance(body, dict):
                        resp = await client.post(url, json=body, headers=merged_headers)
                    else:
                        resp = await client.post(url, content=str(body or ""), headers=merged_headers)
                elif method in ("PUT", "PATCH"):
                    if isinstance(body, dict):
                        resp = await client.request(method, url, json=body, headers=merged_headers)
                    else:
                        resp = await client.request(method, url, content=str(body or ""), headers=merged_headers)
                elif method == "DELETE":
                    resp = await client.delete(url, headers=merged_headers)
                else:
                    resp = await client.request(method, url, headers=merged_headers)

            elapsed = round(time.time() - t0, 3)
            body_preview = resp.text[:500] if resp.text else ""

            # Log the request
            entry = {
                "method": method, "url": url, "status": resp.status_code,
                "elapsed": elapsed, "response_length": len(resp.text),
                "headers_sent": merged_headers,
            }
            self.request_log.append(entry)

            result = {
                "status": resp.status_code,
                "elapsed": elapsed,
                "headers": dict(resp.headers),
                "body": body_preview,
                "body_length": len(resp.text),
                "waf_blocked": _detect_waf_block(resp.status_code, body_preview),
            }
            return json.dumps(result)

        except httpx.TimeoutException:
            elapsed = round(time.time() - t0, 3)
            return json.dumps({"error": "timeout", "elapsed": elapsed, "waf_blocked": False})
        except Exception as e:
            return json.dumps({"error": str(e)})

    async def _inject_payload(self, args: dict) -> str:
        """
        Inject a payload into a parameter and return the response.
        Handles: query param, POST body, JSON body, header injection.
        """
        url       = str(args.get("url", ""))
        parameter = str(args.get("parameter", ""))
        payload   = str(args.get("payload", ""))
        method    = str(args.get("method", "GET")).upper()
        headers   = dict(args.get("headers") or {})
        location  = str(args.get("location", "query")).lower()  # query/body/json/header/cookie
        encoding  = str(args.get("encoding", "none")).lower()
        # Fix relative URLs using base_url
        if url and not url.startswith("http") and self.base_url:
            url = self.base_url.rstrip("/") + "/" + url.lstrip("/")

        # Apply encoding (WAF bypass variants)
        encoded_payload = _apply_encoding(payload, encoding)

        merged_headers = {**self.global_headers, **headers}
        await asyncio.sleep(self.rate_limit_delay)

        t0 = time.time()
        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=10.0,
            ) as client:
                if location == "query":
                    # Append to query string
                    sep = "&" if "?" in url else "?"
                    injected_url = f"{url}{sep}{parameter}={encoded_payload}"
                    resp = await client.request(method, injected_url, headers=merged_headers)
                elif location in ("body", "form"):
                    resp = await client.post(
                        url,
                        data={parameter: encoded_payload},
                        headers=merged_headers,
                    )
                elif location == "json":
                    resp = await client.post(
                        url,
                        json={parameter: encoded_payload},
                        headers=merged_headers,
                    )
                elif location == "header":
                    merged_headers[parameter] = encoded_payload
                    resp = await client.request(method, url, headers=merged_headers)
                elif location == "cookie":
                    merged_headers["Cookie"] = f"{parameter}={encoded_payload}"
                    resp = await client.request(method, url, headers=merged_headers)
                else:
                    # Default: query
                    sep = "&" if "?" in url else "?"
                    resp = await client.request(method, f"{url}{sep}{parameter}={encoded_payload}", headers=merged_headers)

            elapsed = round(time.time() - t0, 3)
            body_preview = resp.text[:800] if resp.text else ""

            result = {
                "status":        resp.status_code,
                "elapsed":       elapsed,
                "body":          body_preview,
                "body_length":   len(resp.text),
                "waf_blocked":   _detect_waf_block(resp.status_code, body_preview),
                "payload_used":  encoded_payload,
                "encoding":      encoding,
            }
            return json.dumps(result)

        except httpx.TimeoutException as e:
            elapsed = round(time.time() - t0, 3)
            # Timeout on time-based injection is significant
            return json.dumps({
                "error": "timeout",
                "elapsed": elapsed,
                "note": "Timeout may indicate time-based blind injection success",
                "waf_blocked": False,
            })
        except Exception as e:
            return json.dumps({"error": str(e)})

    async def _report_finding(self, args: dict) -> str:
        """Record a confirmed vulnerability finding."""
        finding = Finding(
            severity     = str(args.get("severity", "MEDIUM")).upper(),
            vuln_type    = str(args.get("type", "Unknown")),
            url          = str(args.get("url", "")),
            parameter    = str(args.get("parameter", "")),
            evidence     = str(args.get("evidence", "")),
            cvss         = float(args.get("cvss", 5.0)),
            remediation  = str(args.get("remediation", "")),
            waf_bypassed = bool(args.get("waf_bypassed", False)),
            bypass_method= str(args.get("bypass_method", "")),
        )
        self.last_finding = finding
        print(f"  [FINDING] {finding.severity} — {finding.vuln_type} @ {finding.url} (param: {finding.parameter})")
        return json.dumps({"recorded": True, "severity": finding.severity, "type": finding.vuln_type})

    async def _mark_clean(self, args: dict) -> str:
        """Mark a parameter as tested and clean (no vulnerability)."""
        url       = str(args.get("url", ""))
        parameter = str(args.get("parameter", ""))
        reason    = str(args.get("reason", "No indicators found"))
        return json.dumps({"clean": True, "url": url, "parameter": parameter, "reason": reason})

    async def _log_info(self, args: dict) -> str:
        """Log an informational message."""
        msg = str(args.get("message", ""))
        print(f"  [INFO] {msg}")
        return json.dumps({"logged": True})

    async def _crawl_done(self, args: dict) -> str:
        """Signal that scanning is complete."""
        return json.dumps({"done": True, "message": "Scan complete"})


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _detect_waf_block(status_code: int, body: str) -> bool:
    """Detect if a WAF blocked the request."""
    if status_code in (403, 406, 429, 400):
        body_lower = body.lower()
        waf_keywords = [
            "cloudflare", "access denied", "blocked", "forbidden",
            "waf", "firewall", "protection", "security", "not acceptable",
            "request rejected", "malicious", "attack detected",
        ]
        if any(kw in body_lower for kw in waf_keywords):
            return True
    return False


def _apply_encoding(payload: str, encoding: str) -> str:
    """Apply WAF bypass encoding to a payload (Kavachabhedana)."""
    from urllib.parse import quote

    if encoding == "url":
        return quote(payload, safe="")
    elif encoding == "double_url":
        return quote(quote(payload, safe=""), safe="")
    elif encoding == "unicode_fullwidth":
        # Replace ASCII to full-width Unicode (common Cloudflare bypass)
        table = str.maketrans(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'\"`<>",
            "ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ０１２３４５６７８９＇＂｀＜＞"
        )
        return payload.translate(table)
    elif encoding == "html_entity":
        return payload.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace('"', "&quot;")
    elif encoding == "hex":
        return "".join(f"%{ord(c):02x}" for c in payload)
    elif encoding == "case_variation":
        # Alternate case (SQLi keywords)
        result = ""
        for i, c in enumerate(payload):
            result += c.upper() if i % 2 == 0 else c.lower()
        return result
    else:
        return payload  # no encoding
