"""
BRAHMASTRA DAST — Post-engine False-Positive Analysis Phase.

Walks every finding produced by the scan engine and asks brahmastra:p6
(the 32B fine-tuned reasoning model) to judge whether it is a real
vulnerability or a false positive. For findings the AI flags as
false_positive or uncertain — or where AI confidence is low even on
"confirmed" — sends up to N retest probes to the same URL/parameter
(one benign negative control + N-1 positive mutations) to confirm.

Each finding is then UPDATEd in place with:
    fp_status        — "CONFIRMED" / "FALSE_POSITIVE" / "INCONCLUSIVE"
    fp_confidence    — 0-100 int
    fp_analysis      — JSONB structured trace (ai verdict, reason,
                       <think> trace, every probe's request/response
                       summary, final reason)
    fp_retest_count  — number of retest probes actually fired

Pure consumer of the engine output — does not touch engine internals,
the spider, the strategist, or the chat panel. The phase runs strictly
inline between the engine's findings-save loop and the
update_scan_status("complete") call.

Failure modes are designed to never block scan completion:
  * AI unreachable / unparseable               → INCONCLUSIVE, scan continues
  * httpx probe error / network                → that probe recorded as error
  * per-finding wall-clock budget exceeded      → INCONCLUSIVE for that finding
  * any unexpected exception                   → INCONCLUSIVE for that finding
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse, urlencode, parse_qsl

import httpx

from brahmastra.ai_bridge import AIBridge
from server.db import update_finding_fp

EmitFn = Callable[[str, dict], Awaitable[None]]


# ── Indicator tables for retest evaluation ───────────────────────────────────
#
# Each entry is a list of case-insensitive substrings that, if present in
# the response body of a retest probe, count as evidence the
# vulnerability is real. For vuln types where reflection of the literal
# payload is the only signal (XSS, open redirect, generic reflection),
# the list is empty and _matches_indicator falls back to a literal echo
# check on the payload itself.

_INDICATORS: dict[str, list[str]] = {
    "sql":      ["sql syntax", "mysql_fetch", "ora-", "psql:", "sqlite",
                 "you have an error in your sql", "unclosed quotation mark",
                 "syntax error", "odbc", "microsoft ole db"],
    "ssrf":     ["ec2", "metadata", "169.254.169.254", "computemetadata",
                 "instance-id", "iam/security-credentials"],
    "lfi":     ["root:x:", "[boot loader]", "[fonts]", "daemon:x:",
                 "[extensions]", "for 16-bit app support"],
    "path":     ["root:x:", "[boot loader]", "daemon:x:"],
    "rce":      ["uid=", "gid=", "groups=", "volume in drive",
                 "directory of c:\\"],
    "command":  ["uid=", "gid=", "groups=", "volume in drive"],
    "xxe":      ["root:x:", "<!doctype", "[fonts]"],
    "ssti":     ["49", "uid=", "<class 'subprocess.popen'>"],  # 7*7 reflection
}


def _indicator_for(vuln_type: str) -> list[str]:
    """Return the list of substrings that prove a retest probe hit."""
    v = (vuln_type or "").lower()
    for key, indicators in _INDICATORS.items():
        if key in v:
            return indicators
    return []  # XSS, open redirect, reflection — falls back to literal echo


def _parse_http_trace(http_trace: str) -> tuple[int, dict, str]:
    """
    Best-effort split of an engine-emitted raw HTTP trace into
    (status_code, headers_dict, body). The engine writes traces in a
    handful of slightly different formats, so we hunt for the first
    `HTTP/x.y NNN` line and parse from there. On any failure we return
    (0, {}, full_trace) so the AI judge still gets some text to look at.
    """
    if not http_trace:
        return 0, {}, ""

    # Find the response section if request and response are concatenated.
    # The engine often writes "REQUEST:\n... \nRESPONSE:\n..." or just
    # appends them. Look for the LAST occurrence of an HTTP status line.
    status = 0
    headers: dict[str, str] = {}
    body = ""

    matches = list(re.finditer(r"HTTP/\d\.\d\s+(\d{3})", http_trace))
    if not matches:
        return 0, {}, http_trace

    last = matches[-1]
    status = int(last.group(1))
    rest   = http_trace[last.end():]

    # Skip the rest of the status line then walk headers until a blank line.
    nl = rest.find("\n")
    if nl == -1:
        return status, {}, ""
    rest = rest[nl + 1:]

    sep = re.search(r"\r?\n\r?\n", rest)
    if sep:
        header_block = rest[:sep.start()]
        body         = rest[sep.end():]
    else:
        header_block = rest
        body         = ""

    for line in header_block.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()

    return status, headers, body


def _matches_indicator(resp: httpx.Response, indicators: list[str], payload: str) -> bool:
    """True if the probe response shows evidence the vuln is real."""
    try:
        body = resp.text or ""
    except Exception:
        return False
    if not indicators:
        # Reflection-style check: literal echo of the payload (truncated
        # to avoid trivial substring collisions on very short payloads).
        snippet = (payload or "")[:32]
        return bool(snippet) and snippet in body
    body_l = body.lower()
    return any(ind.lower() in body_l for ind in indicators)


# ── The analyzer ─────────────────────────────────────────────────────────────


class FPAnalyzer:
    """
    Per-scan post-processing pass that walks every persisted finding and
    asks the AI bridge for a confirmed/false_positive verdict, optionally
    backed by up to N retest probes against the original URL/parameter.

    Owns NO engine state. Caller (server.api) builds the (id, finding)
    list from the engine's result.findings, then calls analyze_all().
    """

    def __init__(
        self,
        ai: AIBridge,
        emit: EmitFn,
        *,
        max_probes_per_finding: int = 5,
        http_timeout: float = 8.0,
        per_finding_budget_s: float = 30.0,
    ):
        self.ai     = ai
        self.emit   = emit
        self.max_probes = max_probes_per_finding
        self.timeout    = http_timeout
        self.budget     = per_finding_budget_s

    async def analyze_all(
        self,
        scan_id: str,
        findings_with_ids: list[tuple[int, dict]],
    ) -> dict:
        """
        Run the FP phase over every finding from the engine.

        findings_with_ids: list of (db_finding_id, finding_dict) tuples in
        the order save_finding returned them. The dict is the SAME shape
        the engine produced (severity, type/vuln_type, url, parameter,
        evidence, payload, http_trace, ...). Reads response info from
        http_trace via _parse_http_trace because the engine's Finding
        dataclass does not split status/body/headers.

        Returns a summary dict (also emitted as fp_analysis_done):
            {"total": N, "confirmed": x, "false_positive": y,
             "inconclusive": z, "errors": e}
        """
        total = len(findings_with_ids)
        await self.emit("fp_analysis_start", {
            "total":      total,
            "max_probes": self.max_probes,
        })

        confirmed = fp_count = inconclusive = errors = 0

        # Re-use one AsyncClient for the whole phase so we get HTTP
        # connection pooling across retest probes to the same target.
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "BRAHMASTRA-FP/1.0 (post-scan retest)"},
        ) as client:
            for idx, (fid, f) in enumerate(findings_with_ids):
                t0 = time.time()
                try:
                    verdict = await asyncio.wait_for(
                        self._analyze_one(client, fid, f),
                        timeout=self.budget,
                    )
                except asyncio.TimeoutError:
                    errors += 1
                    verdict = {
                        "fp_status":     "INCONCLUSIVE",
                        "fp_confidence": 0,
                        "fp_analysis": {
                            "final_reason": (
                                f"fp phase per-finding timeout after "
                                f"{self.budget:.0f}s"
                            ),
                            "probes": [],
                        },
                        "fp_retest_count": 0,
                    }
                except Exception as e:
                    errors += 1
                    verdict = {
                        "fp_status":     "INCONCLUSIVE",
                        "fp_confidence": 0,
                        "fp_analysis": {
                            "final_reason": (
                                f"fp error: {type(e).__name__}: {e}"[:300]
                            ),
                            "probes": [],
                        },
                        "fp_retest_count": 0,
                    }

                if verdict["fp_status"] == "CONFIRMED":
                    confirmed += 1
                elif verdict["fp_status"] == "FALSE_POSITIVE":
                    fp_count += 1
                else:
                    inconclusive += 1

                try:
                    await update_finding_fp(
                        finding_id      = fid,
                        fp_status       = verdict["fp_status"],
                        fp_confidence   = verdict["fp_confidence"],
                        fp_analysis     = verdict["fp_analysis"],
                        fp_retest_count = verdict["fp_retest_count"],
                    )
                except Exception as e:
                    # DB write failure should NOT crash the FP phase or
                    # block scan completion — log it and move on.
                    errors += 1
                    await self.emit("log", {
                        "level": "warn",
                        "msg":   f"fp_analyzer db update failed for finding "
                                 f"{fid}: {type(e).__name__}: {e}",
                    })

                await self.emit("fp_analysis_finding", {
                    "index":         idx + 1,
                    "total":         total,
                    "finding_id":    fid,
                    "vuln_type":     f.get("type") or f.get("vuln_type") or "",
                    "url":           f.get("url", ""),
                    "fp_status":     verdict["fp_status"],
                    "fp_confidence": verdict["fp_confidence"],
                    "reason":        (verdict["fp_analysis"] or {}).get("final_reason", ""),
                    "ms":            int((time.time() - t0) * 1000),
                })

        summary = {
            "total":          total,
            "confirmed":      confirmed,
            "false_positive": fp_count,
            "inconclusive":   inconclusive,
            "errors":         errors,
        }
        await self.emit("fp_analysis_done", summary)
        return summary

    # ── per-finding ----------------------------------------------------------

    async def _analyze_one(
        self,
        client: httpx.AsyncClient,
        fid: int,
        f: dict,
    ) -> dict:
        t_total = time.time()

        vuln_type = f.get("type") or f.get("vuln_type") or ""
        severity  = f.get("severity") or ""
        url       = f.get("url") or ""
        parameter = f.get("parameter") or ""
        payload   = f.get("payload") or ""
        http_trace = f.get("http_trace") or ""
        evidence   = f.get("evidence") or ""

        resp_status, resp_headers, resp_body = _parse_http_trace(http_trace)
        if not resp_body:
            # Engine didn't capture a body — the AI still gets the
            # evidence string which is usually a one-line indicator.
            resp_body = evidence

        # 1) Ask the AI for an initial verdict
        ai_judgement = await self.ai.judge_finding(
            vuln_type        = vuln_type,
            severity         = severity,
            url              = url,
            parameter        = parameter,
            payload          = payload,
            request_trace    = http_trace,
            response_status  = resp_status,
            response_body    = resp_body,
            response_headers = resp_headers,
        )

        if ai_judgement is None:
            # AI bridge disabled or unreachable. Don't fail the scan —
            # mark INCONCLUSIVE so the operator knows the FP phase
            # didn't run for this finding.
            return {
                "fp_status":     "INCONCLUSIVE",
                "fp_confidence": 0,
                "fp_analysis": {
                    "ai_verdict":   "unavailable",
                    "ai_reason":    "AI bridge disabled or unreachable",
                    "ai_think":     "",
                    "ai_confidence": 0,
                    "probes":        [],
                    "final_reason": "AI bridge unavailable — finding left as-is",
                    "ms_total":     int((time.time() - t_total) * 1000),
                },
                "fp_retest_count": 0,
            }

        analysis: dict[str, Any] = {
            "ai_verdict":    ai_judgement["verdict"],
            "ai_reason":     ai_judgement["reason"],
            "ai_think":      ai_judgement["think"],
            "ai_confidence": ai_judgement["confidence"],
            "probes":        [],
        }

        # 2) Fast path: AI is highly confident this is a real vuln.
        if ai_judgement["verdict"] == "confirmed" and ai_judgement["confidence"] >= 80:
            analysis["final_reason"] = (
                f"AI confirmed at {ai_judgement['confidence']}%: "
                f"{ai_judgement['reason']}"
            )
            analysis["ms_total"] = int((time.time() - t_total) * 1000)
            return {
                "fp_status":       "CONFIRMED",
                "fp_confidence":   ai_judgement["confidence"],
                "fp_analysis":     analysis,
                "fp_retest_count": 0,
            }

        # 3) Otherwise — ask AI for retest probes and run them
        probe_specs = await self.ai.craft_retest_probes(
            vuln_type        = vuln_type,
            parameter        = parameter,
            original_payload = payload,
            max_probes       = self.max_probes,
        )

        if not probe_specs:
            # AI gave us nothing — fall back to trusting the AI verdict
            # alone. Still records SOMETHING actionable on the finding.
            analysis["final_reason"] = (
                f"AI verdict '{ai_judgement['verdict']}' with no retest "
                f"probes available"
            )
            analysis["ms_total"] = int((time.time() - t_total) * 1000)
            status = ("FALSE_POSITIVE"
                      if ai_judgement["verdict"] == "false_positive"
                      else "INCONCLUSIVE")
            return {
                "fp_status":       status,
                "fp_confidence":   ai_judgement["confidence"],
                "fp_analysis":     analysis,
                "fp_retest_count": 0,
            }

        # Send the probes
        method    = (f.get("method") or "GET").upper()
        indicator = _indicator_for(vuln_type)

        n_negative_clean = 0
        n_positive_hit   = 0
        n_pos_total      = sum(
            1 for p in probe_specs if not p.get("is_negative_control")
        )

        for spec in probe_specs:
            probe_payload = spec.get("payload", "")
            is_neg        = bool(spec.get("is_negative_control", False))
            try:
                resp = await self._send_probe(
                    client, url, method, parameter, probe_payload,
                )
                hit = _matches_indicator(resp, indicator, probe_payload)
                analysis["probes"].append({
                    "payload":             probe_payload[:200],
                    "is_negative_control": is_neg,
                    "expect":              spec.get("expect", "")[:200],
                    "status":              resp.status_code,
                    "len":                 len(resp.content),
                    "matched_indicator":   hit,
                    "ms":                  int(resp.elapsed.total_seconds() * 1000),
                })
                if is_neg and not hit:
                    n_negative_clean += 1
                if (not is_neg) and hit:
                    n_positive_hit += 1
            except Exception as e:
                analysis["probes"].append({
                    "payload":             probe_payload[:200],
                    "is_negative_control": is_neg,
                    "error":               f"{type(e).__name__}: {e}"[:200],
                })

        # 4) Final verdict logic
        if (n_pos_total > 0
                and n_positive_hit >= max(1, n_pos_total // 2)
                and n_negative_clean >= 1):
            status = "CONFIRMED"
            conf   = min(100, 60 + 10 * n_positive_hit)
            reason = (
                f"Retest reproduced vuln: {n_positive_hit}/{n_pos_total} "
                f"positive probes hit, negative control was clean"
            )
        elif n_positive_hit == 0 and ai_judgement["verdict"] == "false_positive":
            status = "FALSE_POSITIVE"
            conf   = max(ai_judgement["confidence"], 70)
            reason = (
                f"AI flagged FP and 0/{n_pos_total} retest probes "
                f"reproduced the issue"
            )
        elif n_positive_hit == 0 and n_negative_clean >= 1:
            status = "FALSE_POSITIVE"
            conf   = 60
            reason = (
                f"0/{n_pos_total} retest probes reproduced the issue "
                f"(AI was {ai_judgement['verdict']})"
            )
        else:
            status = "INCONCLUSIVE"
            conf   = 40
            reason = (
                f"Mixed signals: {n_positive_hit}/{n_pos_total} positive "
                f"hits, negative control "
                f"{'clean' if n_negative_clean else 'noisy'}"
            )

        analysis["final_reason"] = reason
        analysis["ms_total"]     = int((time.time() - t_total) * 1000)
        return {
            "fp_status":       status,
            "fp_confidence":   conf,
            "fp_analysis":     analysis,
            "fp_retest_count": len(probe_specs),
        }

    # ── HTTP plumbing --------------------------------------------------------

    async def _send_probe(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        param: str,
        payload: str,
    ) -> httpx.Response:
        """
        Inject `payload` into the named parameter and re-fire the request.
        Mirrors the engine's injection style:
            - GET  → upsert into the query string
            - POST → send as form-encoded body
        Other methods are sent as POST with the parameter in the body so
        we always make a real round-trip.
        """
        if not param:
            # No parameter to inject into — fire the bare URL so we at
            # least get a baseline response code for the indicator
            # check (useful for path-based vulns).
            return await client.request(method or "GET", url)

        if method == "GET":
            # Preserve any existing query string and overwrite just our
            # parameter so the request looks as close to the original
            # engine probe as possible.
            parsed = urlparse(url)
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            qs[param] = payload
            new_url = parsed._replace(query=urlencode(qs)).geturl()
            return await client.get(new_url)

        return await client.post(url, data={param: payload})
