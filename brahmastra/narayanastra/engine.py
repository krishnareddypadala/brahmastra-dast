"""
BRAHMASTRA — Scan Engine Orchestrator
Runs the full scan pipeline. Sits on TOP of the existing naive scanner in api.py.

Flow:
  1. CRAWL  — Spider discovers endpoints + tech stack
  2. RULE   — Rule engine tests all endpoints × all applicable rules
  3. AUTHZ  — AuthZ tester checks IDOR, forced browsing, privesc
  4. MERGE  — If AI enabled, rule+AI results merged (dedup by vuln+url+param)

Parallel mode (AI enabled):
  asyncio.gather(
      RuleEngine.scan(endpoints),
      AIAgent.scan(endpoints),  ← agent.py loop, only when AI enabled
  )
  → merge_findings(rule_results, ai_results)

AI disabled mode:
  Only RuleEngine.scan() runs. Zero GPU touch.
"""

from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional, Callable

import httpx

from brahmastra.sudarshana.base import Finding, ScanTarget, ScanResult
from brahmastra.garudastra.crawlers.spider import Spider
from brahmastra.garudastra.auth.manager import AuthManager, AuthConfig
from brahmastra.narayanastra.rules import ALL_RULES, Rule, get_rules_for_profile
from brahmastra.narayanastra.authz import AuthZTester
from brahmastra.ai_bridge import AIBridge


# ─── Config ───────────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    target:       str
    scan_profile: str  = "full"       # full / quick / stealth / api_only / auth_only / owasp_top10 / pci_dss / api_security / smart

    # AI mode
    ai_mode:      str  = "disabled"   # disabled / brahmastra / gemini_flash / claude_haiku / openai
    ai_api_key:   str  = ""

    # Auth
    auth_config:  Optional[AuthConfig] = None
    second_auth_config: Optional[AuthConfig] = None  # for horizontal IDOR

    # Source
    source_type:    str = "url"       # url / openapi / postman / har / burp / graphql
    source_content: str = ""          # file content for spec/HAR/Burp import

    # Options
    scan_depth:       int  = 2        # 1 / 2 / 3
    authz_testing:    bool = True
    max_concurrency:  int  = 10
    request_delay:    float = 0.1     # seconds between requests


# ─── Engine ───────────────────────────────────────────────────────────────────

class ScanEngine:
    """
    Main orchestrator. Called from api.py instead of the inline run_scan().
    The existing naive scanner still runs — this adds the rule engine on top.
    """

    def __init__(self):
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    async def run(
        self,
        scan_id: str,
        config: ScanConfig,
        emit_fn: Optional[Callable] = None,
    ) -> ScanResult:
        """
        Full scan pipeline.
        emit_fn(event_type: str, data: dict) — sends SSE events to dashboard.
        """
        self._stop_flag = False
        result = ScanResult(scan_id=scan_id, target=config.target)

        async def emit(event_type: str, data: dict):
            if emit_fn:
                try:
                    await emit_fn(event_type, data)
                except Exception:
                    pass

        # ── Resolve auth headers ───────────────────────────────────────────────
        auth_headers: dict = {}
        if config.auth_config:
            mgr = AuthManager(config.auth_config)
            auth_headers = await mgr.get_headers()

        second_auth_headers: dict = {}
        if config.second_auth_config:
            mgr2 = AuthManager(config.second_auth_config)
            second_auth_headers = await mgr2.get_headers()

        # ── Phase 1: Crawl ─────────────────────────────────────────────────────
        await emit("phase", {"phase": "crawl", "message": "Starting Garudastra recon..."})

        endpoints: list[ScanTarget] = []
        try:
            if config.source_type == "url":
                spider = Spider(max_depth=config.scan_depth)
                endpoints = await spider.crawl(
                    config.target,
                    auth_headers=auth_headers,
                    depth=config.scan_depth,
                    emit_fn=emit,
                )
                result.tech_stack = spider.tech_stack
            else:
                endpoints = await _load_from_source(config)
        except Exception as e:
            await emit("error", {"message": f"Crawl error: {e}"})

        await emit("crawl_done", {
            "endpoints_found": len(endpoints),
            "tech_stack": result.tech_stack,
        })

        if not endpoints:
            result.finish()
            await emit("done", {"findings": 0, "requests": 0})
            return result

        # ── Phase 2: Rule Engine + AI (parallel if AI enabled) ─────────────────
        await emit("phase", {"phase": "scan", "message": f"Scanning {len(endpoints)} endpoints..."})

        ai_bridge = AIBridge(mode=config.ai_mode, api_key=config.ai_api_key)
        # Fresh instances per scan — prevents cross-scan state bleed
        rules = [type(r)() for r in get_rules_for_profile(config.scan_profile)]

        # Get AI-suggested extra payloads if AI enabled
        if ai_bridge.enabled and result.tech_stack:
            for rule in rules[:5]:  # Only top rules for efficiency
                extra = await ai_bridge.craft_payloads(
                    rule.name, result.tech_stack, "param", rule.payloads[:3]
                )
                if extra:
                    rule.payloads = rule.payloads + extra

        # AI-suggested extra paths
        if ai_bridge.enabled and result.tech_stack:
            extra_paths = await ai_bridge.suggest_paths(
                config.target, result.tech_stack,
                [t.url for t in endpoints[:20]]
            )
            for path in extra_paths:
                from urllib.parse import urlparse, urljoin
                p = urlparse(config.target)
                url = urljoin(f"{p.scheme}://{p.netloc}", path)
                endpoints.append(ScanTarget(url=url, method="GET", source="ai_suggested"))

        if ai_bridge.enabled:
            # Parallel: rule engine + AI agent
            rule_task = asyncio.create_task(
                self._run_rule_engine(endpoints, rules, auth_headers, ai_bridge, result, config, emit)
            )
            ai_task = asyncio.create_task(
                self._run_ai_agent(endpoints, auth_headers, ai_bridge, result, config, emit)
            )
            rule_findings, ai_findings = await asyncio.gather(rule_task, ai_task)
            merged = _merge_findings(rule_findings, ai_findings)
        else:
            rule_findings = await self._run_rule_engine(
                endpoints, rules, auth_headers, ai_bridge, result, config, emit
            )
            merged = rule_findings

        result.findings.extend(merged)

        # ── Phase 3: AuthZ Testing ─────────────────────────────────────────────
        if config.authz_testing and not self._stop_flag:
            await emit("phase", {"phase": "authz", "message": "Running AuthZ tests..."})
            authz = AuthZTester(concurrency=config.max_concurrency)

            authz_findings: list[Finding] = []

            # IDOR with single auth (ID tampering)
            idor_f = await authz.test_idor(endpoints, auth_headers, emit_fn=emit)
            authz_findings.extend(idor_f)

            # Horizontal IDOR if second auth provided
            if second_auth_headers:
                horiz_f = await authz.test_horizontal_idor(
                    endpoints, auth_headers, second_auth_headers, emit_fn=emit
                )
                authz_findings.extend(horiz_f)

            # Privilege escalation
            privesc_f = await authz.test_privilege_escalation(endpoints, auth_headers, emit_fn=emit)
            authz_findings.extend(privesc_f)

            # Forced browsing
            fb_f = await authz.test_forced_browsing(config.target, auth_headers, emit_fn=emit)
            authz_findings.extend(fb_f)

            result.findings.extend(authz_findings)

        # ── Done ───────────────────────────────────────────────────────────────
        result.finish()
        await emit("done", {
            "findings_count": len(result.findings),
            "requests_count": result.total_requests,
            "duration": _duration(result.started_at, result.finished_at),
            "critical": result.critical_count,
            "high":     result.high_count,
            "medium":   result.medium_count,
            "low":      result.low_count,
        })

        return result

    async def _run_rule_engine(
        self,
        endpoints: list[ScanTarget],
        rules: list[Rule],
        auth_headers: dict,
        ai_bridge: AIBridge,
        result: ScanResult,
        config: ScanConfig,
        emit,
    ) -> list[Finding]:
        """Run all rules against all endpoints."""
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(config.max_concurrency)
        total_probes = len(endpoints) * len(rules)
        done_probes  = 0

        for rule in rules:
            if self._stop_flag:
                break

            rule_findings_count = 0

            for target in endpoints:
                if self._stop_flag:
                    break
                if not rule.payloads:
                    # Passive rule — run detect on baseline response
                    body, hdrs, status, elapsed = await _fetch_baseline(
                        target.url, target.method, auth_headers, config.request_delay
                    )
                    result.total_requests += 1
                    confidence = rule.detect(body, hdrs, status, "", body, status, elapsed)
                    if confidence >= 0.3:
                        finding = _make_finding(rule, confidence, target.url, "(passive)", body, "")
                        findings.append(finding)
                        rule_findings_count += 1
                        await emit("finding", _finding_to_event(finding, source="rule_engine"))
                    done_probes += 1
                    continue

                for param in (target.parameters or [{"name": "q", "location": "query"}]):
                    if self._stop_flag:
                        break
                    param_name = param.get("name", "q")
                    location   = param.get("location", "query")

                    if location not in rule.locations:
                        continue

                    # Reset per-param stateful rules (e.g. SQLiBooleanRule)
                    if hasattr(rule, "reset_state"):
                        rule.reset_state()

                    # Baseline
                    base_body, base_hdrs, base_status, _ = await _fetch_baseline(
                        target.url, target.method, auth_headers, config.request_delay
                    )

                    for payload in rule.payloads:
                        if self._stop_flag:
                            break
                        async with semaphore:
                            body, hdrs, status, elapsed, http_trace = await _inject_and_fetch(
                                target.url, target.method, param_name, payload,
                                location, auth_headers, config.request_delay
                            )
                        result.total_requests += 1

                        confidence = rule.detect(
                            body, hdrs, status, payload,
                            base_body, base_status, elapsed
                        )

                        await emit("probe", {
                            "rule":        rule.id,
                            "rule_id":     rule.id,   # alias so dashboard d.rule_id works
                            "rule_name":   rule.name,
                            "url":         target.url,
                            "parameter":   param_name,
                            "payload":     payload[:80],
                            "status":      status,
                            "confidence":  round(confidence, 2),
                        })

                        if confidence >= 0.8:
                            finding = _make_finding(rule, confidence, target.url, param_name, body, payload, http_trace)
                            findings.append(finding)
                            rule_findings_count += 1
                            await emit("finding", _finding_to_event(finding, source="rule_engine"))
                            break  # One confirmation per param per rule

                        elif confidence >= 0.3 and ai_bridge.enabled:
                            ai_result = await ai_bridge.analyze_finding(
                                payload, body, status, rule.name, confidence,
                                target.url, param_name
                            )
                            if ai_result and ai_result.get("confirmed"):
                                finding = _make_finding(rule, ai_result["confidence"], target.url, param_name, body, payload)
                                finding.think_trace  = ai_result.get("think_trace", "")
                                finding.evidence    += f" [AI confirmed: {ai_result.get('evidence', '')}]"
                                findings.append(finding)
                                rule_findings_count += 1
                                await emit("finding", _finding_to_event(finding, source="ai_confirmed"))
                                break

                    done_probes += 1

            await emit("rule_progress", {
                "rule_id":       rule.id,
                "rule_name":     rule.name,
                "severity":      rule.severity,
                "findings_count": rule_findings_count,
                "done":          done_probes,
                "total":         total_probes,
            })

        return findings

    async def _run_ai_agent(
        self,
        endpoints: list[ScanTarget],
        auth_headers: dict,
        ai_bridge: AIBridge,
        result: ScanResult,
        config: ScanConfig,
        emit,
    ) -> list[Finding]:
        """
        Run the BRAHMASTRA AI agent loop in parallel with the rule engine.
        Uses agent.py BrahmastraAgent when AI is enabled.
        """
        if not ai_bridge.enabled:
            return []

        try:
            from brahmastra.agent import BrahmastraAgent
            from brahmastra.tools import ToolRegistry
        except ImportError:
            return []

        findings: list[Finding] = []

        for target in endpoints[:30]:  # Cap AI targets for cost/speed
            if self._stop_flag:
                break
            try:
                registry = ToolRegistry()
                registry.global_headers = auth_headers
                agent = BrahmastraAgent(
                    model_backend=config.ai_mode,
                    api_key=config.ai_api_key,
                )
                scan_result = await agent.scan(target, registry)
                if scan_result and scan_result.findings:
                    for f in scan_result.findings:
                        findings.append(f)
                        await emit("finding", _finding_to_event(f, source="ai_agent"))
            except Exception:
                pass

        return findings


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _fetch_baseline(
    url: str, method: str, headers: dict, delay: float
) -> tuple[str, dict, int, float]:
    """Fetch the original response as a baseline."""
    await asyncio.sleep(delay)
    t0 = time.time()
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
            resp = await client.request(method, url, headers=headers)
            return resp.text, dict(resp.headers), resp.status_code, round(time.time() - t0, 3)
    except Exception:
        return "", {}, 0, round(time.time() - t0, 3)


async def _inject_and_fetch(
    url: str, method: str, param: str, payload: str,
    location: str, headers: dict, delay: float
) -> tuple[str, dict, int, float, str]:
    """Inject payload into the target and return (body, headers, status, elapsed, http_trace)."""
    await asyncio.sleep(delay)
    t0 = time.time()
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12) as client:
            if location == "query":
                sep = "&" if "?" in url else "?"
                resp = await client.request(method, f"{url}{sep}{param}={payload}", headers=headers)
            elif location in ("body", "form"):
                resp = await client.request(method, url, data={param: payload}, headers=headers)
            elif location == "json":
                resp = await client.request(method, url, json={param: payload}, headers=headers)
            elif location == "header":
                h = {**headers, param: payload}
                resp = await client.request(method, url, headers=h)
            elif location == "cookie":
                h = {**headers, "Cookie": f"{param}={payload}"}
                resp = await client.request(method, url, headers=h)
            elif location == "path_suffix":
                # Append payload directly to URL path (e.g. /page + .bak → /page.bak)
                path_url = url.split("?")[0].rstrip("/") + payload
                resp = await client.request(method, path_url, headers=headers)
            else:
                sep = "&" if "?" in url else "?"
                resp = await client.request(method, f"{url}{sep}{param}={payload}", headers=headers)

            # Build human-readable HTTP trace (request + response)
            req = resp.request
            req_hdrs = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
            req_body = req.content.decode(errors="replace") if req.content else ""
            res_hdrs = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            res_body = resp.text[:4000] + ("\n... [truncated]" if len(resp.text) > 4000 else "")
            http_trace = (
                f"=== REQUEST ===\n"
                f"{req.method} {req.url} HTTP/1.1\n"
                f"{req_hdrs}\n\n"
                f"{req_body}\n\n"
                f"=== RESPONSE ===\n"
                f"HTTP/1.1 {resp.status_code}\n"
                f"{res_hdrs}\n\n"
                f"{res_body}"
            )
            return resp.text, dict(resp.headers), resp.status_code, round(time.time() - t0, 3), http_trace
    except httpx.TimeoutException:
        return "", {}, 0, round(time.time() - t0, 3), ""
    except Exception:
        return "", {}, 0, round(time.time() - t0, 3), ""


def _make_finding(
    rule: Rule, confidence: float, url: str, param: str, body: str, payload: str,
    http_trace: str = ""
) -> Finding:
    severity = rule.severity
    if confidence < 0.6:
        severity = "LOW"
    return Finding(
        severity    = severity,
        vuln_type   = rule.name,
        url         = url,
        parameter   = param,
        evidence    = f"Rule {rule.id} confidence {confidence:.0%}. Body snippet: {body[:200]}",
        cvss        = rule.cvss if confidence >= 0.8 else round(rule.cvss * 0.6, 1),
        remediation = rule.remediation,
        payload     = payload,
        http_trace  = http_trace,
    )


def _merge_findings(rule_findings: list[Finding], ai_findings: list[Finding]) -> list[Finding]:
    """
    Merge rule engine + AI agent findings.
    Deduplicate by (vuln_type, url, parameter).
    Prefer AI finding when both detected the same vuln (richer evidence + think_trace).
    """
    merged: dict[tuple, Finding] = {}

    for f in rule_findings:
        key = (_normalize_vuln(f.vuln_type), f.url, f.parameter)
        merged[key] = f

    for f in ai_findings:
        key = (_normalize_vuln(f.vuln_type), f.url, f.parameter)
        if key in merged:
            # AI finding wins — has think_trace and richer evidence
            existing = merged[key]
            f.evidence = f"{f.evidence}\n[Also detected by rule engine: {existing.evidence[:100]}]"
        merged[key] = f

    return list(merged.values())


def _normalize_vuln(vuln_type: str) -> str:
    """Normalize vuln type for deduplication."""
    return vuln_type.lower().split("(")[0].split("-")[0].strip()


def _finding_to_event(f: Finding, source: str = "rule_engine") -> dict:
    return {
        "severity":    f.severity,
        "type":        f.vuln_type,
        "url":         f.url,
        "parameter":   f.parameter,
        "evidence":    f.evidence,
        "cvss":        f.cvss,
        "remediation": f.remediation,
        "payload":     f.payload,
        "think_trace": f.think_trace,
        "http_trace":  f.http_trace,
        "source":      source,
    }


def _duration(started: str, finished) -> str:
    if not finished:
        return "?"
    try:
        from datetime import datetime
        s = datetime.fromisoformat(started)
        e = datetime.fromisoformat(finished)
        secs = int((e - s).total_seconds())
        m, s = divmod(secs, 60)
        h, m = divmod(m, 60)
        if h:
            return f"{h}h {m}m {s}s"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"
    except Exception:
        return "?"


async def _load_from_source(config: ScanConfig) -> list[ScanTarget]:
    """Load endpoints from OpenAPI/HAR/Burp/Postman source."""
    try:
        if config.source_type == "openapi":
            from brahmastra.garudastra.input.openapi_parser import OpenAPIParser
            return OpenAPIParser().parse(config.source_content, config.target)
        elif config.source_type == "har":
            from brahmastra.garudastra.input.har_parser import HARParser
            return HARParser().parse(config.source_content)
        elif config.source_type == "burp":
            from brahmastra.garudastra.input.burp_parser import BurpParser
            return BurpParser().parse(config.source_content)
        elif config.source_type == "postman":
            from brahmastra.garudastra.input.postman_parser import PostmanParser
            return PostmanParser().parse(config.source_content, config.target)
        elif config.source_type == "graphql":
            from brahmastra.garudastra.input.graphql_parser import GraphQLParser
            return await GraphQLParser().parse(config.target)
    except Exception as e:
        pass
    return []
