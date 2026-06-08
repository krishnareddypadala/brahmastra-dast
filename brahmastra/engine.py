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
from dataclasses import dataclass
from typing import Optional, Callable
from urllib.parse import urlparse, urljoin

import httpx

from brahmastra.sudarshana.base import Finding, ScanTarget, ScanResult
from brahmastra.garudastra.crawlers.spider import Spider
from brahmastra.garudastra.auth.manager import AuthManager, AuthConfig
from brahmastra.narayanastra.rules import ALL_RULES, Rule, get_rules_for_profile
from brahmastra.narayanastra.authz import AuthZTester
from brahmastra.ai_bridge import AIBridge
from brahmastra.concurrency import AdaptiveSemaphore, make_semaphore


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
    max_concurrency:  int  = 50       # hard ceiling for adaptive modes; literal in fixed
    concurrency_mode: str  = "adaptive"  # polite | balanced | aggressive | adaptive | fixed
    request_delay:    float = 0.0     # seconds between requests (default: rely on adaptive controller)



# ─── Engine ───────────────────────────────────────────────────────────────────

class ScanEngine:
    """
    Main orchestrator. Called from api.py instead of the inline run_scan().
    The existing naive scanner still runs — this adds the rule engine on top.
    """

    def __init__(self):
        self._stop_flag = False
        self._http: Optional[httpx.AsyncClient] = None
        self.sem: Optional[AdaptiveSemaphore] = None
        # Per-host dedup index for site-wide passive findings.
        # Key: (rule_id, host) → Finding (the survivor that owns affected_urls)
        self._host_dedup: dict[tuple[str, str], Finding] = {}

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
        self._host_dedup = {}
        result = ScanResult(scan_id=scan_id, target=config.target)

        async def emit(event_type: str, data: dict):
            if emit_fn:
                try:
                    await emit_fn(event_type, data)
                except Exception:
                    pass

        # ── Persistent HTTP client + adaptive concurrency controller ───────────
        limits = httpx.Limits(
            max_connections=max(config.max_concurrency * 2, 20),
            max_keepalive_connections=max(config.max_concurrency, 10),
            keepalive_expiry=30.0,
        )
        self._http = httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=12,
            limits=limits,
            headers={"User-Agent": "BRAHMASTRA/2.0"},
        )
        self.sem = make_semaphore(config.concurrency_mode, config.max_concurrency)
        await emit("concurrency", self.sem.snapshot())

        try:
            return await self._run_inner(scan_id, config, emit, result)
        finally:
            try:
                await self._http.aclose()
            except Exception:
                pass

    async def _run_inner(
        self,
        scan_id: str,
        config: ScanConfig,
        emit,
        result: ScanResult,
    ) -> ScanResult:

        # ── Resolve auth headers ───────────────────────────────────────────────
        # After resolving, emit an auth_status event so the dashboard can
        # show the user whether login actually worked — previously a bad
        # password or missing CSRF token would silently produce an empty
        # cookie jar and the user had no way to see why the authenticated
        # area wasn't being crawled.
        # Instantiate the AIBridge up-front so AuthManager can consult the
        # model to self-heal form-login failures (rename fields, add missing
        # hidden inputs, switch content-type to JSON, etc.) before the scan
        # even begins. Passing None for a disabled AI mode is cheap — the
        # bridge just no-ops on .enabled checks.
        ai_bridge = AIBridge(mode=config.ai_mode, api_key=config.ai_api_key)

        auth_headers: dict = {}
        auth_diag: dict = {}
        # `mgr` is hoisted out of the `if` block so downstream phases
        # (specifically the AI-driven spider's mid-crawl re-auth loop)
        # can call mgr.get_headers() again on session drop. Without this
        # hoist, mgr only exists inside the auth-config branch and the
        # AISpider has no way to trigger a fresh form-login.
        mgr: Optional[AuthManager] = None
        if config.auth_config:
            mgr = AuthManager(config.auth_config, ai_bridge=ai_bridge)
            auth_headers = await mgr.get_headers()
            auth_type = (config.auth_config.auth_type or "none").lower()
            auth_diag = dict(mgr.last_diag) if mgr.last_diag else {}
            await emit("auth_status", {
                "slot":       "primary",
                "auth_type":  auth_type,
                "ok":         bool(auth_headers) and auth_diag.get("ok", bool(auth_headers)),
                "has_cookie": "Cookie" in auth_headers,
                "header_keys": list(auth_headers.keys()),
                "diag":       auth_diag,
                "message":    auth_diag.get("message") or (
                    f"{auth_type} auth resolved: {list(auth_headers.keys()) or 'no headers'}"
                ),
            })

        second_auth_headers: dict = {}
        if config.second_auth_config:
            mgr2 = AuthManager(config.second_auth_config, ai_bridge=ai_bridge)
            second_auth_headers = await mgr2.get_headers()
            auth_type2 = (config.second_auth_config.auth_type or "none").lower()
            diag2 = dict(mgr2.last_diag) if mgr2.last_diag else {}
            await emit("auth_status", {
                "slot":       "secondary",
                "auth_type":  auth_type2,
                "ok":         bool(second_auth_headers) and diag2.get("ok", bool(second_auth_headers)),
                "has_cookie": "Cookie" in second_auth_headers,
                "header_keys": list(second_auth_headers.keys()),
                "diag":       diag2,
                "message":    diag2.get("message") or (
                    f"{auth_type2} secondary auth resolved"
                ),
            })

        # ── Phase 1: Crawl (structural, AI-free) ──────────────────────────────
        # The spider runs robots/sitemap/HTML/fuzz/JS discovery WITHOUT any
        # AI involvement first, so the AI explorer (Phase 1b) gets real
        # evidence to reason about instead of guessing blind.
        await emit("phase", {"phase": "crawl", "message": "Starting Garudastra recon..."})

        # Build auth-aware seed list: post-login landing URL + a heuristic
        # list of common authenticated paths.  Without these, a login-gated
        # app only reveals its public login form because the spider walks
        # the public link graph from `config.target` and the authenticated
        # pages have no inbound links from there — even though we already
        # hold a valid session cookie.
        extra_seeds = await _build_post_auth_seeds(
            config.target, auth_headers, auth_diag, emit
        )

        endpoints: list[ScanTarget] = []
        spider: Spider | None = None
        try:
            if config.source_type == "url":
                spider = Spider(max_depth=config.scan_depth, max_concurrency=config.max_concurrency)
                endpoints = await spider.crawl(
                    config.target,
                    auth_headers=auth_headers,
                    depth=config.scan_depth,
                    emit_fn=emit,
                    extra_seeds=extra_seeds,
                )
                result.tech_stack = spider.tech_stack
            else:
                endpoints = await _load_from_source(config)
        except Exception as e:
            await emit("error", {"message": f"Crawl error: {e}"})

        # ── Phase 1b: AI-assisted evidence-driven exploration ─────────────────
        # Hand the model an evidence bundle (landing HTML sample, discovered
        # URLs with sources, forms, 404'd common paths, tech stack). The AI
        # suggests specific follow-up paths grounded in that evidence. Each
        # suggestion is HEAD-probed; only live ones (2xx/3xx/401/403) are
        # walked recursively via URLParser. Dead guesses are dropped instead
        # of padding the scan target list with 404s.
        if (
            config.ai_mode and config.ai_mode != "disabled"
            and config.source_type == "url"
            and spider is not None
            and endpoints
        ):
            try:
                await emit("phase", {
                    "phase":   "crawl",
                    "message": "AI exploring based on crawl evidence...",
                })
                planner  = AIBridge(mode=config.ai_mode, api_key=config.ai_api_key)
                evidence = spider.get_evidence_bundle()
                suggestions = await planner.explore_paths(
                    base_url=config.target,
                    tech_stack=result.tech_stack,
                    evidence=evidence,
                )
                if suggestions:
                    await emit("ai_plan", {
                        "phase":    "evidence-based",
                        "count":    len(suggestions),
                        "paths":    suggestions,
                        "evidence": {
                            "discovered":   len(evidence.get("discovered", [])),
                            "failed_paths": len(evidence.get("failed_paths", [])),
                            "forms":        len(evidence.get("forms", [])),
                            "tech_stack":   result.tech_stack,
                        },
                    })
                    new_targets = await spider.probe_and_walk(
                        suggestions, auth_headers, emit
                    )
                    if new_targets:
                        # Spider mutated its own target list — re-sync.
                        endpoints = spider.targets
            except Exception as e:
                await emit("error", {"message": f"AI exploration failed: {e}"})

        # ── Phase 1c: AI-driven deep crawler ──────────────────────────────────
        # Runs AFTER the structural spider + evidence-based AI exploration.
        # Where Phase 1b asks the model to GUESS follow-up paths, this phase
        # feeds every HTTP response we fetch to the model and asks it to
        # EXTRACT the URLs + parameters + forms literally present in that
        # response body. Catches endpoints the regex extractors miss
        # (JS-built SPAs, JSON APIs, dynamic templates) and parameters
        # hidden in data-* attributes / script blocks.
        #
        # Budget-bounded because each page = 1 AI call. Default: 40 pages.
        #
        # Also detects session drops mid-crawl via status + URL + body
        # heuristics AND the model's own `auth_lost` flag, then calls
        # AuthManager.get_headers() again (which has its own AI self-heal
        # path for broken login forms) to refresh cookies before retrying.
        if (
            config.ai_mode and config.ai_mode != "disabled"
            and config.source_type == "url"
            and ai_bridge.enabled
        ):
            try:
                from brahmastra.garudastra.crawlers.ai_spider import AISpider
                from brahmastra.garudastra.crawlers.canonicalizer import (
                    canonical_key,
                    PathTemplateTracker,
                )
                await emit("phase", {
                    "phase":   "crawl",
                    "message": "AI deep crawler analysing pages (one model call per page)...",
                })
                ai_spider = AISpider(
                    ai_bridge       = ai_bridge,
                    # Pass the AuthManager only when we actually have one —
                    # AISpider gracefully skips re-auth when None.
                    auth_manager    = mgr,
                    max_pages       = 40,
                    max_concurrency = 6,
                )
                ai_targets = await ai_spider.crawl(
                    start_url    = config.target,
                    auth_headers = auth_headers,
                    emit_fn      = emit,
                )
                # Merge into endpoints with canonical dedup so the rule
                # engine doesn't re-attack URLs the structural spider
                # already handed it. Any new URL/form the AI caught
                # beyond the structural set is appended to `endpoints`.
                if ai_targets:
                    tracker = PathTemplateTracker()
                    existing_keys: set[str] = set()
                    for ep in endpoints:
                        try:
                            existing_keys.add(
                                canonical_key(ep.url, ep.method or "GET", tracker)
                            )
                        except Exception:
                            pass
                    added = 0
                    for at in ai_targets:
                        try:
                            k = canonical_key(at.url, at.method or "GET", tracker)
                        except Exception:
                            k = at.url
                        if k in existing_keys:
                            continue
                        existing_keys.add(k)
                        endpoints.append(at)
                        added += 1
                    await emit("ai_crawl_summary", {
                        "pages_analyzed":  ai_spider._pages_analysed,
                        "reauth_count":    ai_spider._reauth_count,
                        "auth_lost_events":ai_spider._auth_lost_events,
                        "ai_discovered":   len(ai_targets),
                        "new_targets":     added,
                        "total_targets":   len(endpoints),
                        "backend":         ai_bridge.mode,
                    })
            except Exception as e:
                await emit("error", {"message": f"AI deep crawl failed: {e}"})

        # Drain any passive findings the spider collected during Phase 1/2
        # (missing security headers, insecure cookies, stack-trace leaks,
        # sensitive data in HTML comments). These are emitted as real
        # findings so the dashboard + report pick them up alongside
        # rule-engine and AI-confirmed vulns.
        if spider is not None and getattr(spider, "passive_findings", None):
            for pf in spider.passive_findings:
                try:
                    finding = Finding(
                        severity    = pf.get("severity", "LOW"),
                        vuln_type   = pf.get("type", "Passive finding"),
                        url         = pf.get("url", ""),
                        parameter   = pf.get("parameter", ""),
                        evidence    = pf.get("evidence", ""),
                        cvss        = float(pf.get("cvss", 0.0)),
                        remediation = pf.get("remediation", ""),
                        payload     = pf.get("payload", ""),
                    )
                    result.findings.append(finding)
                    await emit("finding", _finding_to_event(finding, source="passive"))
                except Exception:
                    pass

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

        # ai_bridge was already instantiated at auth-resolution time so the
        # AuthManager could use it for form-login self-heal. Reuse the same
        # instance here.
        # Fresh rule instances per scan — prevents cross-scan state bleed
        rules = [type(r)() for r in get_rules_for_profile(config.scan_profile)]

        # ── Phase 1c: AI Strategist — pre-scan planning ───────────────────────
        # Hand the model the full crawl evidence + any passive findings the
        # spider already collected, and ask for a prioritised rule order,
        # focus URLs, and optional custom payloads. We use the result to
        # re-rank `rules` so the most-likely-to-hit families fire first.
        ai_strategy_plan: Optional[dict] = None
        if ai_bridge.enabled and spider is not None:
            try:
                strategy_evidence = spider.get_evidence_bundle()
                findings_seen = [
                    {"severity": f.severity, "type": f.vuln_type}
                    for f in result.findings[-50:]
                ]
                ai_strategy_plan = await ai_bridge.plan_scan_strategy(
                    base_url         = config.target,
                    tech_stack       = result.tech_stack,
                    evidence         = strategy_evidence,
                    available_rules  = [r.name for r in rules],
                    findings_so_far  = findings_seen,
                )
                if ai_strategy_plan:
                    await emit("ai_strategy", {
                        "phase":           "post-crawl",
                        "priority_rules":  ai_strategy_plan.get("priority_rules", []),
                        "focus_urls":      ai_strategy_plan.get("focus_urls", []),
                        "custom_payloads": ai_strategy_plan.get("custom_payloads", {}),
                        "reasoning":       ai_strategy_plan.get("reasoning", ""),
                        "confidence":      ai_strategy_plan.get("confidence", 0.0),
                    })
                    # Re-rank rules so priority_rules fire first. Preserves
                    # every rule (nothing is dropped), just reorders.
                    priority = ai_strategy_plan.get("priority_rules", [])
                    if priority:
                        rank: dict[str, int] = {
                            name: i for i, name in enumerate(priority)
                        }
                        rules.sort(
                            key=lambda r: rank.get(r.name, len(priority) + 1)
                        )
                    # Inject custom payloads into matching rules.
                    custom = ai_strategy_plan.get("custom_payloads", {}) or {}
                    for rule in rules:
                        extras = custom.get(rule.name) or []
                        if extras:
                            rule.payloads = list(rule.payloads) + [
                                str(p) for p in extras
                            ][:10]
            except Exception as e:
                await emit("error", {
                    "message": f"AI strategist call failed: {e}",
                })

        # Get AI-suggested extra payloads if AI enabled
        if ai_bridge.enabled and result.tech_stack:
            for rule in rules[:5]:  # Only top rules for efficiency
                extra = await ai_bridge.craft_payloads(
                    rule.name, result.tech_stack, "param", rule.payloads[:3]
                )
                if extra:
                    rule.payloads = rule.payloads + extra

        # NOTE: the old post-crawl AIBridge.suggest_paths() call used to live
        # here and flat-add AI guesses as ScanTargets regardless of whether
        # they were reachable. That blind-guess path is now replaced by the
        # evidence-driven Phase 1b above (spider.probe_and_walk) which only
        # keeps suggestions that actually respond.

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
        """
        Flat work queue: every (rule, target, param) tuple is fired in parallel
        through the AdaptiveSemaphore. Cross-rule fan-out + connection pooling
        gets us 30-60 req/s instead of 0.7 req/s.
        """
        findings: list[Finding] = []
        rule_findings_count: dict[str, int] = {r.id: 0 for r in rules}
        progress = {"done": 0}
        # Track the last findings-count at which the AI strategist was
        # consulted mid-scan. Every +50 findings we kick off a background
        # re-strategy call so the model can react to what we're finding.
        strategy_state = {"last_consulted_at": 0, "in_flight": False}

        async def maybe_restrategize() -> None:
            """Fire an `ai_strategy` event with mid-scan reasoning if the
            findings count has grown past the +50 threshold. Non-blocking:
            the caller schedules us as a background task."""
            if not ai_bridge.enabled:
                return
            strategy_state["in_flight"] = True
            try:
                evidence = {
                    "discovered": [
                        {"url": t.url, "method": t.method, "source": t.source or "?"}
                        for t in endpoints[:30]
                    ],
                    "failed_paths": [],
                    "forms": [],
                }
                findings_snapshot = [
                    {"severity": f.severity, "type": f.vuln_type}
                    for f in findings[-80:]
                ]
                plan = await ai_bridge.plan_scan_strategy(
                    base_url        = config.target,
                    tech_stack      = result.tech_stack,
                    evidence        = evidence,
                    available_rules = [r.name for r in rules],
                    findings_so_far = findings_snapshot,
                )
                if plan:
                    await emit("ai_strategy", {
                        "phase":          "mid-scan",
                        "priority_rules": plan.get("priority_rules", []),
                        "focus_urls":     plan.get("focus_urls", []),
                        "reasoning":      plan.get("reasoning", ""),
                        "confidence":     plan.get("confidence", 0.0),
                        "findings_count": len(findings),
                    })
            except Exception:
                pass
            finally:
                strategy_state["in_flight"] = False

        # Build flat work units: (rule, target, param_dict_or_None)
        work_units: list[tuple[Rule, ScanTarget, Optional[dict]]] = []
        for rule in rules:
            for target in endpoints:
                if not rule.payloads:
                    # Passive rule — single baseline probe per target, no params
                    work_units.append((rule, target, None))
                    continue
                params = target.parameters or [{"name": "q", "location": "query"}]
                for param in params:
                    location = param.get("location", "query")
                    if location not in rule.locations:
                        continue
                    work_units.append((rule, target, param))

        total_probes = len(work_units)

        async def process_unit(rule: Rule, target: ScanTarget, param: Optional[dict]):
            if self._stop_flag:
                return
            try:
                await self._probe_one(
                    rule, target, param, auth_headers, ai_bridge,
                    result, config, emit, findings, rule_findings_count,
                )
            except Exception:
                pass
            finally:
                progress["done"] += 1
                # Periodic concurrency telemetry (every 25 probes)
                if progress["done"] % 25 == 0 and self.sem is not None:
                    snap = self.sem.snapshot()
                    snap["done"] = progress["done"]
                    snap["total"] = total_probes
                    await emit("concurrency", snap)
                # Mid-scan AI re-strategy: every +50 findings, kick off a
                # non-blocking background call that emits a new ai_strategy
                # event with updated reasoning. The scan keeps probing
                # while the model thinks.
                try:
                    delta = len(findings) - strategy_state["last_consulted_at"]
                    if (
                        delta >= 50
                        and not strategy_state["in_flight"]
                        and ai_bridge.enabled
                    ):
                        strategy_state["last_consulted_at"] = len(findings)
                        asyncio.create_task(maybe_restrategize())
                except Exception:
                    pass

        await asyncio.gather(
            *(process_unit(r, t, p) for r, t, p in work_units),
            return_exceptions=True,
        )

        # Final per-rule progress flush
        for rule in rules:
            await emit("rule_progress", {
                "rule_id":       rule.id,
                "rule_name":     rule.name,
                "severity":      rule.severity,
                "findings_count": rule_findings_count.get(rule.id, 0),
                "done":          total_probes,
                "total":         total_probes,
            })

        return findings

    async def _probe_one(
        self,
        rule: Rule,
        target: ScanTarget,
        param: Optional[dict],
        auth_headers: dict,
        ai_bridge: AIBridge,
        result: ScanResult,
        config: ScanConfig,
        emit,
        findings: list,
        rule_findings_count: dict,
    ) -> None:
        """Probe a single (rule, target, param) — sweeps payloads, breaks on hit."""
        # Passive rule branch
        if param is None or not rule.payloads:
            async with self.sem:
                body, hdrs, status, elapsed = await _fetch_baseline(
                    self._http, target.url, target.method, auth_headers, config.request_delay
                )
            result.total_requests += 1
            confidence = rule.detect(body, hdrs, status, "", body, status, elapsed)
            if confidence < 0.3:
                return

            # Site-wide misconfig (security headers, server banner, etc.):
            # collapse all matches for the same (rule, host) into ONE finding
            # whose evidence carries the full URL list.
            if getattr(rule, "dedupe_per_host", False):
                from urllib.parse import urlparse
                host = urlparse(target.url).netloc
                key = (rule.id, host)
                existing = self._host_dedup.get(key)
                if existing is not None:
                    # Append URL to the existing finding's evidence list
                    if target.url not in existing.evidence:
                        # Track URL count via simple in-place rewrite of evidence
                        if "[+" in existing.evidence:
                            # Already has summary suffix — bump the count
                            import re as _re
                            m = _re.search(r"\[\+(\d+) more URLs?", existing.evidence)
                            n = int(m.group(1)) + 1 if m else 2
                            existing.evidence = _re.sub(
                                r"\[\+\d+ more URLs?[^\]]*\]",
                                f"[+{n} more URLs affected]",
                                existing.evidence,
                            )
                        else:
                            existing.evidence += " [+1 more URL affected]"
                    return
                # First sighting on this host — create the finding and remember it
                finding = _make_finding(rule, confidence, target.url, "(site-wide)", body, "")
                self._host_dedup[key] = finding
                findings.append(finding)
                rule_findings_count[rule.id] = rule_findings_count.get(rule.id, 0) + 1
                await emit("finding", _finding_to_event(finding, source="rule_engine"))
                return

            finding = _make_finding(rule, confidence, target.url, "(passive)", body, "")
            findings.append(finding)
            rule_findings_count[rule.id] = rule_findings_count.get(rule.id, 0) + 1
            await emit("finding", _finding_to_event(finding, source="rule_engine"))
            return

        param_name = param.get("name", "q")
        location   = param.get("location", "query")

        # Stateful rules (e.g. SQLiBoolean/Union/Time) keep mutable state on
        # self._*. With the flat work queue, multiple (rule, target, param)
        # units run in parallel and would race on a shared instance. Clone
        # per work unit so each gets its own state silo. Stateless rules
        # don't have reset_state and can stay shared.
        if hasattr(rule, "reset_state"):
            try:
                rule = type(rule)()
            except Exception:
                try:
                    rule.reset_state()
                except Exception:
                    pass

        # Baseline (counted under sem so latency feeds the controller)
        async with self.sem:
            base_body, base_hdrs, base_status, _ = await _fetch_baseline(
                self._http, target.url, target.method, auth_headers, config.request_delay
            )
        result.total_requests += 1

        for payload in rule.payloads:
            if self._stop_flag:
                return
            async with self.sem:
                body, hdrs, status, elapsed, http_trace = await _inject_and_fetch(
                    self._http, target.url, target.method, param_name, payload,
                    location, auth_headers, config.request_delay
                )
            result.total_requests += 1

            confidence = rule.detect(
                body, hdrs, status, payload,
                base_body, base_status, elapsed
            )

            await emit("probe", {
                "rule":        rule.id,
                "rule_id":     rule.id,
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
                rule_findings_count[rule.id] = rule_findings_count.get(rule.id, 0) + 1
                await emit("finding", _finding_to_event(finding, source="rule_engine"))
                return  # one confirmation per (rule, target, param)

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
                    rule_findings_count[rule.id] = rule_findings_count.get(rule.id, 0) + 1
                    await emit("finding", _finding_to_event(finding, source="ai_confirmed"))
                    return

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
    client: httpx.AsyncClient, url: str, method: str, headers: dict, delay: float
) -> tuple[str, dict, int, float]:
    """Fetch the original response as a baseline. Reuses the engine's pooled client."""
    if delay:
        await asyncio.sleep(delay)
    t0 = time.time()
    try:
        resp = await client.request(method, url, headers=headers)
        return resp.text, dict(resp.headers), resp.status_code, round(time.time() - t0, 3)
    except Exception:
        return "", {}, 0, round(time.time() - t0, 3)


async def _inject_and_fetch(
    client: httpx.AsyncClient, url: str, method: str, param: str, payload: str,
    location: str, headers: dict, delay: float
) -> tuple[str, dict, int, float, str]:
    """Inject payload into the target and return (body, headers, status, elapsed, http_trace)."""
    if delay:
        await asyncio.sleep(delay)
    t0 = time.time()
    try:
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


# Heuristic paths that almost always exist in an authenticated area but
# have NO inbound link from a public login page. Scanned in parallel via
# HEAD — only 2xx/3xx responses become spider seeds, so we don't dilute
# the crawl with 404s.  Ordered roughly by prevalence.
_COMMON_AUTH_PATHS = [
    # User-facing dashboards
    "/dashboard", "/dashboard.php", "/dashboard.html",
    "/home", "/home.php",
    "/profile", "/profile.php", "/myaccount", "/my-account",
    "/account", "/account.php", "/settings", "/settings.php",
    "/preferences", "/user", "/users", "/user/profile",
    "/me", "/members", "/member",
    # Common banking/transfer/money flows (ntr.army-style apps)
    "/transfer", "/transfer.php", "/transactions", "/transactions.php",
    "/payments", "/payment", "/balance", "/wallet",
    "/orders", "/order", "/cart", "/checkout",
    # Messaging / inbox
    "/inbox", "/messages", "/chat", "/notifications",
    # Admin / staff
    "/admin", "/admin.php", "/admin/", "/admin/dashboard",
    "/panel", "/cpanel", "/manage", "/console",
    # API conventions
    "/api/user", "/api/users", "/api/me", "/api/profile",
    "/api/account", "/api/dashboard", "/api/session",
    # ⚠️ NOTE: do NOT include logout / signout / destroy / kill_session paths
    # here. Seeding them into the spider walks them with the captured
    # PHPSESSID, which the server then INVALIDATES — and every subsequent
    # crawl request comes back as the unauthenticated login page. This
    # silently destroys the entire authenticated crawl. The logout endpoint
    # still gets discovered later via the fuzz phase against the public root,
    # but that runs without holding the session cookie of the live scan.
]


# Path substrings that, if visited while holding a session cookie, will
# log us out. We strip any seed whose path contains one of these tokens
# before handing the seed list to the spider.
_SESSION_DESTROYING_PATTERNS = (
    "logout", "log-out", "log_out",
    "signout", "sign-out", "sign_out",
    "destroy", "kill_session", "killsession",
    "/end_session", "endsession",
)


def _is_session_destroying(url: str) -> bool:
    """True if visiting `url` while authenticated is likely to terminate
    the session (logout / signout / destroy / kill_session pages)."""
    try:
        path = (urlparse(url).path or "").lower()
    except Exception:
        return False
    return any(tok in path for tok in _SESSION_DESTROYING_PATTERNS)


async def _build_post_auth_seeds(
    target: str,
    auth_headers: dict,
    auth_diag: dict,
    emit,
) -> list[str]:
    """
    After auth resolution, generate spider seeds for the authenticated
    surface:

      1. The post-login landing URL (auth_diag['final_url']) — this is
         where the login POST redirected to, e.g. /profile.php.
      2. A curated list of common authenticated paths (/dashboard,
         /transfer, /account, ...), HEAD-probed with the auth cookies
         so only live endpoints become seeds.

    Returns a list of absolute URLs on the same host as `target`.  Empty
    list if no cookie/header was captured — we don't want to waste 40
    HEAD requests on an unauthenticated scan.
    """
    if not auth_headers:
        return []

    try:
        parsed = urlparse(target)
    except Exception:
        return []
    base = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.netloc

    seeds: list[str] = []
    seen: set = set()

    # ── (1) Post-login landing page ──
    final_url = (auth_diag or {}).get("final_url", "")
    if final_url:
        try:
            fp = urlparse(final_url)
            if (fp.netloc == host
                    and final_url != target.rstrip("/") + "/"
                    and not _is_session_destroying(final_url)):
                seeds.append(final_url)
                seen.add(final_url)
        except Exception:
            pass

    # ── (2) HEAD-probe common authenticated paths in parallel ──
    # Defence in depth: even though _COMMON_AUTH_PATHS no longer lists logout
    # paths, drop anything that looks session-destroying so a future careless
    # edit can never silently kill an authenticated crawl again.
    candidates = [
        urljoin(base + "/", p.lstrip("/"))
        for p in _COMMON_AUTH_PATHS
        if not _is_session_destroying(p)
    ]
    live: list[str] = []

    # Detect "final URL after redirect == login page" as a failure signal.
    # ntr.army and many PHP apps redirect unauthenticated requests for
    # /profile.php to /login.php and return 200, so status-code alone is
    # not enough to decide if the session actually worked.
    login_url_raw = (auth_diag or {}).get("login_url", "") or ""
    login_path = ""
    try:
        login_path = urlparse(login_url_raw).path or ""
    except Exception:
        login_path = ""

    async def _probe(u: str):
        try:
            status, final = await _head_or_get(u, auth_headers)
            if status is None:
                return
            # If the response landed on the login page, the request was
            # NOT actually authenticated for this path — skip it.
            if login_path and final:
                try:
                    if urlparse(final).path == login_path:
                        return
                except Exception:
                    pass
            # 2xx/3xx and 401/403 all indicate "endpoint exists". 401/403
            # are deliberately included because they're authz bugs
            # waiting to be tested.
            if status < 400 or status in (401, 403):
                live.append(u)
        except Exception:
            pass

    # Cap concurrency so we don't hammer a small box.
    sem = asyncio.Semaphore(10)
    async def _bounded(u: str):
        async with sem:
            await _probe(u)

    await asyncio.gather(*[_bounded(u) for u in candidates])

    for u in live:
        if u not in seen:
            seeds.append(u)
            seen.add(u)

    if seeds:
        try:
            await emit("log", {
                "msg": f"Auth-aware seeds discovered: {len(seeds)} live paths "
                       f"(final_url + {len(live)} common auth paths)",
                "level": "info",
            })
            await emit("log", {
                "msg": "Seeds: " + ", ".join(
                    urlparse(s).path or "/" for s in seeds[:12]
                ) + (f" (+{len(seeds)-12} more)" if len(seeds) > 12 else ""),
                "level": "info",
            })
        except Exception:
            pass
    return seeds


async def _head_or_get(
    url: str, auth_headers: dict
) -> tuple[Optional[int], str]:
    """
    HEAD probe with GET fallback. Returns (status_code, final_url_after_redirects).
    Used by the auth-seed builder to detect the common "redirect to login
    page" pattern — status code 200 alone doesn't prove the session works
    because many apps serve the login page body at 200 for unauthenticated
    requests to protected paths.
    """
    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=6,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                **auth_headers,
            },
        ) as client:
            try:
                r = await client.head(url)
                # Some frameworks return 405 for HEAD but serve GET fine.
                if r.status_code in (405, 501):
                    r = await client.get(url)
                return r.status_code, str(r.url)
            except httpx.RequestError:
                return None, ""
    except Exception:
        return None, ""


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
