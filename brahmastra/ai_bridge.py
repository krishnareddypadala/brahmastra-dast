"""
BRAHMASTRA — AI Bridge
Mediates between the rule engine and AI backends.

Modes:
  "disabled"     → all methods return empty/None. Zero AI calls. GPU-safe.
  "brahmastra"   → calls BRAHMASTRA p6 (32B fine-tuned) via Ollama at localhost:11434
  "gemini_flash" → Google Gemini 2.0 Flash via REST
  "claude_haiku" → Anthropic Claude Haiku via REST
  "openai"       → OpenAI GPT-4o-mini via REST

AI role:
  - analyze_finding(): called when rule confidence is 0.3–0.8 (ambiguous)
    → returns {"confirmed": bool, "evidence": str, "think_trace": str} or None
  - craft_payloads(): after tech fingerprinting, generates targeted extra payloads
    → returns list[str] (empty if disabled)
  - suggest_paths(): after initial crawl, suggests additional paths to probe
    → returns list[str] (empty if disabled)
"""

from __future__ import annotations
import json
import os
import re
from typing import Optional

import httpx


BRAHMASTRA_SYSTEM_PROMPT = (
    "You are BRAHMASTRA, an elite AI-powered DAST security scanner. "
    "Use <think>...</think> to reason before each response. "
    "Be precise — only confirm vulnerabilities with clear evidence. "
    "Respond in JSON only."
)


class AIBridge:
    def __init__(self, mode: str = "disabled", api_key: str = ""):
        self.mode    = mode.lower()
        self.api_key = api_key or os.getenv("AI_API_KEY", "")

    @property
    def enabled(self) -> bool:
        return self.mode != "disabled"

    async def analyze_finding(
        self,
        payload: str,
        response_body: str,
        response_status: int,
        vuln_type: str,
        confidence: float,
        url: str,
        parameter: str,
    ) -> Optional[dict]:
        """
        Ask AI to confirm or dismiss a suspicious finding (confidence 0.3–0.8).
        Returns {"confirmed": bool, "evidence": str, "think_trace": str} or None.
        """
        if not self.enabled:
            return None

        prompt = (
            f"A heuristic rule detected a potential {vuln_type} vulnerability at {url} "
            f"(parameter: {parameter}) with confidence {confidence:.0%}.\n\n"
            f"Payload used: {payload[:200]}\n"
            f"HTTP status: {response_status}\n"
            f"Response body (first 600 chars):\n{response_body[:600]}\n\n"
            f"Is this a confirmed vulnerability? "
            f"Respond with JSON: {{\"confirmed\": true/false, \"evidence\": \"why\", \"confidence\": 0.0-1.0}}"
        )

        raw = await self._call(prompt)
        if not raw:
            return None

        think_trace, clean = _extract_think(raw)
        try:
            data = json.loads(_extract_json(clean))
            return {
                "confirmed":   bool(data.get("confirmed", False)),
                "evidence":    str(data.get("evidence", "")),
                "confidence":  float(data.get("confidence", confidence)),
                "think_trace": think_trace,
            }
        except Exception:
            return None

    async def judge_finding(
        self,
        *,
        vuln_type: str,
        severity: str,
        url: str,
        parameter: str,
        payload: str,
        request_trace: str,
        response_status: int,
        response_body: str,
        response_headers: dict,
    ) -> Optional[dict]:
        """
        Post-scan FP analysis: ask the model whether a finding is a real
        vuln or a false positive.

        Used by brahmastra.fp_analyzer.FPAnalyzer in the inline
        analyzing_fp phase that runs between the engine's findings loop
        and update_scan_status("complete"). Different from
        analyze_finding() above — that one runs in-flight on ambiguous
        heuristic hits during the scan; this one is the dedicated
        post-scan judge.

        Returns:
            {"verdict":    "confirmed" | "false_positive" | "uncertain",
             "confidence": 0-100 int,
             "reason":     str (one sentence),
             "think":      str (extracted <think>...</think> trace)}
            or None if AI is disabled / unreachable / unparseable.
        """
        if not self.enabled:
            return None

        # Headers can be a CIMultiDict / httpx.Headers — coerce to a small
        # plain dict for the prompt and cap at 10 entries to keep token
        # cost predictable.
        try:
            hdr_items = list(response_headers.items())[:10]
            hdr_dict  = {str(k): str(v)[:200] for k, v in hdr_items}
        except Exception:
            hdr_dict = {}

        prompt = (
            "You are a senior offensive-security analyst reviewing a single "
            "DAST finding to decide whether it is a real vulnerability or a "
            "false positive produced by a noisy heuristic.\n\n"
            f"VULN_TYPE: {vuln_type}\n"
            f"SEVERITY:  {severity}\n"
            f"URL:       {url}\n"
            f"PARAMETER: {parameter}\n"
            f"PAYLOAD:   {(payload or '')[:500]}\n\n"
            f"REQUEST (raw, first 2 KB):\n{(request_trace or '')[:2000]}\n\n"
            f"RESPONSE STATUS:  {response_status}\n"
            f"RESPONSE HEADERS: {hdr_dict}\n"
            f"RESPONSE BODY (first 4 KB):\n{(response_body or '')[:4096]}\n\n"
            "Decide between exactly these three verdicts:\n"
            "  - confirmed: the payload demonstrably caused the documented "
            "behaviour (sql error string, literal payload reflection in a "
            "live sink, time delay, file disclosure, command output, etc.) "
            "AND it is exploitable.\n"
            "  - false_positive: the response is a generic error / 404 / "
            "framework template / static asset, the indicator matched by "
            "accident, or the payload was sanitised before reaching any "
            "sink.\n"
            "  - uncertain: cannot decide from this single sample alone — "
            "needs a retest with additional probes.\n\n"
            "Respond with ONLY this JSON, no prose around it:\n"
            '{"verdict":"confirmed|false_positive|uncertain",'
            '"confidence":0-100,"reason":"one sentence"}'
        )

        raw = await self._call(prompt)
        if not raw:
            return None

        think, clean = _extract_think(raw)
        try:
            data = json.loads(_extract_json(clean))
            if not isinstance(data, dict):
                return None
            verdict = str(data.get("verdict", "uncertain")).lower().strip()
            if verdict not in ("confirmed", "false_positive", "uncertain"):
                verdict = "uncertain"
            try:
                conf = int(float(data.get("confidence", 0)))
            except (TypeError, ValueError):
                conf = 0
            return {
                "verdict":    verdict,
                "confidence": max(0, min(100, conf)),
                "reason":     str(data.get("reason", ""))[:500],
                "think":      think[:2000],
            }
        except Exception:
            return {
                "verdict":    "uncertain",
                "confidence": 0,
                "reason":     "ai parse error",
                "think":      think[:2000],
            }

    async def craft_retest_probes(
        self,
        *,
        vuln_type: str,
        parameter: str,
        original_payload: str,
        max_probes: int = 5,
    ) -> list[dict]:
        """
        Ask the model for up to `max_probes` retest payloads for a single
        finding flagged FP / uncertain by judge_finding().

        The returned list MUST contain exactly one benign negative
        control as its first element (so a clean response on a benign
        input proves the endpoint is responsive at all and rules out
        flaky-network confounders), followed by up to `max_probes - 1`
        distinct positive mutations of the original payload.

        Each item:
            {"payload": str,
             "is_negative_control": bool,
             "expect": str (what the analyst should look for)}

        Returns [] if AI is disabled / unreachable / unparseable.
        """
        if not self.enabled:
            return []

        prompt = (
            "You are crafting a retest probe set for a single DAST finding "
            "to confirm or rule out a false positive. The DAST engine "
            "already fired the original payload below; you are now "
            "designing a follow-up sweep.\n\n"
            f"VULN_TYPE:        {vuln_type}\n"
            f"PARAMETER:        {parameter}\n"
            f"ORIGINAL_PAYLOAD: {(original_payload or '')[:300]}\n\n"
            f"Produce EXACTLY {max_probes} probes as a JSON array. Rules:\n"
            "  1. Index 0 MUST be a benign negative control — a plain "
            "string (e.g. 'aaa', '1', 'hello') that should NOT trigger "
            "the vulnerability. Mark it is_negative_control=true. Used "
            "to prove the endpoint is reachable and the indicator only "
            "fires on the real attack.\n"
            f"  2. Indexes 1..{max_probes - 1} are distinct mutations of "
            "the original payload — different encoding, alternate "
            "boundary, time-delay variant, blind variant, double-encoded, "
            "etc. Mark each is_negative_control=false.\n"
            "  3. Each item shape: "
            '{"payload":"...","is_negative_control":bool,"expect":"what '
            'should happen if the vuln is real"}\n'
            "  4. Respond with ONLY the JSON array, no prose around it."
        )

        raw = await self._call(prompt)
        if not raw:
            return []

        _, clean = _extract_think(raw)
        try:
            arr = json.loads(_extract_json(clean))
        except Exception:
            return []
        if not isinstance(arr, list):
            return []

        out: list[dict] = []
        for i, item in enumerate(arr[:max_probes]):
            if not isinstance(item, dict):
                continue
            payload = str(item.get("payload", ""))[:500]
            if not payload:
                continue
            out.append({
                "payload":             payload,
                "is_negative_control": bool(item.get("is_negative_control", i == 0)),
                "expect":              str(item.get("expect", ""))[:200],
            })
        return out

    async def craft_payloads(
        self,
        vuln_type: str,
        tech_stack: list[str],
        param_name: str,
        existing_payloads: list[str],
    ) -> list[str]:
        """
        Generate extra targeted payloads based on detected tech stack.
        Returns [] if disabled.
        """
        if not self.enabled:
            return []

        tech_str = ", ".join(tech_stack) if tech_stack else "unknown"
        prompt = (
            f"Target tech stack: {tech_str}\n"
            f"Vulnerability type: {vuln_type}\n"
            f"Parameter: {param_name}\n"
            f"Existing payloads tested: {json.dumps(existing_payloads[:5])}\n\n"
            f"Generate 5 additional targeted payloads for this specific tech stack. "
            f"Respond with JSON array: [\"payload1\", \"payload2\", ...]"
        )

        raw = await self._call(prompt)
        if not raw:
            return []

        _, clean = _extract_think(raw)
        try:
            payloads = json.loads(_extract_json(clean))
            if isinstance(payloads, list):
                return [str(p) for p in payloads if p][:10]
        except Exception:
            pass
        return []

    async def suggest_paths(
        self,
        base_url: str,
        tech_stack: list[str],
        discovered_paths: list[str],
    ) -> list[str]:
        """
        Suggest additional paths to crawl based on tech stack and what was found so far.
        Returns [] if disabled.
        """
        if not self.enabled:
            return []

        tech_str = ", ".join(tech_stack) if tech_stack else "unknown"
        paths_str = json.dumps(discovered_paths[:20])
        prompt = (
            f"Target: {base_url}\n"
            f"Tech stack: {tech_str}\n"
            f"Already discovered paths: {paths_str}\n\n"
            f"Suggest 10 additional API/admin paths likely to exist on this target. "
            f"Respond with JSON array: [\"/path1\", \"/path2\", ...]"
        )

        raw = await self._call(prompt)
        if not raw:
            return []

        _, clean = _extract_think(raw)
        try:
            paths = json.loads(_extract_json(clean))
            if isinstance(paths, list):
                return [str(p) for p in paths if p.startswith("/")][:15]
        except Exception:
            pass
        return []

    async def explore_paths(
        self,
        base_url: str,
        tech_stack: list[str],
        evidence: dict,
    ) -> list[str]:
        """
        Evidence-driven path exploration — the model receives the actual
        crawl state (sample HTML, discovered URLs with sources, forms,
        404'd paths, tech stack) and is asked for SPECIFIC follow-ups
        grounded in that evidence, not generic guesses.

        evidence = {
            "html_sample":   str    (first ~2KB of landing HTML),
            "discovered":    [{"url","method","source"}, ...],
            "failed_paths":  [str, ...],   # paths that returned 404/410
            "forms":         [{"action","method"}, ...],
        }
        """
        if not self.enabled:
            return []

        tech_str   = ", ".join(tech_stack) if tech_stack else "unknown"
        html_samp  = (evidence.get("html_sample") or "")[:2000]
        discovered = evidence.get("discovered") or []
        failed     = evidence.get("failed_paths") or []
        forms      = evidence.get("forms") or []

        discovered_str = "\n".join(
            f"  - {d.get('method','GET')} {d.get('url','')} [{d.get('source','?')}]"
            for d in discovered[:15]
        ) or "  (none)"
        failed_str = ", ".join(failed[:12]) if failed else "(none tried yet)"
        forms_str = "\n".join(
            f"  - {f.get('method','POST')} {f.get('action','')}"
            for f in forms[:5]
        ) or "  (none)"

        prompt = (
            "You are a pentester planning follow-up crawl targets. "
            "Use ONLY the evidence below. Do NOT invent generic paths — "
            "tie each suggestion to something you can point at in the evidence.\n\n"
            f"Target: {base_url}\n"
            f"Tech stack: {tech_str}\n\n"
            f"Already discovered URLs ({len(discovered)} total, up to 15 shown):\n"
            f"{discovered_str}\n\n"
            f"Forms found:\n{forms_str}\n\n"
            f"Paths already tried and 404'd — do NOT suggest these:\n{failed_str}\n\n"
            f"Landing page HTML sample (first 2KB):\n"
            f"```html\n{html_samp}\n```\n\n"
            "Suggest 8 SPECIFIC paths worth probing next, in priority order. "
            "Prefer paths that are:\n"
            "  1. Hinted at by the HTML sample (routes, links, comments, hidden inputs)\n"
            "  2. Adjacent to discovered forms (e.g. /login -> /logout /register /password-reset)\n"
            "  3. Sibling/parent of discovered URLs (e.g. /user/42 -> /user/1 /user/admin /user)\n"
            "  4. Native to the detected tech stack\n"
            "  5. NOT in the 404'd list above\n\n"
            "Respond with ONLY a JSON array of absolute paths starting with '/'. "
            "Example: [\"/user/1\", \"/api/v2/users\", \"/admin/dashboard\"]"
        )

        raw = await self._call(prompt)
        if not raw:
            return []

        _, clean = _extract_think(raw)
        try:
            paths = json.loads(_extract_json(clean))
            if isinstance(paths, list):
                out = []
                seen = set()
                for p in paths:
                    s = str(p).strip()
                    if s.startswith("/") and s not in seen and s not in failed:
                        seen.add(s)
                        out.append(s)
                return out[:12]
        except Exception:
            pass
        return []

    async def plan_scan_strategy(
        self,
        base_url: str,
        tech_stack: list[str],
        evidence: dict,
        available_rules: list[str],
        findings_so_far: list[dict],
    ) -> Optional[dict]:
        """
        Ask the model for a *scan strategy* given the current state of the
        crawl AND any findings already collected. This is a higher-level
        call than `explore_paths` / `craft_payloads`: the model is acting
        as an armchair pentester prioritising where to focus next.

        Called by the engine in TWO places:
          1. Once after the crawl completes, before the active scan starts
             — the model sees the full crawl surface + passive findings and
             picks which rules to front-load.
          2. Every 50 findings during the active scan — the model gets to
             re-steer the scan based on what's actually being found (e.g.
             "you've already confirmed 3 SQLi, prioritise authz tests next").

        Returns dict shape:
          {
            "priority_rules":  ["SQLi", "XSS", "SSRF", ...],  # ranked
            "focus_urls":      ["/api/login", "/admin", ...], # what to hit hard
            "custom_payloads": {"SQLi": ["payload1", ...]},   # per-rule extras
            "reasoning":       "short human-readable explanation",
            "confidence":      0.0-1.0,
            "think_trace":     "...",                         # <think>..</think>
          }
        or None if AI disabled / the call failed.
        """
        if not self.enabled:
            return None

        tech_str     = ", ".join(tech_stack) if tech_stack else "unknown"
        discovered   = evidence.get("discovered") or []
        forms        = evidence.get("forms") or []
        failed_paths = evidence.get("failed_paths") or []

        disc_str = "\n".join(
            f"  - {d.get('method','GET')} {d.get('url','')} [{d.get('source','?')}]"
            for d in discovered[:25]
        ) or "  (none)"
        forms_str = "\n".join(
            f"  - {f.get('method','POST')} {f.get('action','')}"
            for f in forms[:10]
        ) or "  (none)"

        # Summarise findings so far by type + severity so the prompt
        # stays bounded regardless of scan length.
        finding_summary: dict[str, int] = {}
        for f in findings_so_far[-100:]:
            key = f"{f.get('severity','?')} · {f.get('type','?')}"
            finding_summary[key] = finding_summary.get(key, 0) + 1
        findings_str = "\n".join(
            f"  - {k}: {v}" for k, v in sorted(
                finding_summary.items(), key=lambda x: -x[1]
            )[:15]
        ) or "  (no findings yet)"

        rules_str = ", ".join(available_rules) if available_rules else "all"

        prompt = (
            "You are BRAHMASTRA, an elite DAST strategist. You have just "
            "finished a structural crawl against the target below. Decide "
            "where the active scan phase should focus to maximise real "
            "vulnerability discovery in the shortest time.\n\n"
            f"Target: {base_url}\n"
            f"Tech stack: {tech_str}\n\n"
            f"Discovered surface ({len(discovered)} urls, up to 25 shown):\n"
            f"{disc_str}\n\n"
            f"Forms discovered:\n{forms_str}\n\n"
            f"Paths that 404'd during fuzz:\n"
            f"  {', '.join(failed_paths[:10]) or '(none)'}\n\n"
            f"Findings already collected (by type):\n{findings_str}\n\n"
            f"Available rule families: {rules_str}\n\n"
            "Respond with JSON in exactly this shape:\n"
            "{\n"
            '  "priority_rules":  ["RuleA", "RuleB", ...],\n'
            '  "focus_urls":      ["/path1", "/path2", ...],\n'
            '  "custom_payloads": {"RuleA": ["payload1","payload2"]},\n'
            '  "reasoning":       "why this strategy for THIS target",\n'
            '  "confidence":      0.0\n'
            "}\n\n"
            "Rules:\n"
            "- Rank priority_rules by likelihood of finding a real vuln "
            "on this specific tech stack.\n"
            "- focus_urls MUST be absolute paths starting with '/' drawn "
            "from the discovered surface above.\n"
            "- custom_payloads entries must target frameworks in the tech "
            "stack (e.g. Postgres syntax if Postgres is detected).\n"
            "- reasoning must be ≤ 3 sentences.\n"
            "- Do NOT suggest rules that aren't in the available list."
        )

        raw = await self._call(prompt)
        if not raw:
            return None

        think_trace, clean = _extract_think(raw)
        try:
            data = json.loads(_extract_json(clean))
            if not isinstance(data, dict):
                return None
            return {
                "priority_rules":  [str(r) for r in data.get("priority_rules", [])][:15],
                "focus_urls":      [
                    str(u) for u in data.get("focus_urls", [])
                    if isinstance(u, str) and u.startswith("/")
                ][:20],
                "custom_payloads": {
                    str(k): [str(p) for p in (v or [])][:10]
                    for k, v in (data.get("custom_payloads") or {}).items()
                    if isinstance(v, list)
                },
                "reasoning":   str(data.get("reasoning", ""))[:500],
                "confidence":  float(data.get("confidence", 0.5)),
                "think_trace": think_trace,
            }
        except Exception:
            return None

    async def diagnose_auth_failure(
        self,
        login_url: str,
        username: str,
        login_html: str,
        attempted_payload: dict,
        response_status: int,
        response_body: str,
        response_headers: dict,
        diag: dict,
    ) -> Optional[dict]:
        """
        AI self-heal for form-login failures.

        Called by AuthManager after _form_login() POST returned no cookies.
        Shows the model:
          • the login page HTML (trimmed)
          • what payload we POSTed
          • what the server returned (status + body snippet + headers)
          • our own diagnostics (detected fields, CSRF tokens, etc.)

        Asks for a concrete retry plan in JSON. The model can:
          • rename fields (uname/pwd vs username/password)
          • add missing hidden fields (CAPTCHA tokens, timezone, etc.)
          • change the action URL
          • switch content type from form to JSON
          • flag "requires_human=true" if it's clearly wrong creds / MFA / CAPTCHA
            so we don't waste a retry.

        Returns:
          {
            "diagnosis":       "one-sentence explanation",
            "fix_type":        "rename_fields" | "add_fields" | "new_action" |
                               "json_body" | "none",
            "new_fields":      {"uname": "<USERNAME>", "pwd": "<PASSWORD>"},
            "extra_fields":    {"timezone": "UTC", ...},
            "new_action_url":  "https://.../login.php" or "",
            "use_json_body":   true/false,
            "confidence":      0.0-1.0,
            "requires_human":  true/false,
            "think_trace":     "..."
          }
        or None if AI disabled / the call failed / JSON malformed.
        """
        if not self.enabled:
            return None

        html_snippet = (login_html or "")[:4000]
        body_snippet = (response_body or "")[:1500]
        redacted = {k: ("***" if "pass" in k.lower() or "pwd" in k.lower() else v)
                    for k, v in (attempted_payload or {}).items()}
        hdr_snippet = {
            k: v for k, v in (response_headers or {}).items()
            if k.lower() in (
                "content-type", "set-cookie", "location", "www-authenticate",
                "x-frame-options", "server",
            )
        }

        prompt = (
            "You are BRAHMASTRA, an elite pentester. A form-login attempt "
            "just failed — the server responded but set NO session cookies. "
            "Diagnose why and propose a concrete retry.\n\n"
            f"Login URL:   {login_url}\n"
            f"Username:    {username!r}  (password redacted)\n"
            f"HTTP status: {response_status}\n"
            f"Response headers: {json.dumps(hdr_snippet)}\n\n"
            f"What we POSTed (password redacted):\n"
            f"{json.dumps(redacted, indent=2)}\n\n"
            f"Our diagnostics:\n"
            f"  detected_username_field: {diag.get('detected_username_field','')}\n"
            f"  detected_password_field: {diag.get('detected_password_field','')}\n"
            f"  csrf_fields: {diag.get('csrf_fields', [])}\n"
            f"  action_url:  {diag.get('action_url','')}\n"
            f"  final_url:   {diag.get('final_url','')}\n\n"
            f"Login page HTML (trimmed to 4KB):\n"
            f"```html\n{html_snippet}\n```\n\n"
            f"Response body (trimmed to 1.5KB):\n"
            f"```\n{body_snippet}\n```\n\n"
            "Respond with JSON in exactly this shape:\n"
            "{\n"
            '  "diagnosis":       "one short sentence explaining why login failed",\n'
            '  "fix_type":        "rename_fields" | "add_fields" | "new_action" | "json_body" | "none",\n'
            '  "new_fields":      {"<real_username_field_name>": "<USERNAME>", "<real_password_field_name>": "<PASSWORD>"},\n'
            '  "extra_fields":    {"<field>": "<value>"},\n'
            '  "new_action_url":  "",\n'
            '  "use_json_body":   false,\n'
            '  "confidence":      0.0,\n'
            '  "requires_human":  false\n'
            "}\n\n"
            "Rules:\n"
            "- Use the literal tokens <USERNAME> and <PASSWORD> as the VALUES "
            "in new_fields. BRAHMASTRA will substitute the real credentials "
            "before sending. Never echo the real username or password.\n"
            "- new_fields keys MUST be the ACTUAL HTML input names you see in "
            "the login page above (e.g. 'uname', 'pwd', 'email', 'login_id').\n"
            "- extra_fields are for values BRAHMASTRA didn't originally send "
            "(CSRF tokens we missed, timezone, remember_me=1, etc.). Only "
            "include fields that are visible in the HTML as hidden/required.\n"
            "- Set requires_human=true if the failure looks like wrong creds "
            "('invalid password' in body), CAPTCHA (reCAPTCHA / hCaptcha), MFA, "
            "or a JS-only submit — a retry will NOT fix these.\n"
            "- fix_type='none' means no actionable fix — only use with requires_human=true.\n"
            "- diagnosis must be ≤ 1 sentence."
        )

        raw = await self._call(prompt)
        if not raw:
            return None

        think_trace, clean = _extract_think(raw)
        try:
            data = json.loads(_extract_json(clean))
            if not isinstance(data, dict):
                return None
            fix_type = str(data.get("fix_type", "none")).lower()
            if fix_type not in (
                "rename_fields", "add_fields", "new_action",
                "json_body", "none",
            ):
                fix_type = "none"
            new_fields = data.get("new_fields") or {}
            if not isinstance(new_fields, dict):
                new_fields = {}
            extra_fields = data.get("extra_fields") or {}
            if not isinstance(extra_fields, dict):
                extra_fields = {}
            return {
                "diagnosis":      str(data.get("diagnosis", ""))[:300],
                "fix_type":       fix_type,
                "new_fields":     {str(k): str(v) for k, v in new_fields.items()},
                "extra_fields":   {str(k): str(v) for k, v in extra_fields.items()},
                "new_action_url": str(data.get("new_action_url", "") or ""),
                "use_json_body":  bool(data.get("use_json_body", False)),
                "confidence":     float(data.get("confidence", 0.5)),
                "requires_human": bool(data.get("requires_human", False)),
                "think_trace":    think_trace,
            }
        except Exception:
            return None

    async def extract_endpoints(
        self,
        url: str,
        html_sample: str,
        status_code: int,
        content_type: str,
    ) -> dict:
        """
        AI-driven spider's core call. Given a fetched page, ask the model
        to extract every endpoint, parameter, and form it can see in the
        HTML — AND to flag whether the response looks like a "you've been
        logged out" page so the AISpider can trigger a re-auth loop.

        This is intentionally distinct from `suggest_paths` /
        `explore_paths`:
          - `suggest_paths` / `explore_paths` are GUESSING games —
            they ask the model to invent follow-up URLs based on tech
            stack + what's been crawled so far.
          - `extract_endpoints` is a PARSING job — it pulls what's
            literally present in one HTTP response the spider just
            fetched. No invention, only extraction. Each call is bound
            to one concrete page the crawler is holding in hand.

        Returns:
            {
                "urls":       ["/path1", "/path2", ...],     # absolute or root-relative
                "parameters": [{"name": "q", "in": "query"}, ...],
                "forms":      [{"action": "/login", "method": "POST",
                                "fields": [{"name": "user", "type": "text"}, ...]}],
                "auth_lost":  bool,   # True if the AI thinks we got bounced to login
                "reasoning":  str,
            }
        Empty dict on disabled/parse failure — caller MUST handle {} safely.
        """
        if not self.enabled:
            return {}

        sample = (html_sample or "")[:4000]
        prompt = (
            "You are a pentester mapping a web application. Analyse the "
            "HTTP response below and extract every endpoint, parameter, and "
            "form a human reviewer would notice. Do NOT invent paths — only "
            "use evidence that is literally present in the response body.\n\n"
            f"Current URL:  {url}\n"
            f"Status:       {status_code}\n"
            f"Content-Type: {content_type}\n\n"
            f"Response body (first 4KB):\n```\n{sample}\n```\n\n"
            "Respond with ONLY this JSON structure — no prose around it:\n"
            "{\n"
            '  "urls": ["/new_path_1", "/new_path_2"],\n'
            '  "parameters": [{"name": "q", "in": "query"}, {"name": "id", "in": "query"}],\n'
            '  "forms": [{"action": "/login", "method": "POST", '
            '"fields": [{"name": "user", "type": "text"}, {"name": "pass", "type": "password"}]}],\n'
            '  "auth_lost": false,\n'
            '  "reasoning": "brief explanation"\n'
            "}\n\n"
            "Rules:\n"
            "  1. `urls` must be absolute or root-relative (/path or http://same-host/...); "
            "drop external domains, drop fragments (#...), drop javascript:/mailto:/tel: links.\n"
            "  2. `parameters` = query-string keys, hidden form fields, data-* attributes, "
            "JSON body keys the code is POSTing back — anything that looks tainted.\n"
            "  3. `forms` = every <form> block with action, method, and its input/select/textarea fields.\n"
            "  4. `auth_lost` = true ONLY if the response looks like a login form or a "
            "'please sign in' redirect that you would NOT expect from an authenticated user. "
            "Do NOT set this for public pages or explicit /login URLs the crawler itself asked for.\n"
            "  5. Cap at 30 urls, 20 parameters, 10 forms.\n"
            "  6. If the body is not HTML/JSON/JS (e.g. binary, empty), return empty lists."
        )

        raw = await self._call(prompt)
        if not raw:
            return {}

        _, clean = _extract_think(raw)
        try:
            data = json.loads(_extract_json(clean))
            if not isinstance(data, dict):
                return {}
            urls_raw   = data.get("urls") or []
            params_raw = data.get("parameters") or []
            forms_raw  = data.get("forms") or []
            return {
                "urls":       [str(u) for u in urls_raw if u][:30]
                              if isinstance(urls_raw, list) else [],
                "parameters": params_raw if isinstance(params_raw, list) else [],
                "forms":      forms_raw  if isinstance(forms_raw,  list) else [],
                "auth_lost":  bool(data.get("auth_lost", False)),
                "reasoning":  str(data.get("reasoning", ""))[:400],
            }
        except Exception:
            return {}

    async def chat_guide(
        self,
        scan_context: dict,
        history: list[dict],
        user_message: str,
    ) -> dict:
        """
        Per-scan chat assistant. The operator types a message telling the
        AI to probe more, pivot focus, try specific payloads, explain a
        finding, or re-authenticate; the AI responds with a conversational
        reply PLUS an optional list of structured actions the dashboard
        can render as clickable follow-ups.

        Unlike the other methods in this class (analyze_finding,
        extract_endpoints, explore_paths), this one is explicitly
        multi-turn: `history` is the full prior thread so the model
        keeps context across messages.

        Parameters:
            scan_context: {
                "target":     "https://...",
                "status":     "running" | "completed" | "failed" | ...,
                "profile":    "full" | "quick" | ...,
                "tech_stack": ["WordPress", "PHP", ...],
                "summary":    {"CRITICAL": 0, "HIGH": 3, ..., "total": 7},
                "findings":   [{"severity","type","url","parameter",
                                "evidence"}, ...]   # top ~20 findings only
                "endpoints":  ["https://.../a", ...],  # top ~15 endpoints
            }
            history: [{"role": "user"|"assistant", "content": "..."}, ...]
            user_message: the new message to respond to.

        Returns:
            {
                "reply": "...",
                "suggested_actions": [
                    {"type": "probe_url",    "url": "...", "reason": "..."},
                    {"type": "test_param",   "url": "...", "parameter": "...",
                     "payloads": ["...", "..."], "reason": "..."},
                    {"type": "run_rule",     "rule": "sqli", "reason": "..."},
                    {"type": "reauth",       "reason": "..."},
                    {"type": "focus",        "pattern": "/admin/*", "reason": "..."},
                ],
                "think_trace": "...",
            }
        Empty dict on disabled/parse failure — caller MUST handle {}.
        """
        if not self.enabled:
            return {}

        # ── Build compact scan-context block ────────────────────────────────
        target    = scan_context.get("target", "?")
        status    = scan_context.get("status", "?")
        profile   = scan_context.get("profile", "?")
        tech      = ", ".join(scan_context.get("tech_stack") or []) or "unknown"
        summary   = scan_context.get("summary") or {}
        findings  = scan_context.get("findings") or []
        endpoints = scan_context.get("endpoints") or []

        summary_str = (
            f"CRITICAL={summary.get('CRITICAL',0)}, "
            f"HIGH={summary.get('HIGH',0)}, "
            f"MEDIUM={summary.get('MEDIUM',0)}, "
            f"LOW={summary.get('LOW',0)}, "
            f"total={summary.get('total',0)}"
        )

        findings_lines = []
        for f in findings[:20]:
            sev = (f.get("severity") or "?").upper()
            vt  = f.get("type") or f.get("vuln_type") or "?"
            u   = f.get("url") or ""
            p   = f.get("parameter") or ""
            findings_lines.append(f"  - [{sev}] {vt} at {u} (param: {p or '-'})")
        findings_str = "\n".join(findings_lines) or "  (no findings yet)"

        endpoints_str = "\n".join(f"  - {u}" for u in endpoints[:15]) or "  (none)"

        # ── Serialise history as plain-text turns ───────────────────────────
        # We keep the last 16 messages to cap prompt size — older context
        # is implied via scan_context rather than replayed verbatim.
        hist_lines = []
        for h in (history or [])[-16:]:
            role = (h.get("role") or "user").upper()
            txt  = (h.get("content") or "").strip()
            if not txt:
                continue
            hist_lines.append(f"{role}: {txt}")
        hist_str = "\n".join(hist_lines) or "(no prior turns)"

        # ── Prompt ──────────────────────────────────────────────────────────
        prompt = (
            "You are BRAHMASTRA's in-scan guidance assistant. The human "
            "operator is watching a live or completed DAST scan and is "
            "using this chat to direct you to dig deeper, pivot focus, "
            "try new payloads, explain findings, or fix authentication. "
            "Be concrete and specific — reference URLs and parameters "
            "from the scan state below, not generic hypotheticals.\n\n"
            "=== SCAN CONTEXT ===\n"
            f"Target:     {target}\n"
            f"Status:     {status}\n"
            f"Profile:    {profile}\n"
            f"Tech stack: {tech}\n"
            f"Summary:    {summary_str}\n\n"
            f"Top findings:\n{findings_str}\n\n"
            f"Known endpoints (sample):\n{endpoints_str}\n\n"
            "=== CHAT HISTORY ===\n"
            f"{hist_str}\n\n"
            "=== NEW USER MESSAGE ===\n"
            f"{user_message}\n\n"
            "=== RESPONSE FORMAT ===\n"
            "Respond with ONLY this JSON (no prose outside it):\n"
            "{\n"
            '  "reply": "conversational reply — 1-6 sentences, markdown ok",\n'
            '  "suggested_actions": [\n'
            '    {"type": "probe_url",  "url": "https://target/path",     "reason": "why"},\n'
            '    {"type": "test_param", "url": "https://target/search",   "parameter": "q",\n'
            '     "payloads": ["<svg onload=1>", "\'"], "reason": "why"},\n'
            '    {"type": "run_rule",   "rule": "sqli|xss|ssrf|idor|...", "reason": "why"},\n'
            '    {"type": "reauth",     "reason": "session looks dropped on /dashboard"},\n'
            '    {"type": "focus",      "pattern": "/api/v2/*",           "reason": "most params live here"}\n'
            "  ]\n"
            "}\n\n"
            "Rules:\n"
            "  1. `reply` must be a direct answer to the user's message.\n"
            "  2. `suggested_actions` may be empty [] if nothing is actionable yet.\n"
            "  3. At most 6 actions. Each action MUST have a `type` and a `reason`.\n"
            "  4. URLs in actions must be ones you can point at in the scan context "
            "(or obvious siblings). Do NOT invent unrelated domains.\n"
            "  5. `test_param.payloads` must be a list of concrete strings (max 5).\n"
            "  6. If the user asks a question that needs no action, return reply + []."
        )

        raw = await self._call(prompt)
        if not raw:
            return {}

        think_trace, clean = _extract_think(raw)
        try:
            data = json.loads(_extract_json(clean))
            if not isinstance(data, dict):
                return {}
            reply   = str(data.get("reply") or "").strip()
            actions = data.get("suggested_actions") or []
            if not isinstance(actions, list):
                actions = []
            # Normalise + validate actions — drop malformed entries so the
            # dashboard never tries to render a button with missing fields.
            clean_actions: list[dict] = []
            for a in actions[:6]:
                if not isinstance(a, dict):
                    continue
                atype = str(a.get("type") or "").strip().lower()
                if atype not in (
                    "probe_url", "test_param", "run_rule",
                    "reauth", "focus",
                ):
                    continue
                entry = {"type": atype, "reason": str(a.get("reason") or "")[:300]}
                if atype == "probe_url":
                    entry["url"] = str(a.get("url") or "").strip()
                    if not entry["url"]:
                        continue
                elif atype == "test_param":
                    entry["url"]       = str(a.get("url") or "").strip()
                    entry["parameter"] = str(a.get("parameter") or "").strip()
                    payloads           = a.get("payloads") or []
                    if not isinstance(payloads, list):
                        payloads = []
                    entry["payloads"] = [str(p) for p in payloads if p][:5]
                    if not entry["url"] or not entry["parameter"]:
                        continue
                elif atype == "run_rule":
                    entry["rule"] = str(a.get("rule") or "").strip().lower()
                    if not entry["rule"]:
                        continue
                elif atype == "focus":
                    entry["pattern"] = str(a.get("pattern") or "").strip()
                    if not entry["pattern"]:
                        continue
                # 'reauth' needs no extra fields
                clean_actions.append(entry)
            return {
                "reply":             reply or "(no reply)",
                "suggested_actions": clean_actions,
                "think_trace":       think_trace,
            }
        except Exception:
            # Parse failure — preserve the raw text so the operator still
            # sees SOMETHING in the chat instead of a silent drop.
            return {
                "reply":             (clean or raw or "")[:1500],
                "suggested_actions": [],
                "think_trace":       think_trace,
            }

    async def self_heal_auth(
        self,
        *,
        role: str,
        url: str,
        status: int,
        response_body: str,
        previous_attempts: int,
    ) -> Optional[dict]:
        """
        Consulted by ``AISelfHealMiddleware`` when an authenticated
        request comes back looking like a login page. Returns a short
        corrective plan the middleware can apply before retrying the
        same URL once.

        Return shape::

            {"strategy":  "refresh_cookies" | "add_header" | "swap_token" |
                          "give_up",
             "header_name":  "",    # only for add_header
             "header_value": "",    # only for add_header
             "reason":       "one sentence",
             "think":        "raw <think> trace"}
        """
        if not self.enabled:
            return None

        prompt = (
            "An authenticated HTTP request just came back looking like a "
            "login bounce (the crawler has lost its session). You must "
            "suggest ONE corrective action to retry with. Options:\n"
            "  - refresh_cookies  (caller will re-run Playwright login)\n"
            "  - add_header       (caller will attach header_name=header_value)\n"
            "  - swap_token       (caller will rotate the bearer token)\n"
            "  - give_up          (don't retry; move on)\n\n"
            f"Role: {role}\n"
            f"URL: {url}\n"
            f"HTTP status: {status}\n"
            f"Previous self-heal attempts this role: {previous_attempts}\n"
            f"Response body (first 800 chars):\n{(response_body or '')[:800]}\n\n"
            "Respond with JSON ONLY:\n"
            "{\"strategy\":\"refresh_cookies|add_header|swap_token|give_up\","
            "\"header_name\":\"\",\"header_value\":\"\",\"reason\":\"why\"}"
        )

        raw = await self._call(prompt)
        if not raw:
            return None

        think_trace, clean = _extract_think(raw)
        try:
            data = json.loads(_extract_json(clean))
            strategy = str(data.get("strategy", "give_up")).strip().lower()
            if strategy not in {
                "refresh_cookies", "add_header", "swap_token", "give_up"
            }:
                strategy = "give_up"
            return {
                "strategy":     strategy,
                "header_name":  str(data.get("header_name", "") or ""),
                "header_value": str(data.get("header_value", "") or ""),
                "reason":       str(data.get("reason", "") or "")[:200],
                "think":        think_trace,
            }
        except Exception:
            return None

    # ─── Internal dispatch ────────────────────────────────────────────────────

    async def _call(self, prompt: str) -> str:
        """Dispatch to the configured AI backend."""
        try:
            if self.mode == "brahmastra":
                return await self._call_ollama(prompt, model="brahmastra:0.3", port=11434)
            elif self.mode == "brahmastra_02":
                return await self._call_ollama(prompt, model="brahmastra:0.2", port=11434)
            elif self.mode == "_unused":
                return await self._call_ollama(prompt, model="brahmastra:0.3", port=11434)
            elif self.mode == "ollama_llama33":
                return await self._call_ollama(prompt, model="llama3.3:70b-instruct-q4_0", port=11434)
            elif self.mode == "gemini_flash":
                return await self._call_gemini(prompt, model="gemini-2.5-flash")
            elif self.mode == "gemini_pro":
                return await self._call_gemini(prompt, model="gemini-2.5-pro")
            elif self.mode == "claude_haiku":
                return await self._call_claude(prompt, model="claude-haiku-4-5-20251001")
            elif self.mode == "claude_sonnet":
                return await self._call_claude(prompt, model="claude-sonnet-4-6")
            elif self.mode == "openai":
                return await self._call_openai(prompt, model="gpt-4o-mini")
        except Exception as e:
            import logging
            logging.warning(f"AIBridge._call({self.mode}): {type(e).__name__}: {e}")
            return ""
        return ""

    async def _call_ollama(self, prompt: str, model: str, port: int) -> str:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"http://localhost:{port}/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": BRAHMASTRA_SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt},
                    ],
                    "stream": False,
                },
            )
            data = resp.json()
            return data.get("message", {}).get("content", "")

    async def _call_gemini(self, prompt: str, model: str) -> str:
        if not self.api_key:
            import logging
            logging.warning("AIBridge._call_gemini: api_key is EMPTY — skipping call")
            return ""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
        async with httpx.AsyncClient(timeout=90) as client:
            resp = await client.post(url, json={
                "contents": [{"parts": [{"text": BRAHMASTRA_SYSTEM_PROMPT + "\n\n" + prompt}]}]
            })
            data = resp.json()
            return data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")

    async def _call_claude(self, prompt: str, model: str) -> str:
        if not self.api_key:
            import logging
            logging.warning("AIBridge._call_claude: api_key is EMPTY — skipping call")
            return ""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 1024,
                    "system": BRAHMASTRA_SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if resp.status_code != 200:
                import logging
                logging.warning(f"AIBridge._call_claude: HTTP {resp.status_code} — {resp.text[:300]}")
                return ""
            data = resp.json()
            return data.get("content", [{}])[0].get("text", "")

    async def _call_openai(self, prompt: str, model: str) -> str:
        if not self.api_key:
            return ""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": BRAHMASTRA_SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt},
                    ],
                    "max_tokens": 1024,
                },
            )
            data = resp.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _extract_think(text: str) -> tuple[str, str]:
    """Extract <think>...</think> from response. Returns (think_content, remainder)."""
    think = ""
    clean = text
    m = re.search(r"<think>(.*?)</think>", text, re.DOTALL)
    if m:
        think = m.group(1).strip()
        clean = text[:m.start()] + text[m.end():]
    return think, clean.strip()


def _extract_json(text: str) -> str:
    """Extract first JSON object or array from text."""
    # Try JSON code block
    m = re.search(r"```json\s*([\s\S]+?)\s*```", text)
    if m:
        return m.group(1)
    # Try first { ... } or [ ... ]
    for start_ch, end_ch in [('{', '}'), ('[', ']')]:
        start = text.find(start_ch)
        if start >= 0:
            depth = 0
            for i, ch in enumerate(text[start:], start):
                if ch == start_ch:
                    depth += 1
                elif ch == end_ch:
                    depth -= 1
                    if depth == 0:
                        return text[start:i+1]
    return text
