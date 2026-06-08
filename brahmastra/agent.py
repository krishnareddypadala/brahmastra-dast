"""
BRAHMASTRA — AI Agent Loop
The brain of the scanner. Manages conversation with the BRAHMASTRA model,
parses tool calls, executes them, feeds results back, and loops until done.

Supports both Ollama and llama.cpp server backends.
"""

import json
import re
import asyncio
from typing import Optional
from dataclasses import dataclass, field

import httpx

from brahmastra.tools import ToolRegistry
from brahmastra.sudarshana.base import Finding, ScanResult


SYSTEM_PROMPT = """You are BRAHMASTRA, an elite AI-powered DAST security scanner.
Like the divine weapon of the Puranas, you strike with precision and never miss your mark.
Use <think>...</think> to reason step by step before each action.
When a WAF is detected, deploy Kavachabhedana — the armor-piercing WAF bypass engine.

Available tool calls:
- send_request(method, url, headers={}, body=None, timeout=10)
- inject_payload(url, parameter, payload, method="GET", headers={}, location="query")
- report_finding(severity, type, url, parameter, evidence, cvss, remediation, waf_bypassed=False, bypass_method=None)
- mark_clean(url, parameter, reason)
- log_info(message)
- crawl_done()

MANDATORY RULES — YOU MUST FOLLOW THESE:
1. ALWAYS call inject_payload() or send_request() FIRST to test a parameter.
2. NEVER call report_finding() without first calling inject_payload() and seeing the HTTP response.
3. NEVER call report_finding(severity="NONE") — that is not a valid severity.
4. Valid severities for report_finding: CRITICAL, HIGH, MEDIUM, LOW, INFO only.
5. If a parameter shows no vulnerability after testing, call mark_clean(url, parameter, reason).
6. You MUST test EVERY parameter in the target list before calling crawl_done().
7. For each parameter, inject at least 2-3 payloads and check the HTTP response evidence.
8. Only call report_finding() when you have CONFIRMED evidence from an HTTP response.

WORKFLOW FOR EACH PARAMETER:
Step 1: Call inject_payload() with a test payload
Step 2: Examine the tool result (HTTP response)
Step 3: If evidence of vulnerability found → call report_finding()
Step 4: If no vulnerability → call mark_clean()

Response format:
<think>
[Your reasoning here]
</think>
inject_payload("url", "param", "payload", method="GET")
"""


@dataclass
class AgentConfig:
    model_url: str       = "http://localhost:11434/api/chat"  # Ollama default
    model_name: str      = "brahmastra"
    max_turns: int       = 50
    temperature: float   = 0.1      # Low temp — scanner, not creative writer
    timeout: float       = 30.0     # Per model call
    max_tool_retries: int = 3


class BrahmastraAgent:
    """
    The BRAHMASTRA AI Agent.
    Orchestrates model → tool_call → execution → loop until done.
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config   = config or AgentConfig()
        self.tools    = ToolRegistry()
        self.messages: list[dict] = []
        self.findings: list[Finding] = []

    def reset(self):
        self.messages = []
        self.findings = []

    async def scan(
        self,
        targets: list[dict],  # [{"url": ..., "method": ..., "params": [...]}]
        scan_context: str = "",
    ) -> ScanResult:
        """
        Main scan entry point.
        targets: list of endpoints to test.
        Returns a ScanResult with all findings.
        """
        self.reset()

        # Build initial user message
        target_json = json.dumps(targets, indent=2)
        initial_msg = f"""Begin BRAHMASTRA scan.

{scan_context}

Targets:
{target_json}

For each target, test all parameters for vulnerabilities.
Use <think> to reason before each action.
Call crawl_done() when all targets have been tested.
"""
        self.messages = [
            {"role": "system",  "content": SYSTEM_PROMPT},
            {"role": "user",    "content": initial_msg},
        ]

        turn = 0
        done = False

        while turn < self.config.max_turns and not done:
            turn += 1

            # Call the model
            response_text = await self._call_model()
            if response_text is None:
                break

            # Add assistant response to history
            self.messages.append({"role": "assistant", "content": response_text})

            # Parse tool calls from response
            tool_calls = self._parse_tool_calls(response_text)

            if not tool_calls:
                # Model gave a plain text response — ask it to continue
                self.messages.append({
                    "role": "user",
                    "content": "Continue scanning. Use tool calls to test vulnerabilities."
                })
                continue

            # Execute each tool call
            tool_results = []
            for call in tool_calls:
                fn_name, fn_args = call
                result = await self._execute_tool(fn_name, fn_args)
                tool_results.append(f"{fn_name}: {result}")

                # Check special results
                if fn_name == "report_finding":
                    finding = self.tools.last_finding
                    if finding and finding.severity not in ("NONE", "NO_VULN", "none", "", None):
                        self.findings.append(finding)

                if fn_name == "crawl_done":
                    done = True
                    break

            if not done:
                # Feed tool results back
                tool_result_text = "\n".join(tool_results)
                self.messages.append({
                    "role": "tool",
                    "content": tool_result_text,
                })

        return ScanResult(findings=self.findings, agent_turns=turn)

    async def _call_model(self) -> Optional[str]:
        """Call the BRAHMASTRA model via Ollama API."""
        payload = {
            "model":    self.config.model_name,
            "messages": self.messages,
            "stream":   False,
            "options":  {
                "temperature": self.config.temperature,
                "num_predict": 2048,
            },
        }
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.post(self.config.model_url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data["message"]["content"]
        except Exception as e:
            print(f"[Agent] Model call failed: {e}")
            return None

    def _parse_tool_calls(self, text: str) -> list[tuple]:
        """
        Extract tool calls from model response.
        Handles two formats:
          1. <tool_call>function_name(args)</tool_call>
          2. Bare: inject_payload(...) / send_request(...) etc.
        Returns list of (function_name, parsed_args) tuples.
        """
        # Format 1: explicit XML tags
        pattern = r"<tool_call>(.*?)</tool_call>"
        matches = re.findall(pattern, text, re.DOTALL)

        # Format 2: bare function calls (model output style)
        if not matches:
            KNOWN_FNS = [
                "inject_payload", "send_request", "report_finding",
                "mark_clean", "log_info", "crawl_done",
            ]
            for fn in KNOWN_FNS:
                # Match fn_name(args) — allow multi-line args
                bare = re.findall(rf"{fn}\([^)]*\)", text, re.DOTALL)
                matches.extend(bare)

        calls = []
        for match in matches:
            match = match.strip()
            # Parse: function_name(arg1, key=value, ...)
            fn_match = re.match(r"(\w+)\((.*)\)$", match, re.DOTALL)
            if not fn_match:
                continue
            fn_name = fn_match.group(1)
            args_str = fn_match.group(2).strip()
            parsed = self._parse_args(fn_name, args_str)
            calls.append((fn_name, parsed))

        return calls

    def _parse_args(self, fn_name: str, args_str: str) -> dict:
        """
        Parse argument string into a dict.
        Handles: "url, method='POST', headers={...}, body='...'"
        Uses a safe eval approach with positional → keyword mapping.
        """
        if not args_str:
            return {}
        try:
            # Try JSON-like parse first
            # Wrap in braces to parse as dict
            parsed = {}

            # Split on commas that are not inside brackets/quotes
            # Use a simple state machine
            args = _split_args(args_str)

            # Map positional args based on known function signatures
            SIGNATURES = {
                "send_request":    ["method", "url", "headers", "body", "timeout"],
                "inject_payload":  ["url", "parameter", "payload", "method", "headers", "location"],
                "report_finding":  ["severity", "type", "url", "parameter", "evidence", "cvss", "remediation"],
                "mark_clean":      ["url", "parameter", "reason"],
                "log_info":        ["message"],
            }
            positional_names = SIGNATURES.get(fn_name, [])
            pos_idx = 0

            for arg in args:
                arg = arg.strip()
                if not arg:
                    continue
                if "=" in arg:
                    # keyword arg — only if the key before = is a valid identifier
                    eq_pos = arg.index("=")
                    key = arg[:eq_pos].strip()
                    if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", key):
                        val = arg[eq_pos+1:].strip()
                        parsed[key] = _parse_value(val)
                    else:
                        # = is inside the value (e.g. SQL payload), treat as positional
                        if pos_idx < len(positional_names):
                            parsed[positional_names[pos_idx]] = _parse_value(arg)
                        pos_idx += 1
                        continue
                else:
                    # positional arg
                    if pos_idx < len(positional_names):
                        parsed[positional_names[pos_idx]] = _parse_value(arg)
                    pos_idx += 1

            return parsed
        except Exception:
            return {"_raw": args_str}

    async def _execute_tool(self, fn_name: str, args: dict) -> str:
        """Execute a tool and return result as string."""
        try:
            return await self.tools.execute(fn_name, args)
        except Exception as e:
            return f"ERROR: {e}"


# ─── Argument parsing helpers ─────────────────────────────────────────────────

def _split_args(s: str) -> list[str]:
    """Split argument string by commas, respecting brackets and quotes."""
    args   = []
    depth  = 0
    in_sq  = False   # in single quote
    in_dq  = False   # in double quote
    buf    = ""

    for ch in s:
        if ch == "'" and not in_dq:
            in_sq = not in_sq
            buf += ch
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
            buf += ch
        elif ch in "([{" and not in_sq and not in_dq:
            depth += 1
            buf += ch
        elif ch in ")]}" and not in_sq and not in_dq:
            depth -= 1
            buf += ch
        elif ch == "," and depth == 0 and not in_sq and not in_dq:
            args.append(buf)
            buf = ""
        else:
            buf += ch

    if buf.strip():
        args.append(buf)
    return args


def _parse_value(s: str):
    """Parse a single argument value: string, int, float, bool, dict, list, None."""
    s = s.strip()
    if s in ("True", "true"):  return True
    if s in ("False", "false"): return False
    if s in ("None", "null", ""):  return None
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    # Try JSON decode (for dicts/lists)
    try:
        return json.loads(s)
    except Exception:
        pass
    return s  # Return as-is
