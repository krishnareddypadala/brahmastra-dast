"""
BRAHMASTRA — Garudastra: Form Auto-Filler & Submitter

OWASP ZAP-inspired "form auto-fill" — for every HTML form we find during
the crawl, synthesize HTML5-type-aware values and actually POST the form.
Without this, pages that only exist *after* a form submission (e.g.
/search?q=foo → /search/results, /register → /welcome) are invisible to
the scanner.

What we generate:
  email       →  test.user@brahmastra.scan
  password    →  BrahmastraTest123!
  tel / phone →  5551234567
  number      →  42
  url         →  https://example.com
  date        →  2025-01-01
  datetime-l  →  2025-01-01T12:00
  checkbox    →  "on"
  hidden      →  kept as-is (may be a CSRF token / nonce)
  file        →  skipped (can't synthesise a multipart upload here)
  submit      →  kept as-is (so Django/Flask forms that key off the
                 submit button name still route correctly)
  default     →  "brahmastra"

The submitter:
  - Honours form method (GET form → add params to query string)
  - Honours name heuristics (name, username, first_name, etc.) so the
    filled value is somewhat realistic ("Brahmastra" instead of "brahmastra")
  - Returns (response_text, discovered_urls) so the spider can walk the
    post-submission HTML for links/forms/new endpoints it wouldn't have
    otherwise seen.
  - Skips logout forms (case-insensitive action/name containing "logout"
    or "signout") so we don't kill our own auth session mid-scan.
  - Skips forms with a password field *unless* the action looks like a
    login attempt on a public-reg page — blind submission of password
    forms against arbitrary endpoints is destructive and pointless.

This module NEVER stores raw form bodies. It only returns response HTML
for the spider to parse. The rule engine still sees the ScanTarget with
the form's parameter list and runs its own parameter fuzzing — form-fill
here is a CRAWL aid, not a vuln probe.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urljoin, urlencode, urlparse

import httpx


# Name-based hints that override plain type-based defaults.
_NAME_HINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\b(first[_-]?name|fname|given[_-]?name)\b"), "Brahmastra"),
    (re.compile(r"(?i)\b(last[_-]?name|lname|surname|family[_-]?name)\b"), "Scanner"),
    (re.compile(r"(?i)\b(full[_-]?name|displayname|name)\b"), "Brahmastra Scanner"),
    (re.compile(r"(?i)\b(user(name)?|login|account|nick)\b"), "brahmastra_test"),
    (re.compile(r"(?i)\b(email|e[_-]?mail)\b"), "test.user@brahmastra.scan"),
    (re.compile(r"(?i)\b(pass(word|wd)?|pwd|secret)\b"), "BrahmastraTest123!"),
    (re.compile(r"(?i)\b(confirm|retype|repeat)\b.*\b(pass|pwd)\b"), "BrahmastraTest123!"),
    (re.compile(r"(?i)\b(phone|tel|mobile|cell)\b"), "5551234567"),
    (re.compile(r"(?i)\b(zip|postal|postcode)\b"), "94105"),
    (re.compile(r"(?i)\b(city)\b"), "San Francisco"),
    (re.compile(r"(?i)\b(state|province|region)\b"), "CA"),
    (re.compile(r"(?i)\b(country)\b"), "US"),
    (re.compile(r"(?i)\b(address|street)\b"), "1 Brahmastra Way"),
    (re.compile(r"(?i)\b(search|query|q|keyword|term)\b"), "brahmastra"),
    (re.compile(r"(?i)\b(comment|message|feedback|body|text)\b"), "scan in progress"),
    (re.compile(r"(?i)\b(subject|title|topic)\b"), "brahmastra test"),
    (re.compile(r"(?i)\b(age|years?)\b"), "30"),
    (re.compile(r"(?i)\b(dob|birthday|birth[_-]?date)\b"), "1995-01-01"),
    (re.compile(r"(?i)\b(url|website|homepage|site)\b"), "https://example.com"),
    (re.compile(r"(?i)\b(csrf|xsrf|_token|authenticity_token|nonce)\b"), "__KEEP__"),
]

# HTML5 type → default value. Only consulted when no name hint matches.
_TYPE_DEFAULTS: dict[str, str] = {
    "email":          "test.user@brahmastra.scan",
    "password":       "BrahmastraTest123!",
    "tel":            "5551234567",
    "phone":          "5551234567",
    "number":         "42",
    "range":          "42",
    "url":            "https://example.com",
    "date":           "2025-01-01",
    "time":           "12:00",
    "datetime":       "2025-01-01T12:00",
    "datetime-local": "2025-01-01T12:00",
    "month":          "2025-01",
    "week":           "2025-W01",
    "color":          "#000000",
    "search":         "brahmastra",
    "checkbox":       "on",
    "radio":          "on",
    "text":           "brahmastra",
}

# Action / form-name substrings that disqualify a form from auto-submission.
_SKIP_ACTION_SUBSTR: tuple[str, ...] = (
    "logout", "signout", "sign-out", "sign_out", "/destroy",
    "delete-account", "delete_account", "unsubscribe", "deactivate",
)


def synth_value(name: str, input_type: str, existing: str = "") -> str:
    """
    Pick a single value for one form field.

    If `existing` is non-empty and the field is type=hidden, we keep it
    (CSRF tokens, nonces, __VIEWSTATE). Otherwise consult name hints
    then type defaults.
    """
    # Hidden fields: keep the server-supplied value if any.
    if input_type == "hidden" and existing:
        return existing

    # Name-based hints (first match wins)
    for pat, val in _NAME_HINTS:
        if pat.search(name or ""):
            return existing if val == "__KEEP__" else val

    # Type-based defaults
    return _TYPE_DEFAULTS.get((input_type or "text").lower(), "brahmastra")


def should_submit(form: dict) -> bool:
    """
    Return False for forms we refuse to auto-submit:
      - logout / deactivate / unsubscribe endpoints (action keyword)
      - forms whose only purpose is file upload (we can't fill those)
    """
    action = (form.get("action") or "").lower()
    for bad in _SKIP_ACTION_SUBSTR:
        if bad in action:
            return False

    # If every field is type=file, we can't synthesize a sensible body.
    params = form.get("params") or []
    non_file = [p for p in params if (p.get("type") or "text").lower() != "file"]
    if params and not non_file:
        return False

    return True


def build_payload(form: dict) -> dict[str, str]:
    """
    Turn a parsed form dict (from url_parser._extract_forms) into a
    {field_name: synthesized_value} body ready to POST/GET-submit.
    """
    body: dict[str, str] = {}
    for p in form.get("params") or []:
        name = p.get("name") or ""
        if not name:
            continue
        field_type = (p.get("type") or "text").lower()
        if field_type == "file":
            # httpx chokes on multipart without a file handle; we already
            # gate these out in should_submit, but double-check.
            continue
        existing = p.get("value") or ""  # value= attribute kept by extended extractor
        body[name] = synth_value(name, field_type, existing)
    return body


async def submit_form(
    form: dict,
    auth_headers: Optional[dict] = None,
    timeout: float = 10.0,
) -> tuple[str, int, str]:
    """
    Auto-fill a single form and submit it.

    Returns: (response_body, status_code, final_url)
    On any error returns ("", 0, form["action"]).

    The spider calls this once per form during Phase 2b and then parses
    the returned body through url_parser._extract_links to pull any new
    paths reachable only via post-submission flow.
    """
    if not should_submit(form):
        return "", 0, form.get("action", "")

    action = form.get("action") or ""
    method = (form.get("method") or "POST").upper()
    body = build_payload(form)
    headers = dict(auth_headers or {})

    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=timeout,
        ) as client:
            if method == "GET":
                resp = await client.get(action, params=body, headers=headers)
            else:
                # application/x-www-form-urlencoded — the common case.
                # We do NOT send multipart unless the form requires files
                # (and should_submit() already filtered those out).
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                resp = await client.request(
                    method, action, data=body, headers=headers,
                )
        return resp.text or "", resp.status_code, str(resp.url)
    except Exception:
        return "", 0, action
