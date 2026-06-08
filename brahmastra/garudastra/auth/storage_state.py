"""
BRAHMASTRA — Playwright ``storage_state`` helpers.

Playwright persists the browser context (cookies + localStorage +
sessionStorage) as a JSON file. The legacy httpx crawler and the
:class:`AuthManager` consume those cookies as a flat ``{name: value}``
dict suitable for ``httpx.AsyncClient(cookies=...)``. This module is
the single place we do that conversion so every caller sees the same
cookies from a given login.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_state(path: str) -> dict:
    """Load a Playwright ``storage_state.json`` file from disk."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def state_to_httpx_cookies(state: dict) -> dict[str, str]:
    """
    Convert a Playwright state dict into a plain ``{name: value}``
    dict suitable for ``httpx.AsyncClient(cookies=...)``. We drop
    the domain/path/secure metadata because httpx only needs the
    flat name/value pairs for the legacy crawler's single-target
    request pattern.
    """
    raw_cookies = state.get("cookies") if isinstance(state, dict) else None
    if not isinstance(raw_cookies, list):
        return {}
    out: dict[str, str] = {}
    for c in raw_cookies:
        if not isinstance(c, dict):
            continue
        name = c.get("name") or ""
        value = c.get("value") or ""
        if not name:
            continue
        out[str(name)] = str(value)
    return out


def ensure_state_dir(path: str) -> Path:
    """
    Ensure a state directory exists with mode 0700 (owner-only).
    Returns the resolved :class:`Path`.
    """
    p = Path(path).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    try:
        import os
        os.chmod(str(p), 0o700)
    except Exception:
        pass
    return p
