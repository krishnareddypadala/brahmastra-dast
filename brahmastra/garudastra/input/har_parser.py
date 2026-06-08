"""
BRAHMASTRA — Garudastra: HAR File Parser
Parses HTTP Archive (HAR) files from browser devtools or Burp.
Replays and fuzzes all captured requests.
"""

import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from typing import Optional

from brahmastra.sudarshana.base import ScanTarget


class HARParser:
    """Parse HAR file into ScanTargets."""

    async def parse(
        self,
        har_source: str,
        auth_headers: Optional[dict] = None,
        filter_domain: Optional[str] = None,
    ) -> list[ScanTarget]:
        """
        har_source: file path or raw JSON string.
        filter_domain: if set, only include requests to this domain.
        """
        data = _load_har(har_source)
        if not data:
            return []

        entries = data.get("log", {}).get("entries", [])
        targets = []
        seen    = set()

        for entry in entries:
            req  = entry.get("request", {})
            url  = req.get("url", "")
            method = req.get("method", "GET").upper()

            if not url:
                continue

            # Domain filter
            if filter_domain:
                parsed = urlparse(url)
                if filter_domain not in parsed.netloc:
                    continue

            # Skip static assets
            if _is_static(url):
                continue

            # Dedup by method+url
            key = f"{method}:{url}"
            if key in seen:
                continue
            seen.add(key)

            # Extract headers
            headers = {h["name"]: h["value"] for h in req.get("headers", [])
                       if not h["name"].startswith(":")}  # Skip HTTP/2 pseudo-headers
            headers.update(auth_headers or {})

            # Extract query params
            params = []
            qs = req.get("queryString", [])
            for q in qs:
                params.append({
                    "name":     q.get("name", ""),
                    "location": "query",
                    "type":     "string",
                })

            # Extract POST body params
            post_data = req.get("postData", {})
            if post_data:
                mime = post_data.get("mimeType", "")
                if "json" in mime:
                    try:
                        body_json = json.loads(post_data.get("text", "{}"))
                        for key_name in (body_json if isinstance(body_json, dict) else {}).keys():
                            params.append({"name": key_name, "location": "json", "type": "string"})
                    except json.JSONDecodeError:
                        pass
                elif "form" in mime or "urlencoded" in mime:
                    for param in post_data.get("params", []):
                        params.append({
                            "name":     param.get("name", ""),
                            "location": "body",
                            "type":     "string",
                        })

            targets.append(ScanTarget(
                url        = url,
                method     = method,
                parameters = params,
                headers    = headers,
                source     = "har",
            ))

        return targets


def _load_har(source: str) -> Optional[dict]:
    path = Path(source)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    try:
        return json.loads(source)
    except json.JSONDecodeError:
        return None


def _is_static(url: str) -> bool:
    static_exts = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".min.js", ".min.css",
    )
    return any(url.lower().split("?")[0].endswith(ext) for ext in static_exts)
