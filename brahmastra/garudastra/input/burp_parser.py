"""
BRAHMASTRA — Garudastra: Burp Suite Project XML Parser
Parses Burp Suite proxy history XML into ScanTargets.
Handles Base64-encoded request/response data.
"""

import base64
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

from brahmastra.sudarshana.base import ScanTarget


class BurpParser:
    """Parse Burp Suite XML export into ScanTargets."""

    async def parse(
        self,
        xml_source: str,
        auth_headers: Optional[dict] = None,
        filter_domain: Optional[str] = None,
    ) -> list[ScanTarget]:
        """
        xml_source: file path or raw XML string.
        filter_domain: only include requests to this domain.
        """
        content = _load_xml(xml_source)
        if not content:
            return []

        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return []

        targets = []
        seen    = set()

        for item in root.findall(".//item"):
            url_elem   = item.find("url")
            method_elem= item.find("method")
            req_elem   = item.find("request")

            if url_elem is None or req_elem is None:
                continue

            url    = url_elem.text or ""
            method = (method_elem.text if method_elem is not None else "GET").upper()

            # Domain filter
            if filter_domain:
                parsed = urlparse(url)
                if filter_domain not in parsed.netloc:
                    continue

            # Dedup
            key = f"{method}:{url}"
            if key in seen:
                continue
            seen.add(key)

            # Skip static
            if _is_static(url):
                continue

            # Decode request
            req_b64 = req_elem.get("base64", "false").lower() == "true"
            req_text = req_elem.text or ""
            if req_b64:
                try:
                    req_text = base64.b64decode(req_text).decode("utf-8", errors="ignore")
                except Exception:
                    req_text = ""

            # Parse HTTP request
            headers, body = _parse_http_request(req_text)
            headers.update(auth_headers or {})

            # Extract parameters
            params = _extract_params(url, body, headers)

            targets.append(ScanTarget(
                url        = url,
                method     = method,
                parameters = params,
                headers    = headers,
                body       = body if body else None,
                source     = "burp_xml",
            ))

        return targets


def _load_xml(source: str) -> Optional[str]:
    path = Path(source)
    if path.exists():
        return path.read_text(encoding="utf-8", errors="ignore")
    if source.strip().startswith("<"):
        return source
    return None


def _parse_http_request(raw: str) -> tuple[dict, Optional[str]]:
    """Parse raw HTTP request text into headers dict and body string."""
    lines = raw.replace("\r\n", "\n").split("\n")
    headers = {}
    body    = None
    in_body = False
    body_lines = []

    for i, line in enumerate(lines):
        if i == 0:
            continue  # Skip request line
        if not line.strip() and not in_body:
            in_body = True
            continue
        if in_body:
            body_lines.append(line)
        else:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()

    if body_lines:
        body = "\n".join(body_lines).strip() or None

    return headers, body


def _extract_params(url: str, body: Optional[str], headers: dict) -> list[dict]:
    """Extract parameters from URL query string and request body."""
    params = []
    parsed = urlparse(url)

    # Query params
    for name in parse_qs(parsed.query, keep_blank_values=True):
        params.append({"name": name, "location": "query", "type": "string"})

    # Body params
    content_type = headers.get("Content-Type", "").lower()
    if body:
        if "json" in content_type:
            try:
                import json
                data = json.loads(body)
                if isinstance(data, dict):
                    for k in data:
                        params.append({"name": k, "location": "json", "type": "string"})
            except Exception:
                pass
        elif "urlencoded" in content_type or "form" in content_type:
            for name in parse_qs(body, keep_blank_values=True):
                params.append({"name": name, "location": "body", "type": "string"})

    return params


def _is_static(url: str) -> bool:
    static_exts = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot", ".map",
    )
    return any(url.lower().split("?")[0].endswith(ext) for ext in static_exts)
