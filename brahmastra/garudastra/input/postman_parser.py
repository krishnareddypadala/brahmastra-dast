"""
BRAHMASTRA — Garudastra: Postman Collection Parser
Parses Postman Collection v2.0 and v2.1 into ScanTargets.
Handles folders, pre-request scripts (for variable extraction), and auth.
"""

import json
from pathlib import Path
from typing import Optional
import re

from brahmastra.sudarshana.base import ScanTarget


class PostmanParser:
    """Parse Postman Collection into ScanTargets."""

    async def parse(
        self,
        collection_source: str,
        base_url_override: Optional[str] = None,
        auth_headers: Optional[dict] = None,
        variables: Optional[dict] = None,
    ) -> list[ScanTarget]:
        """
        collection_source: file path or raw JSON string.
        variables: override Postman variables {{var}} in URLs.
        """
        data = _load_collection(collection_source)
        if not data:
            return []

        self.variables = variables or {}
        self.auth_headers = auth_headers or {}

        # Extract collection-level variables
        for v in data.get("variable", []):
            self.variables.setdefault(v.get("key", ""), v.get("value", ""))

        targets = []
        items = data.get("item", [])
        self._extract_items(items, targets)
        return targets

    def _extract_items(self, items: list, targets: list):
        """Recursively extract requests from items (folders + requests)."""
        for item in items:
            if "item" in item:
                # Folder — recurse
                self._extract_items(item["item"], targets)
            elif "request" in item:
                target = self._parse_request(item["request"])
                if target:
                    targets.append(target)

    def _parse_request(self, req: dict) -> Optional[ScanTarget]:
        if not isinstance(req, dict):
            return None

        # URL
        url_obj = req.get("url", {})
        if isinstance(url_obj, str):
            url = url_obj
        else:
            url = url_obj.get("raw", "")

        # Resolve Postman variables {{var}}
        url = self._resolve_vars(url)

        if not url or not url.startswith("http"):
            return None

        method = str(req.get("method", "GET")).upper()

        # Headers
        headers = {}
        for h in req.get("header", []):
            if isinstance(h, dict) and not h.get("disabled"):
                headers[h.get("key", "")] = self._resolve_vars(str(h.get("value", "")))
        headers.update(self.auth_headers)

        # Query params (from URL object)
        params = []
        if isinstance(url_obj, dict):
            for q in url_obj.get("query", []):
                if isinstance(q, dict) and not q.get("disabled"):
                    params.append({
                        "name":     q.get("key", ""),
                        "location": "query",
                        "type":     "string",
                    })

        # Body
        body = req.get("body", {})
        body_str = None
        if isinstance(body, dict) and body.get("mode"):
            mode = body["mode"]
            if mode == "raw":
                raw = self._resolve_vars(body.get("raw", ""))
                body_str = raw
                # Extract JSON body params
                if body.get("options", {}).get("raw", {}).get("language") == "json":
                    try:
                        body_json = json.loads(raw)
                        if isinstance(body_json, dict):
                            for k in body_json:
                                params.append({"name": k, "location": "json", "type": "string"})
                    except json.JSONDecodeError:
                        pass
            elif mode == "urlencoded":
                for p in body.get("urlencoded", []):
                    if isinstance(p, dict) and not p.get("disabled"):
                        params.append({"name": p.get("key", ""), "location": "body", "type": "string"})
            elif mode == "formdata":
                for p in body.get("formdata", []):
                    if isinstance(p, dict) and not p.get("disabled") and p.get("type") != "file":
                        params.append({"name": p.get("key", ""), "location": "body", "type": "string"})

        return ScanTarget(
            url        = url,
            method     = method,
            parameters = params,
            headers    = headers,
            body       = body_str,
            source     = "postman",
        )

    def _resolve_vars(self, s: str) -> str:
        """Replace {{variable}} with known values or test defaults."""
        def replace(m):
            key = m.group(1).strip()
            return self.variables.get(key, f"test_{key}")
        return re.sub(r"\{\{([^}]+)\}\}", replace, s)


def _load_collection(source: str) -> Optional[dict]:
    path = Path(source)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    try:
        return json.loads(source)
    except json.JSONDecodeError:
        return None
