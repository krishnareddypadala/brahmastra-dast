"""
BRAHMASTRA — Garudastra: OpenAPI 3.x / Swagger 2.0 Parser
Parses OpenAPI spec and extracts all endpoints, parameters, request bodies.
Returns ScanTarget list ready for the agent to test.

Handles:
  - OpenAPI 3.x (YAML + JSON)
  - Swagger 2.0 (YAML + JSON)
  - Path parameters: /users/{id}
  - Query parameters
  - Request body (JSON schema)
  - Security schemes detection
"""

import json
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

from brahmastra.sudarshana.base import ScanTarget


class OpenAPIParser:
    """Parse OpenAPI 3.x or Swagger 2.0 spec into ScanTargets."""

    async def parse(
        self,
        spec_source: str,
        base_url: Optional[str] = None,
        auth_headers: Optional[dict] = None,
    ) -> list[ScanTarget]:
        """
        spec_source: file path or URL to OpenAPI spec.
        base_url: override the server URL (e.g. https://staging.example.com).
        auth_headers: auth headers to attach to all targets.
        """
        # Load spec
        spec = await _load_spec(spec_source)
        if not spec:
            return []

        # Detect version
        version = str(spec.get("openapi", spec.get("swagger", ""))).split(".")[0]

        if version == "3":
            return self._parse_openapi3(spec, base_url, auth_headers or {})
        elif version == "2":
            return self._parse_swagger2(spec, base_url, auth_headers or {})
        else:
            return []

    def _parse_openapi3(self, spec: dict, base_url: Optional[str], auth_headers: dict) -> list[ScanTarget]:
        targets = []

        # Resolve base URL from servers
        if not base_url:
            servers = spec.get("servers", [{}])
            base_url = servers[0].get("url", "") if servers else ""

        paths = spec.get("paths", {})
        components = spec.get("components", {})
        schemas = components.get("schemas", {})

        for path, path_item in paths.items():
            full_url = base_url.rstrip("/") + path

            for method, operation in path_item.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                    continue
                if not isinstance(operation, dict):
                    continue

                params = []

                # Path parameters
                for param in operation.get("parameters", []) + path_item.get("parameters", []):
                    if isinstance(param, dict):
                        params.append({
                            "name":     param.get("name", ""),
                            "location": param.get("in", "query"),
                            "type":     _extract_param_type(param.get("schema", {})),
                            "required": param.get("required", False),
                        })

                # Request body
                body_schema = None
                req_body = operation.get("requestBody", {})
                if req_body:
                    content = req_body.get("content", {})
                    json_content = content.get("application/json", content.get("*/*", {}))
                    schema = json_content.get("schema", {})
                    # Resolve $ref
                    if "$ref" in schema:
                        ref = schema["$ref"].split("/")[-1]
                        schema = schemas.get(ref, {})
                    # Extract properties as parameters
                    for prop_name, prop_schema in schema.get("properties", {}).items():
                        params.append({
                            "name":     prop_name,
                            "location": "json",
                            "type":     prop_schema.get("type", "string"),
                            "required": prop_name in schema.get("required", []),
                        })
                    body_schema = schema

                # Replace path params with test values
                test_url = _fill_path_params(full_url, params)

                targets.append(ScanTarget(
                    url        = test_url,
                    method     = method.upper(),
                    parameters = params,
                    headers    = {"Content-Type": "application/json", **auth_headers},
                    source     = "openapi3",
                ))

        return targets

    def _parse_swagger2(self, spec: dict, base_url: Optional[str], auth_headers: dict) -> list[ScanTarget]:
        targets = []

        if not base_url:
            host    = spec.get("host", "localhost")
            schemes = spec.get("schemes", ["https"])
            basePath= spec.get("basePath", "")
            base_url = f"{schemes[0]}://{host}{basePath}"

        paths = spec.get("paths", {})
        definitions = spec.get("definitions", {})

        for path, path_item in paths.items():
            full_url = base_url.rstrip("/") + path

            for method, operation in path_item.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue
                if not isinstance(operation, dict):
                    continue

                params = []
                for param in operation.get("parameters", []):
                    if isinstance(param, dict):
                        location = param.get("in", "query")
                        if location == "body":
                            # Swagger 2 body param — extract schema fields
                            schema = param.get("schema", {})
                            if "$ref" in schema:
                                ref = schema["$ref"].split("/")[-1]
                                schema = definitions.get(ref, {})
                            for prop_name, prop_schema in schema.get("properties", {}).items():
                                params.append({
                                    "name":     prop_name,
                                    "location": "json",
                                    "type":     prop_schema.get("type", "string"),
                                    "required": prop_name in schema.get("required", []),
                                })
                        else:
                            params.append({
                                "name":     param.get("name", ""),
                                "location": location,
                                "type":     param.get("type", "string"),
                                "required": param.get("required", False),
                            })

                test_url = _fill_path_params(full_url, params)

                targets.append(ScanTarget(
                    url        = test_url,
                    method     = method.upper(),
                    parameters = params,
                    headers    = {"Content-Type": "application/json", **auth_headers},
                    source     = "swagger2",
                ))

        return targets


# ─── Helpers ────────────────────────────────────────────────────────────────

async def _load_spec(source: str) -> Optional[dict]:
    """Load spec from file path or URL."""
    import yaml

    # File
    path = Path(source)
    if path.exists():
        content = path.read_text(encoding="utf-8")
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return yaml.safe_load(content)

    # URL
    if source.startswith(("http://", "https://")):
        import httpx
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                resp = await client.get(source)
                content = resp.text
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    return yaml.safe_load(content)
        except Exception:
            return None

    # Raw content
    try:
        return json.loads(source)
    except json.JSONDecodeError:
        try:
            import yaml
            return yaml.safe_load(source)
        except Exception:
            return None


def _extract_param_type(schema: dict) -> str:
    if not schema:
        return "string"
    t = schema.get("type", "string")
    fmt = schema.get("format", "")
    if fmt:
        return f"{t}({fmt})"
    return t


def _fill_path_params(url: str, params: list[dict]) -> str:
    """Replace {param} in URL with test values."""
    import re
    path_params = {p["name"]: p for p in params if p.get("location") == "path"}

    def replace(match):
        name = match.group(1)
        p = path_params.get(name, {})
        typ = p.get("type", "string")
        if "integer" in typ or "number" in typ:
            return "1"
        return "test"

    return re.sub(r"\{([^}]+)\}", replace, url)
