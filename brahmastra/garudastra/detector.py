"""
BRAHMASTRA — Garudastra: Input Format Detector
Auto-detects the input type and routes to the appropriate parser.

Supported formats:
  1. URL           — starts with http:// or https://
  2. OpenAPI 3.x   — YAML/JSON with "openapi: 3" key
  3. Swagger 2.0   — YAML/JSON with "swagger: 2" key
  4. Postman       — JSON with "info.schema" containing postman
  5. GraphQL SDL   — .graphql file or starts with "type Query"
  6. HAR           — JSON with "log.version" key
  7. Burp XML      — XML with <items> root
  8. gRPC proto    — .proto file
"""

import json
from pathlib import Path
from enum import Enum


class InputFormat(Enum):
    URL       = "url"
    OPENAPI3  = "openapi3"
    SWAGGER2  = "swagger2"
    POSTMAN   = "postman"
    GRAPHQL   = "graphql"
    HAR       = "har"
    BURP_XML  = "burp_xml"
    GRPC      = "grpc"
    UNKNOWN   = "unknown"


class InputDetector:
    """
    Detect the format of the scan target input.
    Returns InputFormat enum + the appropriate parser class.
    """

    @staticmethod
    def detect(input_str: str) -> InputFormat:
        """
        Detect format from a string (URL, file path, or raw content).
        """
        input_str = input_str.strip()

        # URL — starts with scheme
        if input_str.startswith(("http://", "https://", "ws://", "wss://")):
            return InputFormat.URL

        # File path — check extension
        path = Path(input_str)
        if path.exists():
            return InputDetector._detect_file(path)

        # Raw content detection
        return InputDetector._detect_content(input_str)

    @staticmethod
    def _detect_file(path: Path) -> InputFormat:
        suffix = path.suffix.lower()

        if suffix in (".graphql", ".gql"):
            return InputFormat.GRAPHQL
        if suffix == ".proto":
            return InputFormat.GRPC
        if suffix == ".xml":
            # Could be Burp XML
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")[:1000]
                if "<items " in content or "<items>" in content:
                    return InputFormat.BURP_XML
            except Exception:
                pass
            return InputFormat.UNKNOWN
        if suffix in (".yaml", ".yml", ".json"):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                return InputDetector._detect_content(content)
            except Exception:
                return InputFormat.UNKNOWN

        # Try reading and detecting content
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            return InputDetector._detect_content(content)
        except Exception:
            return InputFormat.UNKNOWN

    @staticmethod
    def _detect_content(content: str) -> InputFormat:
        # Try JSON/YAML parsing
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Try YAML
            try:
                import yaml
                data = yaml.safe_load(content)
            except Exception:
                data = None

        if isinstance(data, dict):
            # OpenAPI 3.x
            if "openapi" in data and str(data["openapi"]).startswith("3"):
                return InputFormat.OPENAPI3
            # Swagger 2.0
            if "swagger" in data and str(data["swagger"]).startswith("2"):
                return InputFormat.SWAGGER2
            # Postman Collection
            if "info" in data and isinstance(data["info"], dict):
                schema = data["info"].get("schema", "")
                if "postman" in str(schema).lower():
                    return InputFormat.POSTMAN
            # HAR
            if "log" in data and isinstance(data["log"], dict) and "version" in data["log"]:
                return InputFormat.HAR

        # GraphQL SDL — plain text
        content_stripped = content.strip()
        if content_stripped.startswith("type ") or "type Query" in content:
            return InputFormat.GRAPHQL

        # Burp XML
        if content_stripped.startswith("<") and ("<items" in content):
            return InputFormat.BURP_XML

        # gRPC proto
        if content_stripped.startswith("syntax") and "proto" in content[:50]:
            return InputFormat.GRPC

        return InputFormat.UNKNOWN

    @staticmethod
    def get_parser(fmt: InputFormat):
        """Return the appropriate parser instance for a given format."""
        from brahmastra.garudastra.input.url_parser     import URLParser
        from brahmastra.garudastra.input.openapi_parser import OpenAPIParser
        from brahmastra.garudastra.input.postman_parser import PostmanParser
        from brahmastra.garudastra.input.har_parser     import HARParser
        from brahmastra.garudastra.input.graphql_parser import GraphQLParser
        from brahmastra.garudastra.input.burp_parser    import BurpParser

        parsers = {
            InputFormat.URL:      URLParser,
            InputFormat.OPENAPI3: OpenAPIParser,
            InputFormat.SWAGGER2: OpenAPIParser,   # Same parser handles both
            InputFormat.POSTMAN:  PostmanParser,
            InputFormat.HAR:      HARParser,
            InputFormat.GRAPHQL:  GraphQLParser,
            InputFormat.BURP_XML: BurpParser,
        }
        cls = parsers.get(fmt)
        if cls is None:
            raise ValueError(f"No parser available for format: {fmt}")
        return cls()
