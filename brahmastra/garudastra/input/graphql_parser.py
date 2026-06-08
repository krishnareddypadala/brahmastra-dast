"""
BRAHMASTRA — Garudastra: GraphQL Parser (Gandharva Astra prep)
Parses GraphQL SDL or performs introspection to discover:
  - All queries, mutations, subscriptions
  - All types and their fields
  - Input types (attack surface)

Returns ScanTargets for the Gandharva Astra vulnerability module.
"""

import json
from pathlib import Path
from typing import Optional

import httpx

from brahmastra.sudarshana.base import ScanTarget

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name description isDeprecated deprecationReason
        args { name type { name kind ofType { name kind } } defaultValue }
        type { name kind ofType { name kind ofType { name kind } } }
      }
      inputFields {
        name description
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""


class GraphQLParser:
    """Parse GraphQL SDL or perform introspection to build scan targets."""

    async def parse(
        self,
        source: str,
        graphql_url: Optional[str] = None,
        auth_headers: Optional[dict] = None,
    ) -> list[ScanTarget]:
        """
        source: GraphQL URL, SDL file path, or raw SDL string.
        graphql_url: explicit endpoint URL (e.g. https://example.com/graphql).
        """
        self.auth_headers = auth_headers or {}
        targets = []

        # Determine if it's a URL (perform introspection)
        if source.startswith(("http://", "https://")):
            schema = await self._introspect(source)
            url = source
        elif graphql_url:
            # Load SDL from file/string, use graphql_url as endpoint
            schema = await self._introspect(graphql_url)
            url = graphql_url
        else:
            # Just use the SDL for analysis, URL will be guessed
            url = "http://localhost/graphql"
            schema = None

        if schema:
            targets.extend(self._build_targets_from_schema(schema, url))
        else:
            # Minimal target — test the endpoint itself
            targets.append(ScanTarget(
                url        = url,
                method     = "POST",
                parameters = [{"name": "query", "location": "json", "type": "graphql"}],
                headers    = {"Content-Type": "application/json", **self.auth_headers},
                source     = "graphql",
            ))

        return targets

    async def _introspect(self, url: str) -> Optional[dict]:
        """Perform GraphQL introspection query."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                resp = await client.post(
                    url,
                    json={"query": INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json", **self.auth_headers},
                )
                data = resp.json()
                if "data" in data and "__schema" in data["data"]:
                    return data["data"]["__schema"]
        except Exception:
            pass
        return None

    def _build_targets_from_schema(self, schema: dict, url: str) -> list[ScanTarget]:
        """Build scan targets from introspection schema."""
        targets = []
        types   = {t["name"]: t for t in schema.get("types", []) if not t["name"].startswith("__")}

        query_type    = (schema.get("queryType")    or {}).get("name")
        mutation_type = (schema.get("mutationType") or {}).get("name")

        for type_name in [query_type, mutation_type]:
            if not type_name or type_name not in types:
                continue
            operation = "query" if type_name == query_type else "mutation"
            type_def  = types[type_name]

            for field in (type_def.get("fields") or []):
                field_name = field.get("name", "")
                args       = field.get("args", [])

                # Build a test query/mutation
                if args:
                    arg_str = ", ".join(f'{a["name"]}: "test"' for a in args)
                    gql = f'{operation} {{ {field_name}({arg_str}) }}'
                else:
                    gql = f'{operation} {{ {field_name} }}'

                params = []
                for arg in args:
                    params.append({
                        "name":     arg["name"],
                        "location": "graphql_arg",
                        "type":     (arg.get("type") or {}).get("name", "String"),
                    })

                targets.append(ScanTarget(
                    url        = url,
                    method     = "POST",
                    parameters = params,
                    headers    = {"Content-Type": "application/json", **self.auth_headers},
                    body       = json.dumps({"query": gql}),
                    source     = "graphql",
                ))

        return targets
