"""
BRAHMASTRA — CLI Entry Point

Usage:
  brahmastra scan --target https://example.com --out report.json
  brahmastra scan --spec openapi.yaml --auth-type oauth2 --client-id X --client-secret Y --out report.pdf
  brahmastra scan --target https://example.com --auth-type form --login-url /login --username admin --password admin123
  brahmastra scan --har exported.har --out report.json
  brahmastra scan --burp burp_history.xml --out report.json

Options:
  --target        URL to crawl and scan
  --spec          OpenAPI/Swagger/Postman/HAR/Burp/GraphQL file
  --out           Output file path (auto-detect format from extension)
  --format        Output format: json (default), html, pdf, sarif
  --auth-type     Authentication type (none/basic/bearer/jwt/api-key/cookie/oauth2-cc/form/totp)
  --username      Username for basic/form/jwt auth
  --password      Password for basic/form auth
  --token         Pre-supplied bearer token
  --api-key       API key value
  --api-key-name  API key header name (default: X-API-Key)
  --login-url     Login URL for form/jwt auth
  --client-id     OAuth2 client ID
  --client-secret OAuth2 client secret
  --token-url     OAuth2 token endpoint
  --model-url     BRAHMASTRA model URL (default: http://localhost:11434/api/chat)
  --model-name    Model name (default: brahmastra)
  --max-turns     Max agent turns (default: 50)
  --rate-limit    Delay between requests in seconds (default: 0.1)
  --no-verify     Disable SSL verification (default: True for DAST)
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click

from brahmastra.agent import BrahmastraAgent, AgentConfig
from brahmastra.garudastra.detector import InputDetector, InputFormat
from brahmastra.garudastra.auth.manager import AuthManager, AuthConfig, auth_from_cli
from brahmastra.sudarshana.json_reporter import JSONReporter


@click.group()
@click.version_option("0.1.0", prog_name="brahmastra")
def cli():
    """
    BRAHMASTRA — AI-Native DAST Security Scanner

    Like the divine weapon of the Puranas, it strikes with precision and never misses.
    """
    pass


@cli.command()
@click.option("--target",      "-t",  default=None,  help="URL to scan")
@click.option("--spec",        "-s",  default=None,  help="Spec file (OpenAPI/Postman/HAR/Burp/GraphQL)")
@click.option("--har",                default=None,  help="HAR file")
@click.option("--burp",               default=None,  help="Burp Suite XML export")
@click.option("--out",         "-o",  default="brahmastra-report.json", help="Output file path")
@click.option("--format",      "-f",  default=None,  help="Output format: json/html/pdf/sarif")
@click.option("--auth-type",          default="none",help="Auth type")
@click.option("--username",    "-u",  default=None,  help="Username")
@click.option("--password",    "-p",  default=None,  help="Password")
@click.option("--token",              default=None,  help="Bearer token")
@click.option("--api-key",            default=None,  help="API key value")
@click.option("--api-key-name",       default="X-API-Key", help="API key header name")
@click.option("--api-key-location",   default="header", help="API key location: header/query/cookie")
@click.option("--login-url",          default=None,  help="Login URL for form/JWT auth")
@click.option("--client-id",          default=None,  help="OAuth2 client ID")
@click.option("--client-secret",      default=None,  help="OAuth2 client secret")
@click.option("--token-url",          default=None,  help="OAuth2 token endpoint URL")
@click.option("--totp-secret",        default=None,  help="TOTP base32 secret for MFA")
@click.option("--model-url",          default="http://localhost:11434/api/chat", help="Model API URL")
@click.option("--model-name",         default="brahmastra", help="Model name")
@click.option("--max-turns",          default=50,    type=int, help="Max agent turns")
@click.option("--rate-limit",         default=0.1,   type=float, help="Delay between requests (seconds)")
@click.option("--base-url",           default=None,  help="Override base URL for spec files")
@click.option("--verbose", "-v",      is_flag=True,  help="Verbose output")
def scan(
    target, spec, har, burp, out, format,
    auth_type, username, password, token, api_key,
    api_key_name, api_key_location, login_url,
    client_id, client_secret, token_url, totp_secret,
    model_url, model_name, max_turns, rate_limit,
    base_url, verbose,
):
    """Run a BRAHMASTRA security scan."""
    asyncio.run(_run_scan(
        target=target, spec=spec, har=har, burp=burp,
        out=out, fmt=format,
        auth_type=auth_type, username=username, password=password,
        token=token, api_key=api_key, api_key_name=api_key_name,
        api_key_location=api_key_location, login_url=login_url,
        client_id=client_id, client_secret=client_secret,
        token_url=token_url, totp_secret=totp_secret,
        model_url=model_url, model_name=model_name,
        max_turns=max_turns, rate_limit=rate_limit,
        base_url=base_url, verbose=verbose,
    ))


async def _run_scan(**kwargs):
    target     = kwargs.get("target")
    spec       = kwargs.get("spec")
    har        = kwargs.get("har")
    burp       = kwargs.get("burp")
    out        = kwargs.get("out", "brahmastra-report.json")
    fmt        = kwargs.get("fmt")
    verbose    = kwargs.get("verbose", False)
    model_url  = kwargs.get("model_url", "http://localhost:11434/api/chat")
    model_name = kwargs.get("model_name", "brahmastra")
    max_turns  = kwargs.get("max_turns", 50)
    rate_limit = kwargs.get("rate_limit", 0.1)
    base_url   = kwargs.get("base_url")

    _banner()

    # ── Determine input source ──────────────────────────────────────
    input_source = target or spec or har or burp
    if not input_source:
        click.echo("ERROR: Provide --target, --spec, --har, or --burp", err=True)
        sys.exit(1)

    # ── Auth setup ──────────────────────────────────────────────────
    auth_cfg = AuthConfig(
        auth_type        = kwargs.get("auth_type", "none"),
        username         = kwargs.get("username") or "",
        password         = kwargs.get("password") or "",
        token            = kwargs.get("token") or "",
        api_key          = kwargs.get("api_key") or "",
        api_key_name     = kwargs.get("api_key_name") or "X-API-Key",
        api_key_location = kwargs.get("api_key_location") or "header",
        login_url        = kwargs.get("login_url") or "",
        client_id        = kwargs.get("client_id") or "",
        client_secret    = kwargs.get("client_secret") or "",
        token_url        = kwargs.get("token_url") or "",
        totp_secret      = kwargs.get("totp_secret") or "",
    )
    auth_mgr = AuthManager(auth_cfg)
    auth_headers = await auth_mgr.get_headers()

    if auth_headers:
        click.echo(f"  [Auth] {auth_cfg.auth_type} — headers obtained")

    # ── Parse targets ───────────────────────────────────────────────
    click.echo(f"\n  [Garudastra] Detecting input format: {input_source}")
    fmt_detected = InputDetector.detect(input_source)
    click.echo(f"  [Garudastra] Format: {fmt_detected.value}")

    parser  = InputDetector.get_parser(fmt_detected)
    targets = await parser.parse(
        input_source,
        **({"auth_headers": auth_headers} if hasattr(parser, "parse") else {}),
        **(_base_url_kwarg(parser, base_url)),
    )

    if not targets:
        click.echo("ERROR: No scan targets found. Check your input.", err=True)
        sys.exit(1)

    click.echo(f"  [Garudastra] Discovered {len(targets)} targets")

    # ── Run agent ───────────────────────────────────────────────────
    agent_cfg = AgentConfig(
        model_url  = model_url,
        model_name = model_name,
        max_turns  = max_turns,
    )
    agent = BrahmastraAgent(config=agent_cfg)
    agent.tools.rate_limit_delay = rate_limit
    agent.tools.global_headers   = auth_headers
    agent.tools.base_url         = target or ""

    click.echo(f"\n  [Narayanastra] Starting AI scan  ({model_name} @ {model_url})")
    click.echo(f"  Max turns: {max_turns}  |  Rate limit: {rate_limit}s")
    click.echo()

    target_dicts = [t.to_dict() for t in targets]
    result = await agent.scan(target_dicts)
    result.finish()
    result.target = input_source

    # ── Report ──────────────────────────────────────────────────────
    out_path = Path(out)
    ext      = fmt or out_path.suffix.lstrip(".").lower() or "json"

    if ext == "json":
        reporter = JSONReporter(out_path)
        reporter.write(result)
    else:
        # Fallback to JSON until other reporters are implemented
        reporter = JSONReporter(out_path.with_suffix(".json"))
        reporter.write(result)
        click.echo(f"  [{ext.upper()} reporter coming soon — saved as JSON]")

    # ── Summary ──────────────────────────────────────────────────────
    _print_summary(result)
    sys.exit(result.exit_code)


def _banner():
    click.echo("""
╔══════════════════════════════════════════════════════════════╗
║  BRAHMASTRA — AI-Native DAST Security Scanner                ║
║  Like the divine weapon of the Puranas, it never misses.     ║
╚══════════════════════════════════════════════════════════════╝
""")


def _print_summary(result):
    from brahmastra.sudarshana.base import SEVERITY_ORDER
    click.echo(f"""
╔══ BRAHMASTRA Scan Complete ══════════════════════════════════
║  Target     : {result.target}
║  Findings   : {len(result.findings)} total
║  CRITICAL   : {result.critical_count}
║  HIGH       : {result.high_count}
║  MEDIUM     : {result.medium_count}
║  LOW        : {result.low_count}
║  Exit code  : {result.exit_code}
╚══════════════════════════════════════════════════════════════
""")
    if result.findings:
        click.echo("Top Findings:")
        for f in result.sorted_findings[:5]:
            click.echo(f"  [{f.severity}] {f.vuln_type} @ {f.url} (param: {f.parameter})")


def _base_url_kwarg(parser, base_url):
    if base_url and hasattr(parser, "parse"):
        return {"base_url": base_url}
    return {}


def main():
    cli()


if __name__ == "__main__":
    main()
