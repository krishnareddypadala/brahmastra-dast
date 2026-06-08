"""
BRAHMASTRA — Garudastra: URL Canonicalizer

OWASP ZAP-inspired URL normalization and path-template detection.

Without canonicalization, a crawler treats these as five distinct URLs:
    /profile?sid=abc123&utm_source=x
    /profile?sid=def456
    /profile?utm_source=y&sid=abc123
    /user/1
    /user/999

...and wastes the entire scan budget on the same page rendered with
different tracking IDs or IDs that all hit the same Flask/Django route.

This module provides three primitives used by the spider's dedup layer:

  canonicalize_url(url)
      Strip session IDs / tracking params (jsessionid, phpsessid, utm_*,
      gclid, fbclid, ref, etc.), normalize query key order, drop fragment.

  PathTemplateTracker
      Incremental detector for "high-cardinality" path segments. Once it
      sees N (default 3) sibling paths that differ only in one segment
      which looks ID-ish (digits, UUID, slug), it emits a templated form
      like `/user/{id}` and future sibling URLs collapse into that key.

  canonical_key(url, method, tracker)
      The thing the spider's `visited` set actually stores. Combines
      the stripped URL, the templated path, and method into a single
      dedup key.

Design notes:
  - Pure-Python, no deps. Safe to call from hot paths.
  - The template tracker is scoped PER-SCAN (instantiated once in
    spider.crawl()). It is stateful but not thread-safe; callers must
    use it from the same asyncio task tree.
  - Stripped params are not deleted from the ScanTarget — the rule
    engine still sees them. We only strip them from the dedup KEY so
    the spider doesn't re-walk the same page with 40 different session
    IDs attached.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode


# Params that uniquely identify a session/visitor — never meaningful for
# crawl dedup. Anything matching is dropped from the canonical key.
STRIP_PARAMS: set[str] = {
    # Classic session IDs
    "jsessionid", "phpsessid", "aspsessionid", "sid", "sessid",
    "session", "session_id", "sessionid", "cfid", "cftoken",
    # Analytics / marketing
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_name", "utm_reader", "utm_viz_id", "utm_pubreferrer",
    "gclid", "gclsrc", "dclid", "fbclid", "msclkid", "mc_cid", "mc_eid",
    "yclid", "_openstat", "wickedid", "pk_source", "pk_medium", "pk_campaign",
    # Misc tracking
    "ref", "referrer", "source", "src", "_ga", "_gid", "_gac",
    "amp", "amp_js_v", "mkt_tok",
}

# Path segments that ZAP's DefaultParser treats as "definitely an ID".
# A segment matching any of these patterns counts as a template candidate.
_ID_LIKE: list[re.Pattern] = [
    re.compile(r"^\d+$"),                                           # 42, 999
    re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", re.I),  # UUID
    re.compile(r"^[a-f0-9]{24,64}$", re.I),                         # hex hash
    re.compile(r"^[A-Za-z0-9_-]{20,}$"),                            # long slug / token
]


def _segment_is_id_like(seg: str) -> bool:
    """Return True if `seg` looks like a per-entity identifier."""
    if not seg:
        return False
    for pat in _ID_LIKE:
        if pat.match(seg):
            return True
    return False


def canonicalize_url(url: str) -> str:
    """
    Strip tracking/session params, sort query keys, drop fragment.

    Input:  /cart?sid=abc&item=42&utm_source=x#checkout
    Output: /cart?item=42
    """
    try:
        p = urlparse(url)
    except Exception:
        return url

    # Strip tracking params; keep real ones
    kept = [
        (k, v)
        for k, v in parse_qsl(p.query, keep_blank_values=True)
        if k.lower() not in STRIP_PARAMS
    ]
    # Sort by key so ?a=1&b=2 == ?b=2&a=1 for dedup purposes
    kept.sort(key=lambda kv: kv[0])
    new_query = urlencode(kept)

    # Drop fragment, normalize empty path to "/"
    path = p.path or "/"

    return urlunparse((p.scheme, p.netloc, path, "", new_query, ""))


class PathTemplateTracker:
    """
    Incremental path-template detector.

    Walk the tree of discovered paths. When we see that a given path
    "slot" (parent prefix + position) has been filled by at least
    `threshold` distinct ID-ish values, collapse all future sibling
    URLs sharing that prefix into a templated form.

    Example after 3 observations:
      /user/1      →  /user/{id}
      /user/42     →  /user/{id}
      /user/admin  →  /user/{id}
      /user/999    →  /user/{id}   ← future hits collapse immediately

    The detector only fires for segments that actually look ID-ish
    (see `_segment_is_id_like`) — "/user/profile" and "/user/settings"
    do NOT trigger templating because neither segment matches an ID
    pattern.
    """

    def __init__(self, threshold: int = 3) -> None:
        self.threshold = max(2, int(threshold))
        # key: parent_prefix (tuple of segments), position_index  →  set of seen ID values
        self._slots: dict[tuple[tuple[str, ...], int], set[str]] = {}
        # key: (parent_prefix, position_index) once this slot has been
        # templated, its entry here is True and all future URLs with
        # the same prefix+position get collapsed to "{id}".
        self._templated: set[tuple[tuple[str, ...], int]] = set()

    def templatize(self, path: str) -> str:
        """
        Record observation of `path` and return its templated form.

        The returned path may equal the input on the first call; only
        once `threshold` distinct ID-ish siblings have been seen does
        the slot flip to `{id}`.
        """
        if not path or path == "/":
            return path
        segments = [s for s in path.split("/") if s != ""]
        out: list[str] = []
        prefix: list[str] = []
        for i, seg in enumerate(segments):
            slot_key = (tuple(prefix), i)
            if slot_key in self._templated:
                out.append("{id}")
            elif _segment_is_id_like(seg):
                bucket = self._slots.setdefault(slot_key, set())
                bucket.add(seg)
                if len(bucket) >= self.threshold:
                    self._templated.add(slot_key)
                    out.append("{id}")
                else:
                    out.append(seg)
            else:
                out.append(seg)
            # Parent prefix grows with the ORIGINAL (untemplated) segment
            # so "/user/1/posts" and "/user/2/posts" share the same prefix
            # when templating the posts-level slot.
            prefix.append(seg if not _segment_is_id_like(seg) else "{id}")

        return "/" + "/".join(out)

    def stats(self) -> dict:
        """Return counts of tracked slots and templated slots (for debugging/telemetry)."""
        return {
            "tracked_slots":   len(self._slots),
            "templated_slots": len(self._templated),
        }


def canonical_key(
    url: str,
    method: str = "GET",
    tracker: Optional[PathTemplateTracker] = None,
) -> str:
    """
    Produce the single dedup key the spider's `visited` set stores.

    Combines:
      - canonicalize_url() to strip trackers/session IDs
      - PathTemplateTracker (if given) to collapse /user/1 + /user/2 + ...
      - HTTP method prefix so GET /api/x and POST /api/x stay distinct
    """
    canon = canonicalize_url(url)
    if tracker is not None:
        try:
            p = urlparse(canon)
            templated_path = tracker.templatize(p.path)
            canon = urlunparse((p.scheme, p.netloc, templated_path, "", p.query, ""))
        except Exception:
            pass
    return f"{(method or 'GET').upper()} {canon}"
