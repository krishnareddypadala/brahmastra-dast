"""
BRAHMASTRA — Sudarshana: Finding Data Model
The base data structures for all vulnerability findings and scan results.

Sudarshana — Vishnu's spinning discus — always finds its mark.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json


# Severity ordering for sorting
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    """A confirmed vulnerability finding."""
    severity:      str            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    vuln_type:     str            # e.g. "SQL Injection - Auth Bypass"
    url:           str            # Target URL
    parameter:     str            # Vulnerable parameter/field
    evidence:      str            # What confirmed the vulnerability
    cvss:          float          # CVSS 3.1 score
    remediation:   str            # How to fix it
    waf_bypassed:  bool  = False
    bypass_method: str   = ""
    timestamp:     str   = field(default_factory=lambda: datetime.utcnow().isoformat())
    think_trace:   str   = ""     # Full <think>...</think> reasoning chain
    payload:       str   = ""     # The payload that confirmed the vuln
    http_trace:    str   = ""     # Raw HTTP request/response

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.upper(), 99)

    def to_dict(self) -> dict:
        return {
            "severity":      self.severity,
            "type":          self.vuln_type,
            "url":           self.url,
            "parameter":     self.parameter,
            "evidence":      self.evidence,
            "cvss":          self.cvss,
            "remediation":   self.remediation,
            "waf_bypassed":  self.waf_bypassed,
            "bypass_method": self.bypass_method,
            "timestamp":     self.timestamp,
            "think_trace":   self.think_trace,
            "payload":       self.payload,
        }


@dataclass
class ScanTarget:
    """A single endpoint to be tested."""
    url:         str
    method:      str         = "GET"
    parameters:  list[dict]  = field(default_factory=list)
    headers:     dict        = field(default_factory=dict)
    body:        Optional[str] = None
    auth_type:   str         = "none"
    source:      str         = "url"    # url / openapi / postman / har / graphql / etc.

    def to_dict(self) -> dict:
        return {
            "url":        self.url,
            "method":     self.method,
            "parameters": self.parameters,
            "headers":    self.headers,
            "body":       self.body,
            "auth_type":  self.auth_type,
        }


@dataclass
class ScanResult:
    """Complete result of a BRAHMASTRA scan."""
    findings:     list[Finding]  = field(default_factory=list)
    agent_turns:  int            = 0
    scan_id:      str            = field(default_factory=lambda: _generate_scan_id())
    target:       str            = ""
    started_at:   str            = field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at:  Optional[str]  = None
    total_requests: int          = 0
    waf_detected:   bool         = False
    waf_vendor:     str          = ""
    tech_stack:     list[str]    = field(default_factory=list)

    def finish(self):
        self.finished_at = datetime.utcnow().isoformat()

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")

    @property
    def exit_code(self) -> int:
        """Exit code for CI/CD gates."""
        if self.critical_count > 0: return 4
        if self.high_count > 0:     return 3
        if self.medium_count > 0:   return 2
        if self.low_count > 0:      return 1
        return 0

    @property
    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity_rank)

    def to_dict(self) -> dict:
        return {
            "scan_id":       self.scan_id,
            "target":        self.target,
            "started_at":    self.started_at,
            "finished_at":   self.finished_at,
            "total_requests":self.total_requests,
            "waf_detected":  self.waf_detected,
            "waf_vendor":    self.waf_vendor,
            "tech_stack":    self.tech_stack,
            "summary": {
                "critical": self.critical_count,
                "high":     self.high_count,
                "medium":   self.medium_count,
                "low":      self.low_count,
                "total":    len(self.findings),
            },
            "findings": [f.to_dict() for f in self.sorted_findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def _generate_scan_id() -> str:
    import uuid
    return f"brahmastra-{uuid.uuid4().hex[:8]}"
