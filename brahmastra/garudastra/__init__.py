"""
Garudastra — Recon & Crawling Phase
Garuda: Vishnu's divine eagle, fastest, sees all.

Discovers endpoints, tech stack, auth scheme, parameters.
Feeds into Agneyastra (payload generation) and Narayanastra (probing).
"""

from brahmastra.garudastra.detector import InputDetector
from brahmastra.garudastra.input.url_parser import URLParser
from brahmastra.garudastra.input.openapi_parser import OpenAPIParser

__all__ = ["InputDetector", "URLParser", "OpenAPIParser"]
