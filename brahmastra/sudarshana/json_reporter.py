"""
BRAHMASTRA — Sudarshana: JSON Reporter
Outputs scan results as OWASP-schema compatible JSON.
"""

import json
from pathlib import Path
from brahmastra.sudarshana.base import ScanResult


class JSONReporter:
    """Write scan results to JSON file."""

    def __init__(self, output_path: Path | str):
        self.output_path = Path(output_path)

    def write(self, result: ScanResult) -> Path:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"  [Sudarshana] JSON report: {self.output_path}")
        return self.output_path

    @staticmethod
    def to_stdout(result: ScanResult):
        print(result.to_json())
