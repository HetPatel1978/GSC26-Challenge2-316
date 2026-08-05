"""Finding dataclass, severity enum, and SARIF export.

Detectors (scanner/detectors/*.py) each produce a list[Finding]; eval/ and
the patcher consume that list without caring which detector produced it.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """One vulnerability instance at one location in one workflow file."""

    rule_id: str
    severity: Severity
    file: str
    line: int | None
    message: str
    context: str | None = None
    fix_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SARIFExporter:
    """Serializes a list of Findings to SARIF 2.1.0 — the format GitHub
    code scanning and most CI security dashboards consume.
    """

    TOOL_NAME = "cicd-vuln-scanner"
    TOOL_VERSION = "0.1.0"
    INFORMATION_URI = "https://github.com/placeholder/cicd-vuln-scanner"

    def __init__(self, findings: list[Finding]):
        self.findings = findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": "2.1.0",
            "$schema": (
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json"
            ),
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "informationUri": self.INFORMATION_URI,
                            "rules": self._rules(),
                        }
                    },
                    "results": [self._result(f) for f in self.findings],
                }
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def _rules(self) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for finding in self.findings:
            if finding.rule_id not in seen:
                seen[finding.rule_id] = {
                    "id": finding.rule_id,
                    "shortDescription": {"text": finding.rule_id.replace("-", " ").capitalize()},
                }
        return list(seen.values())

    def _result(self, finding: Finding) -> dict[str, Any]:
        uri = finding.file.replace("\\", "/") if finding.file else finding.file
        physical_location: dict[str, Any] = {"artifactLocation": {"uri": uri}}
        if finding.line is not None:
            physical_location["region"] = {"startLine": finding.line}

        return {
            "ruleId": finding.rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": finding.message},
            "locations": [{"physicalLocation": physical_location}],
        }
