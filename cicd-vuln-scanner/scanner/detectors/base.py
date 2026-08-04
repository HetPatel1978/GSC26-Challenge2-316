"""BaseDetector ABC that all category detectors implement.

Every detector takes a parsed `scanner.ir.Workflow` and returns a list of
`scanner.findings.Finding`. Detectors are pure functions of the IR -- no
shared mutable state -- so they can run in any order, be composed freely by
`scanner/cli.py`, and be unit-tested in isolation against a single fixture.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from scanner.findings import Finding
from scanner.ir import Workflow


class Detector(ABC):
    """One vulnerability category from taxonomy.md.

    Subclasses set `rule_id` (the primary/umbrella rule id used in
    findings -- some detectors emit a couple of more specific rule ids for
    subtypes, see secrets.py) and `category` (human-readable, matches a
    taxonomy.md heading), then implement `detect`.
    """

    rule_id: str
    category: str

    @abstractmethod
    def detect(self, workflow: Workflow) -> list[Finding]:
        """Return every finding for this category in `workflow`.

        Empty list if none. Must not raise on a malformed or partial IR --
        treat missing optional fields as "not present" rather than error,
        since real-world workflow files are frequently incomplete or use
        GitHub Actions features this scanner doesn't model yet.
        """
        raise NotImplementedError


def run_all(detectors: list[Detector], workflow: Workflow) -> list[Finding]:
    """Run every detector against `workflow` and flatten the results,
    preserving detector order (taxonomy.md's priority order)."""
    findings: list[Finding] = []
    for detector in detectors:
        findings.extend(detector.detect(workflow))
    return findings
