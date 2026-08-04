"""Tests for scanner/findings.py."""

from scanner.findings import Finding, SARIFExporter, Severity


def _finding(**overrides) -> Finding:
    defaults = dict(
        rule_id="script-injection",
        severity=Severity.CRITICAL,
        file="ci.yml",
        line=25,
        message="Untrusted github.event.issue.title interpolated into run:",
        context="jobs.build.steps[1].run",
        fix_hint="Use an env var indirection instead of inline interpolation",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_finding_to_dict_serializes_severity_as_string():
    finding = _finding()
    data = finding.to_dict()
    assert data["severity"] == "critical"
    assert data["rule_id"] == "script-injection"
    assert data["line"] == 25


def test_sarif_exporter_structure():
    findings = [_finding(), _finding(rule_id="unpinned-action", severity=Severity.LOW, line=None)]
    sarif = SARIFExporter(findings).to_dict()

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"script-injection", "unpinned-action"}
    assert len(run["results"]) == 2


def test_sarif_severity_maps_to_level():
    critical = SARIFExporter([_finding(severity=Severity.CRITICAL)]).to_dict()
    low = SARIFExporter([_finding(severity=Severity.LOW)]).to_dict()

    assert critical["runs"][0]["results"][0]["level"] == "error"
    assert low["runs"][0]["results"][0]["level"] == "note"


def test_sarif_omits_region_when_line_is_none():
    sarif = SARIFExporter([_finding(line=None)]).to_dict()
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in location


def test_sarif_includes_start_line_when_present():
    sarif = SARIFExporter([_finding(line=42)]).to_dict()
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["region"]["startLine"] == 42
