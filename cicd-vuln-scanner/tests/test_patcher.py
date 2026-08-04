"""Tests for scanner/patcher.py."""

from __future__ import annotations

from scanner.findings import Finding, Severity
from scanner.patcher import suggest_patch, suggest_patches

_TEMPLATED_RULE_IDS = [
    "script-injection",
    "pull-request-target-checkout",
    "excess-permissions",
    "hardcoded-secret",
    "secret-echoed-to-log",
    "secret-inline-interpolation",
    "secret-in-url",
    "pip-extra-index-url",
    "unscoped-private-package",
    "cache-poisoning",
    "predictable-cache-key",
]


def _finding(rule_id: str, fix_hint: str | None = "generic fix hint") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        file="ci.yml",
        line=3,
        message="something is wrong",
        fix_hint=fix_hint,
    )


def test_every_templated_rule_id_has_before_and_after():
    for rule_id in _TEMPLATED_RULE_IDS:
        patch = suggest_patch(_finding(rule_id))
        assert patch.before, rule_id
        assert patch.after, rule_id
        assert patch.explanation
        assert patch.summary


def test_unknown_rule_id_falls_back_to_fix_hint():
    finding = _finding("some-future-rule", fix_hint="do the thing")
    patch = suggest_patch(finding)
    assert patch.before is None
    assert patch.after is None
    assert patch.summary == "do the thing"


def test_unknown_rule_id_without_fix_hint_falls_back_to_message():
    finding = _finding("some-future-rule", fix_hint=None)
    patch = suggest_patch(finding)
    assert patch.summary == "No template available for this rule."
    assert patch.explanation == finding.message


def test_render_includes_rule_id_and_sections():
    patch = suggest_patch(_finding("script-injection"))
    rendered = patch.render()
    assert "[script-injection]" in rendered
    assert "--- before ---" in rendered
    assert "--- after ---" in rendered


def test_render_omits_before_after_sections_when_absent():
    patch = suggest_patch(_finding("some-future-rule", fix_hint="do the thing"))
    rendered = patch.render()
    assert "--- before ---" not in rendered
    assert "do the thing" in rendered


def test_suggest_patches_preserves_order_and_count():
    findings = [_finding("script-injection"), _finding("hardcoded-secret"), _finding("cache-poisoning")]
    patches = suggest_patches(findings)
    assert [p.finding.rule_id for p in patches] == [f.rule_id for f in findings]
