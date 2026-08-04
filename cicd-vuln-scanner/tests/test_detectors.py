"""Tests for scanner/detectors/. One true-positive + one true-negative check
per detector, against the fixtures in tests/fixtures/, plus the
permission-inheritance edge cases that are easy to get wrong."""

from __future__ import annotations

from pathlib import Path

from scanner.detectors.cache_poisoning import CachePoisoningDetector
from scanner.detectors.dependency_confusion import DependencyConfusionDetector
from scanner.detectors.injection import ScriptInjectionDetector
from scanner.detectors.permissions import ExcessPermissionsDetector
from scanner.detectors.pull_request_target import PullRequestTargetDetector
from scanner.detectors.secrets import SecretLeakageDetector
from scanner.parser import parse_workflow_file

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str):
    return parse_workflow_file(str(FIXTURES / name))


def _rule_ids(findings):
    return [f.rule_id for f in findings]


def _by_context(findings, context: str):
    return next(f for f in findings if f.context == context)


# --- script injection ---------------------------------------------------


def test_script_injection_flags_direct_interpolation():
    wf = _load("script_injection.yml")
    findings = ScriptInjectionDetector().detect(wf)
    assert _rule_ids(findings) == ["script-injection"]
    finding = findings[0]
    assert finding.context == "jobs.unsafe.steps[0].run"
    assert "github.event.comment.body" in finding.message
    assert finding.severity.value == "critical"


def test_script_injection_does_not_flag_env_indirection_or_safe_context():
    wf = _load("script_injection.yml")
    findings = ScriptInjectionDetector().detect(wf)
    contexts = {f.context for f in findings}
    assert "jobs.safe-env-indirection.steps[0].run" not in contexts
    assert "jobs.safe-non-tainted.steps[0].run" not in contexts


def test_script_injection_clean_fixture_has_no_findings():
    wf = _load("minimal.yml")
    assert ScriptInjectionDetector().detect(wf) == []


# --- pull_request_target --------------------------------------------------


def test_pull_request_target_flags_fork_head_checkout():
    wf = _load("pull_request_target.yml")
    findings = PullRequestTargetDetector().detect(wf)
    assert len(findings) == 1
    assert findings[0].rule_id == "pull-request-target-checkout"
    assert findings[0].severity.value == "critical"
    assert findings[0].context == "jobs.build.steps[0].with.ref"


def test_pull_request_target_ignores_non_prt_workflows():
    wf = _load("minimal.yml")
    assert PullRequestTargetDetector().detect(wf) == []


def test_pull_request_target_ignores_prt_without_fork_checkout():
    wf = _load("script_injection.yml")  # no pull_request_target trigger at all
    assert PullRequestTargetDetector().detect(wf) == []


# --- excess permissions --------------------------------------------------


def test_excess_permissions_flags_missing_block():
    wf = _load("minimal.yml")
    findings = ExcessPermissionsDetector().detect(wf)
    assert len(findings) == 1
    assert findings[0].rule_id == "excess-permissions"
    assert findings[0].severity.value == "medium"


def test_excess_permissions_clean_when_explicit_top_level():
    wf = _load("permissions.yml")
    findings = ExcessPermissionsDetector().detect(wf)
    assert findings == []


def test_excess_permissions_ignores_job_missing_block_when_top_level_explicit():
    # "inherits" job in permissions.yml has no job-level permissions:, but
    # the workflow-level block is explicit, so nothing should fire for it.
    wf = _load("permissions.yml")
    assert "inherits" in wf.jobs
    findings = ExcessPermissionsDetector().detect(wf)
    assert findings == []


def test_excess_permissions_flags_blanket_write_all_at_workflow_and_job_level():
    raw = {
        "on": "push",
        "permissions": "write-all",
        "jobs": {
            "a": {
                "runs-on": "ubuntu-latest",
                "permissions": "write-all",
                "steps": [{"run": "echo hi"}],
            }
        },
    }
    from scanner.parser import parse_workflow

    wf = parse_workflow(raw, source_path="write-all.yml")
    findings = ExcessPermissionsDetector().detect(wf)
    contexts = {f.context for f in findings}
    assert "(workflow-level)" in contexts
    assert "jobs.a" in contexts
    assert all(f.severity.value == "high" for f in findings)


# --- secrets --------------------------------------------------------------


def test_secret_leakage_flags_hardcoded_literal():
    wf = _load("secrets_leak.yml")
    findings = SecretLeakageDetector().detect(wf)
    finding = _by_context(findings, "jobs.hardcoded.steps[0].env.AWS_KEY")
    assert finding.rule_id == "hardcoded-secret"
    assert finding.severity.value == "critical"


def test_secret_leakage_escalates_echoed_secret_to_critical():
    wf = _load("secrets_leak.yml")
    findings = SecretLeakageDetector().detect(wf)
    finding = _by_context(findings, "jobs.echoed.steps[0].run")
    assert finding.rule_id == "secret-echoed-to-log"
    assert finding.severity.value == "critical"


def test_secret_leakage_flags_inline_non_echo_as_medium():
    wf = _load("secrets_leak.yml")
    findings = SecretLeakageDetector().detect(wf)
    finding = _by_context(findings, "jobs.inline-no-echo.steps[0].run")
    assert finding.rule_id == "secret-inline-interpolation"
    assert finding.severity.value == "medium"


def test_secret_leakage_flags_secret_in_url():
    wf = _load("secrets_leak.yml")
    findings = SecretLeakageDetector().detect(wf)
    url_findings = [f for f in findings if f.rule_id == "secret-in-url"]
    assert len(url_findings) == 1
    assert url_findings[0].context == "jobs.url-basic-auth.steps[0].run"
    assert url_findings[0].severity.value == "high"


def test_secret_leakage_clean_job_has_no_findings():
    wf = _load("secrets_leak.yml")
    findings = SecretLeakageDetector().detect(wf)
    assert not any(f.context.startswith("jobs.clean.") for f in findings)


# --- dependency confusion --------------------------------------------------


def test_dependency_confusion_flags_pip_extra_index_url():
    wf = _load("dependency_confusion.yml")
    findings = DependencyConfusionDetector().detect(wf)
    finding = _by_context(findings, "jobs.pip-risky.steps[0].run")
    assert finding.rule_id == "pip-extra-index-url"


def test_dependency_confusion_flags_unscoped_npm_install():
    wf = _load("dependency_confusion.yml")
    findings = DependencyConfusionDetector().detect(wf)
    finding = _by_context(findings, "jobs.npm-risky.steps[0].run")
    assert finding.rule_id == "unscoped-private-package"
    assert "internal-widget" in finding.message


def test_dependency_confusion_does_not_flag_safe_jobs():
    wf = _load("dependency_confusion.yml")
    findings = DependencyConfusionDetector().detect(wf)
    contexts = {f.context for f in findings}
    assert "jobs.npm-safe.steps[0].run" not in contexts
    assert "jobs.pip-safe.steps[0].run" not in contexts


# --- cache poisoning --------------------------------------------------------


def test_cache_poisoning_flags_cache_write_on_pull_request():
    wf = _load("cache_poisoning.yml")
    findings = CachePoisoningDetector().detect(wf)
    write_findings = [f for f in findings if f.rule_id == "cache-poisoning"]
    contexts = {f.context for f in write_findings}
    assert "jobs.writes-cache.steps[1]" in contexts
    assert "jobs.autocache.steps[0]" in contexts


def test_cache_poisoning_ignores_restore_only_step():
    wf = _load("cache_poisoning.yml")
    findings = CachePoisoningDetector().detect(wf)
    contexts = {f.context for f in findings}
    assert not any(c.startswith("jobs.restore-only") for c in contexts)


def test_cache_poisoning_flags_predictable_key():
    wf = _load("cache_poisoning.yml")
    findings = CachePoisoningDetector().detect(wf)
    finding = _by_context(findings, "jobs.writes-cache.steps[1].with.key")
    assert finding.rule_id == "predictable-cache-key"


def test_cache_poisoning_ignores_non_pull_request_trigger():
    wf = _load("minimal.yml")  # triggered by push
    assert CachePoisoningDetector().detect(wf) == []
