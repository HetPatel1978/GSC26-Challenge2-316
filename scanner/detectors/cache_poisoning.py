"""Cache poisoning detector.

GitHub scopes Actions cache entries by branch, but restore falls back
across the branch hierarchy: a workflow run on the base branch can restore
a cache entry that was *written* by a workflow run on a PR branch. For a
`pull_request`-triggered workflow, that PR branch is attacker-controlled --
a forked PR run can seed a cache entry (build output, a dependency
resolved from a tampered lockfile, a compiled artifact) that a later,
privileged base-branch run then restores and trusts without rebuilding it.

Two checks:

1. `cache-poisoning` -- any step that writes to the cache (`actions/cache`,
   `actions/cache/save`, or a setup-* action with its built-in `cache:`
   input enabled) inside a `pull_request`-triggered job.
2. `predictable-cache-key` -- a cache `key`/`restore-keys` derived directly
   from attacker-controlled context, making a specific target entry easy
   to collide with deliberately rather than just opportunistically.
"""

from __future__ import annotations

from scanner.detectors.base import Detector
from scanner.findings import Finding, Severity
from scanner.ir import Step, Workflow
from scanner.taint import is_tainted_context

_CACHE_WRITE_ACTIONS = ("actions/cache", "actions/cache/save")
_AUTOCACHE_INPUT_BY_ACTION = {
    "actions/setup-node": "cache",
    "actions/setup-python": "cache",
    "actions/setup-java": "cache",
    "actions/setup-go": "cache",
}


def _action_name(step: Step) -> str | None:
    if not step.uses:
        return None
    return step.action_ref[0] if step.action_ref else step.uses


def _writes_cache(step: Step) -> bool:
    name = _action_name(step)
    if name is None:
        return False
    if name in _CACHE_WRITE_ACTIONS:
        return True
    autocache_key = _AUTOCACHE_INPUT_BY_ACTION.get(name)
    return bool(autocache_key and step.with_inputs.get(autocache_key))


class CachePoisoningDetector(Detector):
    category = "Cache poisoning"
    rule_id = "cache-poisoning"

    def detect(self, workflow: Workflow) -> list[Finding]:
        if "pull_request" not in workflow.on:
            return []

        findings: list[Finding] = []
        for job in workflow.jobs.values():
            for step in job.steps:
                if _writes_cache(step):
                    findings.append(self._cache_write_finding(workflow, job.id, step))
                findings += self._predictable_key_findings(workflow, job.id, step)
        return findings

    def _cache_write_finding(self, workflow: Workflow, job_id: str, step: Step) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=Severity.HIGH,
            file=workflow.source_path or "",
            line=step.line,
            message=(
                f"`{_action_name(step)}` writes to the Actions cache in a `pull_request`-"
                "triggered job; GitHub's cache restore rules let a same-branch-hierarchy "
                "base-branch run later restore an entry written by a forked PR run, letting a "
                "malicious PR poison what a privileged build later trusts."
            ),
            context=f"jobs.{job_id}.steps[{step.index}]",
            fix_hint=(
                "Avoid writing cache from fork-triggered `pull_request` jobs (use "
                "`actions/cache/restore` read-only there instead), or key the cache so "
                "PR-branch and base-branch entries can never collide, or switch to "
                "content-addressed keys (a hash of the lockfile) instead of branch names."
            ),
        )

    def _predictable_key_findings(self, workflow: Workflow, job_id: str, step: Step) -> list[Finding]:
        out: list[Finding] = []
        for key_field in ("key", "restore-keys"):
            if not isinstance(step.with_inputs.get(key_field), str):
                continue
            for expr in step.expressions():
                if expr.source_field != f"with.{key_field}":
                    continue
                if not any(is_tainted_context(ctx) for ctx in expr.contexts_referenced()):
                    continue
                out.append(
                    Finding(
                        rule_id="predictable-cache-key",
                        severity=Severity.MEDIUM,
                        file=workflow.source_path or "",
                        line=step.line,
                        message=(
                            f"Cache `{key_field}` is derived from attacker-controlled input, "
                            "making a poisoned entry easy to target deliberately rather than "
                            "just opportunistically."
                        ),
                        context=f"jobs.{job_id}.steps[{step.index}].with.{key_field}",
                        fix_hint=(
                            "Derive cache keys from content hashes (lockfiles, source) rather "
                            "than branch- or PR-controlled values."
                        ),
                    )
                )
        return out
