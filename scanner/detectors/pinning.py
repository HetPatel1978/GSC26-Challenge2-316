"""Unpinned third-party actions detector.

`uses: org/action@<ref>` accepts a full commit SHA, a tag, or a branch
name, but only a SHA is immutable. A mutable ref (`@v4`, `@main`,
`@latest`) can be repointed by the action's maintainer -- deliberately, via
a compromised maintainer account, or via a compromised publishing pipeline
of theirs -- to a different commit after a workflow using it has already
been reviewed and merged, and the next run of that workflow executes
whatever the ref now resolves to with no change to the consuming
workflow's own file. Pinning to a commit SHA removes that class of risk
entirely: the ref always resolves to the exact content that was reviewed.
"""

from __future__ import annotations

import re

from scanner.detectors.base import Detector
from scanner.findings import Finding, Severity
from scanner.ir import Step, Workflow

# A full (40 hex chars) or abbreviated (7+ hex chars) commit SHA. 7 is the
# floor git itself treats as an unambiguous short SHA; requiring hex-only
# excludes version tags like "v4" or "v4.1.0" and branch names, which is
# exactly the population this detector needs to flag.
_SHA_REF_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


class UnpinnedActionDetector(Detector):
    category = "Unpinned third-party actions"
    rule_id = "unpinned-action"

    def detect(self, workflow: Workflow) -> list[Finding]:
        findings: list[Finding] = []
        for job in workflow.jobs.values():
            for step in job.steps:
                finding = self._check_step(workflow, job.id, step)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _check_step(self, workflow: Workflow, job_id: str, step: Step) -> Finding | None:
        # `step.action_ref` is None for local actions (`./path`, no `@`) and
        # docker actions addressed by tag/digest via `:` rather than `@` --
        # neither is a "third-party action pinned by ref" in the sense this
        # detector cares about.
        if not step.uses or not step.action_ref:
            return None
        name, ref = step.action_ref
        if not ref or _SHA_REF_RE.match(ref):
            return None
        return Finding(
            rule_id=self.rule_id,
            severity=Severity.MEDIUM,
            file=workflow.source_path or "",
            line=step.line,
            message=(
                f"`{name}@{ref}` is pinned to a mutable ref, not a commit SHA -- whoever "
                "controls that tag or branch can repoint it to different content at any time, "
                "and the next run of this workflow executes whatever it now resolves to."
            ),
            context=f"jobs.{job_id}.steps[{step.index}].uses",
            fix_hint=(
                f"Pin to the full commit SHA `{ref}` currently resolves to (e.g. "
                f"`{name}@<40-char-sha> # {ref}`), and use Dependabot or Renovate to keep the "
                "pin updated."
            ),
        )
