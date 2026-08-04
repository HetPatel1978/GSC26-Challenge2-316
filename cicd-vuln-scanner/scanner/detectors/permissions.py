"""GITHUB_TOKEN permission analysis detector.

GitHub Actions' default token permissions -- what a workflow/job gets when
no `permissions:` block is present anywhere in scope -- come from the
repository/organization setting, and on many repos (anything created
before the 2023 default change, or with the org setting left broad) that
default is read/write across every scope. That implicit default, not any
particular explicit grant, is the actual finding: a compromised step
(malicious third-party action, or a script-injection sink elsewhere in the
same job) inherits whatever the token can do, and "whatever it can do" is
invisible from the workflow file alone when nothing is set.
"""

from __future__ import annotations

from scanner.detectors.base import Detector
from scanner.findings import Finding, Severity
from scanner.ir import Workflow


class ExcessPermissionsDetector(Detector):
    category = "Excess GITHUB_TOKEN permissions"
    rule_id = "excess-permissions"

    def detect(self, workflow: Workflow) -> list[Finding]:
        findings: list[Finding] = []

        if workflow.permissions.blanket == "write-all":
            findings.append(self._blanket_write_all(workflow))

        if not workflow.permissions.explicit and not self._every_job_scopes_permissions(workflow):
            findings.append(self._implicit_default(workflow))

        for job in workflow.jobs.values():
            if job.permissions.blanket == "write-all":
                findings.append(self._blanket_write_all(workflow, job_id=job.id, line=job.line))

        return findings

    def _every_job_scopes_permissions(self, workflow: Workflow) -> bool:
        """True if every job sets its own `permissions:`, making the
        top-level absence moot -- job-level permissions always override
        workflow-level ones, explicit or not, so a workflow that omits the
        top-level block but scopes every individual job is not actually
        relying on the broad default anywhere."""
        if not workflow.jobs:
            return False
        return all(job.permissions.explicit for job in workflow.jobs.values())

    def _implicit_default(self, workflow: Workflow) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=Severity.MEDIUM,
            file=workflow.source_path or "",
            line=None,
            message=(
                "No `permissions:` block at workflow or job level; GITHUB_TOKEN falls back to "
                "the repository/organization default, which may grant broad read/write access "
                "to every step in every job."
            ),
            context="(workflow-level)",
            fix_hint=(
                "Add a top-level `permissions:` block scoped to the minimum needed (often "
                "`contents: read`), and grant additional write scopes only on the specific jobs "
                "that need them."
            ),
        )

    def _blanket_write_all(
        self, workflow: Workflow, job_id: str | None = None, line: int | None = None
    ) -> Finding:
        context = f"jobs.{job_id}" if job_id else "(workflow-level)"
        scope_desc = f" for job `{job_id}`" if job_id else ""
        return Finding(
            rule_id=self.rule_id,
            severity=Severity.HIGH,
            file=workflow.source_path or "",
            line=line,
            message=(
                f"`permissions: write-all` grants every scope write access{scope_desc}; a single "
                "compromised step can act on all of them."
            ),
            context=context,
            fix_hint=(
                "Replace `write-all` with an explicit per-scope mapping listing only the scopes "
                "and levels actually needed."
            ),
        )
