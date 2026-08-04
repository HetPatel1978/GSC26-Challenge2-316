"""pull_request_target misuse detector.

`pull_request_target` runs with the base repository's context -- full
GITHUB_TOKEN permissions and access to repository secrets -- even when
triggered by a fork's pull request. That's safe by itself: the workflow
*file* that actually runs is always the base branch's version, no matter
what the PR branch contains. It stops being safe the moment a step checks
out the fork's HEAD *content* and something later in the job builds,
tests, or otherwise executes that content, because now attacker-controlled
code is running with the base repo's privileges.
"""

from __future__ import annotations

from scanner.detectors.base import Detector
from scanner.findings import Finding, Severity
from scanner.ir import Step, Workflow

_CHECKOUT_ACTION = "actions/checkout"

# Context paths that pin `actions/checkout`'s `ref:` to the fork PR's head
# content. Deliberately separate from taint.py's TAINTED_CONTEXTS (which
# models attacker-controlled *shell-injectable text*): `head.sha` isn't
# text an attacker can shape to break out of a command, but it's exactly
# the value that determines *which commit's content* gets checked out --
# the thing that matters for this detector.
_FORK_HEAD_REF_CONTEXTS = frozenset(
    {
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.head_ref",
    }
)


def _action_name(step: Step) -> str | None:
    if not step.uses:
        return None
    return step.action_ref[0] if step.action_ref else step.uses


def _checks_out_fork_head(step: Step) -> bool:
    if _action_name(step) != _CHECKOUT_ACTION:
        return False
    if not isinstance(step.with_inputs.get("ref"), str):
        return False
    for expr in step.expressions():
        if expr.source_field != "with.ref":
            continue
        if any(ctx in _FORK_HEAD_REF_CONTEXTS for ctx in expr.contexts_referenced()):
            return True
    return False


class PullRequestTargetDetector(Detector):
    category = "pull_request_target misuse"
    rule_id = "pull-request-target-checkout"

    def detect(self, workflow: Workflow) -> list[Finding]:
        if "pull_request_target" not in workflow.on:
            return []

        findings: list[Finding] = []
        for job in workflow.jobs.values():
            for step in job.steps:
                if not _checks_out_fork_head(step):
                    continue
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        file=workflow.source_path or "",
                        line=step.line,
                        message=(
                            "`pull_request_target` workflow checks out the fork PR's head "
                            "content, combining base-repo secrets/token access with untrusted "
                            "code -- any later step that builds, tests, or otherwise executes "
                            "that checkout runs attacker-controlled code with privileged access."
                        ),
                        context=f"jobs.{job.id}.steps[{step.index}].with.ref",
                        fix_hint=(
                            "Switch the trigger to `pull_request` (loses secrets/write token, "
                            "which is usually fine for build/test), or keep "
                            "`pull_request_target` but drop the explicit `ref:` so checkout "
                            "stays on the base branch, and only read (never execute) fork "
                            "content in a separate, token-less job."
                        ),
                    )
                )
        return findings
