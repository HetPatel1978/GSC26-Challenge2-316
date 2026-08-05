"""Self-hosted runner misuse detector.

GitHub's own docs warn against ever using self-hosted runners on a public
repository: unlike GitHub-hosted runners, self-hosted machines are
typically long-lived and non-ephemeral, so anything that runs on one can
leave state behind for a later job to trust, exfiltrate secrets or network
access the runner has, or pivot into whatever else sits on that
infrastructure.

Two fork-triggerable events make that reachable from an untrusted PR, with
different severity because of *what* an attacker actually controls:

- `pull_request` -- for this event, GitHub runs the workflow file as it
  exists in the merge of the PR branch, which the fork author controls
  directly. `runs-on: self-hosted` and every step are attacker-authored --
  full arbitrary code execution on the runner.
- `pull_request_target` -- the workflow file itself always comes from the
  base branch (a fork can't rewrite `runs-on` or the steps here), but the
  job still runs with a privileged token on persistent infrastructure, so
  whatever it does execute (see pull_request_target.py for the
  fork-checkout case that turns this into full compromise) is still
  unsafe to run there.
"""

from __future__ import annotations

from typing import Any

from scanner.detectors.base import Detector
from scanner.findings import Finding, Severity
from scanner.ir import Workflow

_FORK_TRIGGERABLE_EVENTS = ("pull_request", "pull_request_target")


def _is_self_hosted(runs_on: Any) -> bool:
    if isinstance(runs_on, str):
        return runs_on == "self-hosted"
    if isinstance(runs_on, list):
        return "self-hosted" in runs_on
    if isinstance(runs_on, dict):
        # Runner-group targeting (`runs-on: {group: ..., labels: [...]}`)
        # is itself a self-hosted-infrastructure feature -- GitHub-hosted
        # runners aren't addressed through `group:`.
        if "group" in runs_on:
            return True
        labels = runs_on.get("labels")
        if isinstance(labels, list):
            return "self-hosted" in labels
        return labels == "self-hosted"
    return False


class SelfHostedRunnerDetector(Detector):
    category = "Self-hosted runner misuse"
    rule_id = "self-hosted-runner-fork-trigger"

    def detect(self, workflow: Workflow) -> list[Finding]:
        triggering_events = [e for e in _FORK_TRIGGERABLE_EVENTS if e in workflow.on]
        if not triggering_events:
            return []

        severity = Severity.CRITICAL if "pull_request" in triggering_events else Severity.HIGH
        events_desc = "`/`".join(triggering_events)

        findings: list[Finding] = []
        for job in workflow.jobs.values():
            if not _is_self_hosted(job.runs_on):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=severity,
                    file=workflow.source_path or "",
                    line=job.line,
                    message=(
                        f"Job `{job.id}` runs on a self-hosted runner in a workflow triggered by "
                        f"`{events_desc}`, which a fork's pull request can trigger. Self-hosted "
                        "runners are typically long-lived, non-ephemeral machines, so code that "
                        "reaches one can persist state, read other jobs' data, or pivot into "
                        "whatever network it sits on."
                    ),
                    context=f"jobs.{job.id}",
                    fix_hint=(
                        "Never target self-hosted runners from workflows a public repository's "
                        "forked pull requests can trigger. Switch these jobs to a GitHub-hosted "
                        "runner (`runs-on: ubuntu-latest`), or restrict the trigger to a "
                        "non-fork event and gate any self-hosted job behind maintainer approval."
                    ),
                )
            )
        return findings
