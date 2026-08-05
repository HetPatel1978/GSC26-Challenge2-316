"""Script injection detector: attacker-controlled github.event.* in run: steps.

Thin presentation layer over `scanner.taint.find_injection_sinks` -- all of
the actual source/sink reasoning lives in taint.py; this module just turns
each `TaintFinding` into a `Finding` with severity and human-readable text.
"""

from __future__ import annotations

from scanner.detectors.base import Detector
from scanner.findings import Finding, Severity
from scanner.ir import Workflow
from scanner.taint import find_injection_sinks


class ScriptInjectionDetector(Detector):
    category = "Script injection"
    rule_id = "script-injection"

    def detect(self, workflow: Workflow) -> list[Finding]:
        findings: list[Finding] = []
        for job_id, tf in find_injection_sinks(workflow):
            refs = ", ".join(dict.fromkeys(tf.tainted_contexts))  # de-dup, keep order
            sink_desc = (
                "an embedded script (actions/github-script)"
                if tf.expression.source_field == "with.script"
                else "a run: command"
            )
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.CRITICAL,
                    file=workflow.source_path or "",
                    line=tf.step.line,
                    message=(
                        f"Untrusted {refs} is interpolated directly into {sink_desc}, allowing "
                        "arbitrary shell/script injection from a crafted PR title, issue body, "
                        "comment, or branch name."
                    ),
                    context=f"jobs.{job_id}.steps[{tf.step.index}].{tf.expression.source_field}",
                    fix_hint=(
                        "Pass the value through `env:` and reference it as a shell variable "
                        f"instead of inline interpolation, e.g. `env: {{ USER_INPUT: '${{{{ {tf.tainted_contexts[0]} }}}}' }}` "
                        'then `run: echo "$USER_INPUT"` -- never `run: echo "${{ ... }}"`.'
                    ),
                )
            )
        return findings
