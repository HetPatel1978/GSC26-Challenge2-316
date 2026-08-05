"""Dependency confusion detector.

Heuristic, static-only checks for CI install patterns known to be
exploitable via dependency confusion (publishing a malicious package under
an internal-looking name to a public registry, then relying on the
resolver to prefer the highest-versioned copy regardless of which index it
came from):

1. `pip-extra-index-url` -- `pip install ... --extra-index-url <url>`.
   pip's classic resolution compares versions across *every* configured
   index and installs the highest match it finds, including the public
   PyPI default -- the textbook dependency-confusion primitive, and the
   exact mechanism in the original 2021 research (Birsan) that named the
   class.
2. `unscoped-private-package` -- `npm install <name>` in a step that also
   configures a scoped private registry (`npm config set @scope:registry=`
   or an equivalent `.npmrc` line) but installs a *different*, unscoped
   package name in the same command -- that unscoped name still resolves
   against the public npm registry, not the private one.
"""

from __future__ import annotations

import re

from scanner.detectors.base import Detector
from scanner.findings import Finding, Severity
from scanner.ir import Step, Workflow

_PIP_EXTRA_INDEX = re.compile(r"\bpip3?\s+install\b[^\n]*--extra-index-url\b")
_NPM_SCOPED_REGISTRY = re.compile(r"(@[\w.-]+):registry=")
_NPM_INSTALL_LINE = re.compile(r"^npm\s+(?:ci|install|i)\b(.*)$")


class DependencyConfusionDetector(Detector):
    category = "Dependency confusion"
    rule_id = "dependency-confusion"

    def detect(self, workflow: Workflow) -> list[Finding]:
        findings: list[Finding] = []
        for job in workflow.jobs.values():
            for step in job.steps:
                if not isinstance(step.run, str):
                    continue
                findings += self._pip_extra_index(workflow, job.id, step)
                findings += self._npm_unscoped(workflow, job.id, step)
        return findings

    def _pip_extra_index(self, workflow: Workflow, job_id: str, step: Step) -> list[Finding]:
        assert isinstance(step.run, str)
        if not _PIP_EXTRA_INDEX.search(step.run):
            return []
        return [
            Finding(
                rule_id="pip-extra-index-url",
                severity=Severity.MEDIUM,
                file=workflow.source_path or "",
                line=step.line,
                message=(
                    "`pip install --extra-index-url` lets pip choose the highest-versioned "
                    "match across all configured indexes, including the public PyPI default -- "
                    "a malicious package published there under an internal package's name can win."
                ),
                context=f"jobs.{job_id}.steps[{step.index}].run",
                fix_hint=(
                    "Use `--index-url` to fully replace the default index for internal "
                    "packages, or pin exact versions with `--require-hashes`, or configure "
                    "per-package index priority."
                ),
            )
        ]

    def _npm_unscoped(self, workflow: Workflow, job_id: str, step: Step) -> list[Finding]:
        assert isinstance(step.run, str)
        scopes = _NPM_SCOPED_REGISTRY.findall(step.run)
        if not scopes:
            return []

        out: list[Finding] = []
        for line in step.run.splitlines():
            match = _NPM_INSTALL_LINE.match(line.strip())
            if not match:
                continue
            for token in match.group(1).split():
                if token.startswith("-"):
                    continue
                pkg = token.split("@", 1)[0] if not token.startswith("@") else token
                if pkg and not pkg.startswith("@"):
                    out.append(
                        Finding(
                            rule_id="unscoped-private-package",
                            severity=Severity.MEDIUM,
                            file=workflow.source_path or "",
                            line=step.line,
                            message=(
                                f"`npm install {pkg}` installs an unscoped package name even "
                                f"though this step configures a scoped private registry "
                                f"({', '.join(sorted(set(scopes)))}); an unscoped name still "
                                "resolves against the public npm registry."
                            ),
                            context=f"jobs.{job_id}.steps[{step.index}].run",
                            fix_hint=(
                                f"Publish/install the internal package under one of the "
                                f"configured scopes (e.g. `{sorted(set(scopes))[0]}/{pkg}`) so "
                                "resolution is unambiguous."
                            ),
                        )
                    )
        return out
