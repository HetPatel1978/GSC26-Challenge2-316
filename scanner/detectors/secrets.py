"""Hardcoded secrets and log-leakage detector.

Three independent checks, all filed under this detector since they're all
"the secrets store isn't being used the way it's meant to be" issues:

1. `hardcoded-secret` -- a literal, recognizable credential shape (vendor
   API key prefix, PEM private key block, a plain `password: "..."`
   assignment) embedded directly in workflow YAML instead of referenced via
   `secrets.*`.
2. `secret-echoed-to-log` / `secret-inline-interpolation` -- a `secrets.*`
   expression interpolated directly into `run:`. GitHub masks *known*
   secret values in the log by exact string match, but that's easy to
   defeat (partial prints, base64, char-by-char echo) and the value is
   still exposed on the runner's process listing either way, so any direct
   inline use is flagged; a command that looks like it prints its own
   arguments (echo/cat/print/curl -v/...) is escalated to critical.
3. `secret-in-url` -- a secret embedded as basic-auth in a URL
   (`https://user:${{ secrets.X }}@host/...`), which tools that consume the
   URL (curl, git) commonly log or persist to disk (e.g. `.netrc`,
   `.git/config`) in full.

Deliberately narrow regexes for (1): generic high-entropy scanning belongs
in a dedicated secret scanner (gitleaks/trufflehog), not this best-effort
static check, and would swamp real findings with false positives on
hashes, SHAs, and base64-encoded non-secrets that show up constantly in CI
logs and YAML.
"""

from __future__ import annotations

import re

from scanner.detectors.base import Detector
from scanner.findings import Finding, Severity
from scanner.ir import Step, Workflow

_LITERAL_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS access key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "generic credential assignment": re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*['"][A-Za-z0-9/+_=-]{16,}['"]"""
    ),
}

_ECHO_LIKE = re.compile(r"(?i)\b(?:echo|print|printf|cat|console\.log|Write-Output|Write-Host)\b")
_SECRETS_EXPR = re.compile(r"\$\{\{\s*secrets\.[\w.-]+\s*\}\}")
_URL_BASIC_AUTH_SECRET = re.compile(r"https?://[^:/\s'\"]+:\$\{\{\s*secrets\.[\w.-]+\s*\}\}@")


def _iter_string_fields(step: Step):
    """Yield (field_name, text) for every string-valued field on `step`
    worth scanning -- run body, `with:` values, `env:` values. Skips
    non-string values (booleans, numbers, nested mappings)."""
    if isinstance(step.run, str):
        yield "run", step.run
    for key, value in step.with_inputs.items():
        if isinstance(value, str):
            yield f"with.{key}", value
    for key, value in step.env.items():
        if isinstance(value, str):
            yield f"env.{key}", value


class SecretLeakageDetector(Detector):
    category = "Secret/token leakage"
    rule_id = "secret-leakage"  # umbrella id; individual findings use a more specific one

    def detect(self, workflow: Workflow) -> list[Finding]:
        findings: list[Finding] = []
        for job in workflow.jobs.values():
            for step in job.steps:
                findings += self._literal_secrets(workflow, job.id, step)
                findings += self._secrets_in_url(workflow, job.id, step)
                findings += self._secrets_echoed(workflow, job.id, step)
        return findings

    def _literal_secrets(self, workflow: Workflow, job_id: str, step: Step) -> list[Finding]:
        out: list[Finding] = []
        for field_name, text in _iter_string_fields(step):
            for kind, pattern in _LITERAL_SECRET_PATTERNS.items():
                if pattern.search(text):
                    out.append(
                        Finding(
                            rule_id="hardcoded-secret",
                            severity=Severity.CRITICAL,
                            file=workflow.source_path or "",
                            line=step.line,
                            message=(
                                f"Literal {kind} embedded directly in `{field_name}` instead of "
                                "a repository/organization secret."
                            ),
                            context=f"jobs.{job_id}.steps[{step.index}].{field_name}",
                            fix_hint=(
                                "Move the value to a GitHub Actions secret and reference it as "
                                "${{ secrets.NAME }}, then rotate the exposed credential."
                            ),
                        )
                    )
        return out

    def _secrets_in_url(self, workflow: Workflow, job_id: str, step: Step) -> list[Finding]:
        out: list[Finding] = []
        for field_name, text in _iter_string_fields(step):
            if _URL_BASIC_AUTH_SECRET.search(text):
                out.append(
                    Finding(
                        rule_id="secret-in-url",
                        severity=Severity.HIGH,
                        file=workflow.source_path or "",
                        line=step.line,
                        message=(
                            f"Secret embedded as basic-auth credentials in a URL in `{field_name}`; "
                            "tools that consume the URL (curl, git) commonly log or persist it in full."
                        ),
                        context=f"jobs.{job_id}.steps[{step.index}].{field_name}",
                        fix_hint=(
                            "Pass the credential via an auth header or a dedicated token flag "
                            "instead of embedding it in the URL string."
                        ),
                    )
                )
        return out

    def _secrets_echoed(self, workflow: Workflow, job_id: str, step: Step) -> list[Finding]:
        if not isinstance(step.run, str) or not _SECRETS_EXPR.search(step.run):
            return []
        escalated = bool(_ECHO_LIKE.search(step.run))
        severity = Severity.CRITICAL if escalated else Severity.MEDIUM
        rule_id = "secret-echoed-to-log" if escalated else "secret-inline-interpolation"
        message = (
            "A secret is interpolated directly into a command that prints its own output, "
            "leaking the secret value to the workflow log."
            if escalated
            else (
                "A secret is interpolated inline into `run:` rather than passed via `env:`, "
                "increasing exposure via process listings and log-masking bypasses."
            )
        )
        return [
            Finding(
                rule_id=rule_id,
                severity=severity,
                file=workflow.source_path or "",
                line=step.line,
                message=message,
                context=f"jobs.{job_id}.steps[{step.index}].run",
                fix_hint=(
                    "Assign the secret to an `env:` var and reference it as a shell variable "
                    "inside `run:`; never echo, print, or log a secret value."
                ),
            )
        ]
