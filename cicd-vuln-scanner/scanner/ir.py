"""Internal representation for a parsed GitHub Actions workflow.

Tree shape: Workflow -> Job -> Step, with Trigger (the `on:` block),
Permissions (the `permissions:` block), and Expression (a single
`${{ ... }}` interpolation) as supporting types.

This module is pure data plus generic structural helpers (expression
extraction, action-ref splitting). Vulnerability-specific logic belongs in
scanner/detectors/, not here, so the IR stays reusable across detectors,
the patcher, and eval tooling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

_EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_CONTEXT_REF_RE = re.compile(r"\b[a-zA-Z_][\w-]*(?:\.[\w-]+)+\b")

# All GITHUB_TOKEN permission scopes GitHub Actions recognizes.
PERMISSION_SCOPES = (
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
)


class PermissionLevel(str, Enum):
    NONE = "none"
    READ = "read"
    WRITE = "write"


@dataclass
class Expression:
    """A single `${{ ... }}` interpolation extracted from some field.

    `source_field` records where it came from (e.g. "run", "if",
    "with.script", "env.FOO") so the taint engine (scanner/taint.py) can
    reason about sinks without re-walking the tree.
    """

    raw: str
    source_field: str

    def contexts_referenced(self) -> list[str]:
        """Dotted context accessors mentioned in this expression, e.g.
        ["github.event.issue.title", "env.FOO"]. Regex-based and
        best-effort — real taint analysis lives in scanner/taint.py.
        """
        return _CONTEXT_REF_RE.findall(self.raw)

    @staticmethod
    def find_all(text: Any, source_field: str) -> list["Expression"]:
        if not isinstance(text, str):
            return []
        return [
            Expression(raw=match.strip(), source_field=source_field)
            for match in _EXPR_RE.findall(text)
        ]


@dataclass
class Permissions:
    """The `permissions:` block of a workflow or a job.

    `explicit` is False when no `permissions:` key was present at all, in
    which case the workflow/job inherits the repository's default token
    permissions (which may be broad) — that absence is itself the signal
    the excess-permissions detector cares about, so we preserve it instead
    of defaulting to a guessed level.

    `blanket` holds "write-all" / "read-all" when `permissions:` was a bare
    string rather than a mapping. `scopes` holds per-scope levels when it
    was a mapping (including an empty mapping, meaning all scopes none).
    """

    explicit: bool = False
    blanket: str | None = None
    scopes: dict[str, PermissionLevel] = field(default_factory=dict)

    def level_for(self, scope: str) -> PermissionLevel:
        if self.blanket == "write-all":
            return PermissionLevel.WRITE
        if self.blanket == "read-all":
            return PermissionLevel.READ
        return self.scopes.get(scope, PermissionLevel.NONE)

    @property
    def any_write(self) -> bool:
        if self.blanket == "write-all":
            return True
        return any(level == PermissionLevel.WRITE for level in self.scopes.values())


@dataclass
class Trigger:
    """One entry of the workflow's `on:` block, normalized to (event, config).

    `on:` may be a bare string, a list of strings, or a mapping of event
    name -> config (null, `{}`, or event-specific filters like `types`,
    `branches`, `paths`). Each form collapses to one Trigger per event.
    """

    event: str
    config: dict[str, Any] = field(default_factory=dict)
    line: int | None = None

    @property
    def types(self) -> list[str]:
        raw = self.config.get("types")
        if raw is None:
            return []
        return raw if isinstance(raw, list) else [raw]

    @property
    def branches(self) -> list[str]:
        raw = self.config.get("branches")
        if raw is None:
            return []
        return raw if isinstance(raw, list) else [raw]


@dataclass
class Step:
    """One entry of a job's `steps:` list."""

    index: int
    id: str | None = None
    name: str | None = None
    if_condition: str | None = None
    uses: str | None = None
    run: str | None = None
    shell: str | None = None
    with_inputs: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    working_directory: str | None = None
    continue_on_error: bool = False
    timeout_minutes: int | None = None
    line: int | None = None

    @property
    def action_ref(self) -> tuple[str, str] | None:
        """Split `uses: org/action@ref` into (org/action, ref).

        None if this isn't a `uses:` step or the ref has no `@`.
        """
        if not self.uses or "@" not in self.uses:
            return None
        name, _, ref = self.uses.rpartition("@")
        return (name, ref)

    def expressions(self) -> list[Expression]:
        """All `${{ }}` expressions in fields relevant to taint analysis."""
        found: list[Expression] = []
        found += Expression.find_all(self.run, "run")
        found += Expression.find_all(self.if_condition, "if")
        found += Expression.find_all(self.name, "name")
        for key, val in self.with_inputs.items():
            found += Expression.find_all(val, f"with.{key}")
        for key, val in self.env.items():
            found += Expression.find_all(val, f"env.{key}")
        return found


@dataclass
class Strategy:
    """A job's `strategy:` block, most commonly used for matrix builds."""

    matrix: dict[str, Any] = field(default_factory=dict)
    fail_fast: bool = True
    max_parallel: int | None = None


@dataclass
class Job:
    """One entry of the workflow's `jobs:` mapping.

    Covers both a normal job (with `steps:`) and a reusable-workflow call
    job (with `uses:` pointing at another workflow file instead of steps).
    """

    id: str
    name: str | None = None
    runs_on: Any = None
    needs: list[str] = field(default_factory=list)
    if_condition: str | None = None
    permissions: Permissions = field(default_factory=Permissions)
    env: dict[str, Any] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)
    strategy: Strategy | None = None
    container: dict[str, Any] | None = None
    services: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)
    timeout_minutes: int | None = None
    continue_on_error: bool = False
    line: int | None = None

    # Reusable-workflow call job: `uses: org/repo/.github/workflows/x.yml@ref`
    uses: str | None = None
    with_inputs: dict[str, Any] = field(default_factory=dict)
    secrets: dict[str, Any] | str | None = None  # mapping, or "inherit"

    @property
    def is_reusable_call(self) -> bool:
        return self.uses is not None

    def all_expressions(self) -> list[Expression]:
        found: list[Expression] = []
        found += Expression.find_all(self.if_condition, "if")
        for step in self.steps:
            found += step.expressions()
        return found


@dataclass
class Workflow:
    """Root of the IR tree for one `.github/workflows/*.yml` file."""

    name: str | None = None
    source_path: str | None = None
    on: dict[str, Trigger] = field(default_factory=dict)
    permissions: Permissions = field(default_factory=Permissions)
    env: dict[str, Any] = field(default_factory=dict)
    defaults: dict[str, Any] = field(default_factory=dict)
    concurrency: dict[str, Any] | str | None = None
    jobs: dict[str, Job] = field(default_factory=dict)

    # Populated when `on:` includes `workflow_call` (this workflow is reusable).
    call_inputs: dict[str, Any] = field(default_factory=dict)
    call_outputs: dict[str, Any] = field(default_factory=dict)
    call_secrets: dict[str, Any] = field(default_factory=dict)

    def has_trigger(self, event: str) -> bool:
        return event in self.on

    def all_steps(self) -> list[tuple[Job, Step]]:
        return [(job, step) for job in self.jobs.values() for step in job.steps]

    def all_expressions(self) -> list[Expression]:
        found: list[Expression] = []
        for job in self.jobs.values():
            found += job.all_expressions()
        return found
