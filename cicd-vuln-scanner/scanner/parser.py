"""YAML -> WorkflowIR parsing.

Two responsibilities live here, deliberately kept separate:

1. `load_workflow_yaml` — parse workflow YAML text into a plain dict,
   using a custom PyYAML loader (`_LineLoader`) that fixes a correctness
   bug and adds line tracking (see class docstring below).
2. `parse_workflow` — walk that dict into a `scanner.ir.Workflow` tree,
   filling in defaults for every optional field GitHub Actions allows to
   be omitted.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from yaml.resolver import BaseResolver

from scanner.ir import (
    Job,
    Permissions,
    PermissionLevel,
    Step,
    Strategy,
    Trigger,
    Workflow,
)


class _LineDict(dict):
    """dict subclass carrying the 1-based source line of the YAML mapping
    node it was built from, as the `__line__` *attribute* (not a dict key —
    it must not show up in `.items()`/`.keys()` or it would corrupt normal
    iteration over env vars, permission scopes, matrix values, etc.).
    """

    __line__: int = 0


class _LineLoader(yaml.SafeLoader):
    """SafeLoader with two fixes needed to correctly parse GitHub Actions
    workflow YAML:

    1. YAML 1.1 (PyYAML's default) resolves bare `on`, `off`, `yes`, `no` as
       booleans. Every workflow file has a top-level `on:` key, which would
       silently parse as the key `True` instead of the string "on" — a
       well-known PyYAML/GitHub-Actions footgun. We narrow boolean
       resolution to `true`/`false` only, matching YAML 1.2 behavior.
    2. Track the source line of every mapping node so IR objects can report
       `line` for findings without a second parse pass.
    """


def _construct_mapping_with_lines(loader: yaml.SafeLoader, node: yaml.MappingNode):
    data = _LineDict()
    data.__line__ = node.start_mark.line + 1
    yield data
    data.update(loader.construct_mapping(node, deep=True))


_LineLoader.add_constructor(BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_with_lines)

_LineLoader.yaml_implicit_resolvers = {
    first_char: [pair for pair in resolvers if pair[0] != "tag:yaml.org,2002:bool"]
    for first_char, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_BOOL_RE = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
for _ch in "tTfF":
    _LineLoader.yaml_implicit_resolvers.setdefault(_ch, []).append(
        ("tag:yaml.org,2002:bool", _BOOL_RE)
    )


def _line_of(node: Any) -> int | None:
    return getattr(node, "__line__", None)


def load_workflow_yaml(text: str) -> dict:
    """Parse raw workflow YAML text into a dict, with line tracking.

    Returns {} for an empty document (GitHub tolerates but ignores these).
    """
    data = yaml.load(text, Loader=_LineLoader)
    return data or {}


def parse_workflow_file(path: str) -> Workflow:
    """Convenience wrapper: read a workflow file from disk and parse it."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_workflow(load_workflow_yaml(text), source_path=str(path))


def _stringify_condition(value: Any) -> str | None:
    """`if:` conditions are usually strings, but a bare `if: false` or
    `if: true` parses as a YAML bool rather than a string. Normalize to str
    so `Step.if_condition` / `Job.if_condition` always hold the same type.
    """
    if value is None:
        return None
    return str(value)


def _parse_permissions(raw_permissions: Any) -> Permissions:
    if raw_permissions is None:
        return Permissions(explicit=False)
    if isinstance(raw_permissions, str):
        return Permissions(explicit=True, blanket=raw_permissions)
    if isinstance(raw_permissions, dict):
        scopes: dict[str, PermissionLevel] = {}
        for scope, level in raw_permissions.items():
            try:
                scopes[scope] = PermissionLevel(level)
            except ValueError:
                continue
        return Permissions(explicit=True, scopes=scopes)
    return Permissions(explicit=False)


def _parse_on(raw_on: Any) -> dict[str, Trigger]:
    if raw_on is None:
        return {}
    if isinstance(raw_on, str):
        return {raw_on: Trigger(event=raw_on)}
    if isinstance(raw_on, list):
        return {event: Trigger(event=event) for event in raw_on}
    if isinstance(raw_on, dict):
        triggers: dict[str, Trigger] = {}
        for event, config in raw_on.items():
            config_dict = config if isinstance(config, dict) else {}
            triggers[event] = Trigger(
                event=event,
                config=config_dict,
                line=_line_of(config) if isinstance(config, dict) else None,
            )
        return triggers
    return {}


def _parse_container(raw_container: Any) -> dict[str, Any] | None:
    """`container:` may be a bare image-name string (shorthand for
    `{image: <name>}`) or a full mapping."""
    if raw_container is None:
        return None
    if isinstance(raw_container, str):
        return {"image": raw_container}
    return raw_container


def _parse_strategy(raw_strategy: Any) -> Strategy | None:
    if not raw_strategy:
        return None
    return Strategy(
        matrix=raw_strategy.get("matrix") or {},
        fail_fast=bool(raw_strategy.get("fail-fast", True)),
        max_parallel=raw_strategy.get("max-parallel"),
    )


def _parse_step(raw_step: Any, index: int) -> Step:
    raw_step = raw_step or {}
    return Step(
        index=index,
        id=raw_step.get("id"),
        name=raw_step.get("name"),
        if_condition=_stringify_condition(raw_step.get("if")),
        uses=raw_step.get("uses"),
        run=raw_step.get("run"),
        shell=raw_step.get("shell"),
        with_inputs=raw_step.get("with") or {},
        env=raw_step.get("env") or {},
        working_directory=raw_step.get("working-directory"),
        continue_on_error=bool(raw_step.get("continue-on-error", False)),
        timeout_minutes=raw_step.get("timeout-minutes"),
        line=_line_of(raw_step),
    )


def _parse_job(job_id: str, raw_job: Any) -> Job:
    raw_job = raw_job or {}

    needs = raw_job.get("needs") or []
    if isinstance(needs, str):
        needs = [needs]

    raw_steps = raw_job.get("steps") or []
    steps = [_parse_step(raw_step, i) for i, raw_step in enumerate(raw_steps)]

    return Job(
        id=job_id,
        name=raw_job.get("name"),
        runs_on=raw_job.get("runs-on"),
        needs=needs,
        if_condition=_stringify_condition(raw_job.get("if")),
        permissions=_parse_permissions(raw_job.get("permissions")),
        env=raw_job.get("env") or {},
        steps=steps,
        strategy=_parse_strategy(raw_job.get("strategy")),
        container=_parse_container(raw_job.get("container")),
        services=raw_job.get("services") or {},
        outputs=raw_job.get("outputs") or {},
        timeout_minutes=raw_job.get("timeout-minutes"),
        continue_on_error=bool(raw_job.get("continue-on-error", False)),
        uses=raw_job.get("uses"),
        with_inputs=raw_job.get("with") or {},
        secrets=raw_job.get("secrets"),
        line=_line_of(raw_job),
    )


def parse_workflow(raw: dict, source_path: str | None = None) -> Workflow:
    """Build a `Workflow` IR from a parsed YAML mapping.

    `raw` is expected to come from `load_workflow_yaml` (for line-number
    support) but plain `yaml.safe_load` output works too — `line` fields
    will just stay None.
    """
    raw = raw or {}

    workflow = Workflow(
        name=raw.get("name"),
        source_path=source_path,
        on=_parse_on(raw.get("on")),
        permissions=_parse_permissions(raw.get("permissions")),
        env=raw.get("env") or {},
        defaults=raw.get("defaults") or {},
        concurrency=raw.get("concurrency"),
    )

    raw_jobs = raw.get("jobs") or {}
    for job_id, raw_job in raw_jobs.items():
        workflow.jobs[job_id] = _parse_job(job_id, raw_job)

    call_trigger = workflow.on.get("workflow_call")
    if call_trigger is not None:
        workflow.call_inputs = call_trigger.config.get("inputs") or {}
        workflow.call_outputs = call_trigger.config.get("outputs") or {}
        workflow.call_secrets = call_trigger.config.get("secrets") or {}

    return workflow
