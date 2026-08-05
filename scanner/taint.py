"""Taint propagation engine: attacker-controlled github.event.* sources -> run: sinks.

Core technical contribution of this project. Flow-insensitive but
sink-precise: rather than tracking data through arbitrary shell logic, it
answers the one question that actually distinguishes exploitable script
injection from safe interpolation --

    Does a `${{ }}` expression that references attacker-controlled context
    data land *directly* in a field that GitHub Actions hands to a shell or
    script interpreter, as opposed to a field that's merely read (`if:`,
    `name:`) or that goes through `env:` indirection first?

That framing is deliberate: GitHub's own recommended mitigation for script
injection is exactly "assign to env:, then reference as a shell variable",
and that mitigation works *because* the tainted expression then never
appears inside a `${{ }}` in a sink field -- it's substituted by the shell,
not by the Actions runner's expression engine, so it can't break out of
the surrounding command string. Since `Step.expressions()` only reports
`${{ }}` expressions actually present in each field's raw text, an env-
indirected value is simply invisible to `find_injection_sinks` below,
which is exactly the property that makes the mitigation verifiable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from scanner.ir import Expression, Step, Workflow

# Exact dotted context paths that carry attacker-supplied free text on at
# least one trigger event capable of reaching them (issue/PR titles and
# bodies, comment/review bodies, branch names an attacker chooses, commit
# messages on a fork). Kept as an explicit allowlist rather than a blanket
# "anything under github.event.*" rule to hold down false positives on
# fields that are structurally safe (ids, booleans, SHAs, enums).
TAINTED_CONTEXTS: frozenset[str] = frozenset(
    {
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.event.pull_request.head.repo.full_name",
        "github.event.pull_request.head.repo.owner.login",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.review_comment.body",
        "github.event.discussion.title",
        "github.event.discussion.body",
        "github.event.pages.page_name",
        "github.event.workflow_run.head_branch",
        "github.event.workflow_run.head_commit.message",
        "github.event.head_commit.author.email",
        "github.event.head_commit.author.name",
        "github.event.head_commit.message",
        "github.head_ref",
    }
)

# Regex patterns for context paths the exact-match set above can't express
# -- array-indexed accessors (`github.event.commits[0].message`, whose
# `[0]` the IR's dotted-context regex simply skips over, leaving
# `github.event.commits.message`) and per-event "someone's email" fields
# that repeat across several event payloads.
TAINTED_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^github\.event\.commits\.message$"),
    re.compile(r"^github\.event\.\w+\.email$"),
)

# Fields where a raw `${{ }}` substitution becomes shell/script source
# rather than data that's merely read -- `run:` is executed by a shell,
# `with.script` is executed as JS by actions/github-script (and similar
# actions using the same input name).
SINK_FIELDS: frozenset[str] = frozenset({"run", "with.script"})


def is_tainted_context(context_ref: str) -> bool:
    """True if `context_ref` (e.g. "github.event.issue.title") is a known
    attacker-controllable context accessor."""
    if context_ref in TAINTED_CONTEXTS:
        return True
    return any(pattern.match(context_ref) for pattern in TAINTED_PATTERNS)


def tainted_refs(expr: Expression) -> list[str]:
    """Tainted dotted context paths referenced inside `expr`, in order,
    duplicates preserved (a repeated ref is still worth surfacing once per
    occurrence to callers that care about counts)."""
    return [ref for ref in expr.contexts_referenced() if is_tainted_context(ref)]


def is_sink_field(source_field: str) -> bool:
    return source_field in SINK_FIELDS


@dataclass
class TaintFinding:
    """One "tainted expression reaches a sink" instance, before it's turned
    into a `Finding` by `scanner/detectors/injection.py`. Kept separate
    from `Finding` so the taint engine carries no opinion on severity or
    message wording -- that's presentation, decided by the detector.
    """

    expression: Expression
    tainted_contexts: list[str]
    step: Step


def find_injection_sinks(workflow: Workflow) -> list[tuple[str, TaintFinding]]:
    """Walk every job/step in `workflow`; return `(job_id, TaintFinding)`
    for every expression in a sink field that references a tainted
    context, in workflow-document order.
    """
    results: list[tuple[str, TaintFinding]] = []
    for job in workflow.jobs.values():
        for step in job.steps:
            for expr in step.expressions():
                if not is_sink_field(expr.source_field):
                    continue
                refs = tainted_refs(expr)
                if refs:
                    results.append((job.id, TaintFinding(expr, refs, step)))
    return results
