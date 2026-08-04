"""Tests for scanner/taint.py -- context classification and sink detection,
independent of any one detector's presentation choices."""

from __future__ import annotations

from scanner.ir import Expression
from scanner.parser import parse_workflow
from scanner.taint import (
    find_injection_sinks,
    is_sink_field,
    is_tainted_context,
    tainted_refs,
)


def test_is_tainted_context_true_for_known_sources():
    assert is_tainted_context("github.event.issue.title")
    assert is_tainted_context("github.event.pull_request.body")
    assert is_tainted_context("github.event.comment.body")
    assert is_tainted_context("github.head_ref")


def test_is_tainted_context_false_for_structurally_safe_fields():
    assert not is_tainted_context("github.repository")
    assert not is_tainted_context("github.sha")
    assert not is_tainted_context("github.event.pull_request.number")
    assert not is_tainted_context("github.actor")


def test_is_tainted_context_matches_regex_patterns():
    assert is_tainted_context("github.event.commits.message")
    assert is_tainted_context("github.event.pusher.email")


def test_tainted_refs_filters_mixed_expression():
    expr = Expression(raw="github.event.issue.title == github.sha", source_field="run")
    refs = tainted_refs(expr)
    assert refs == ["github.event.issue.title"]


def test_is_sink_field():
    assert is_sink_field("run")
    assert is_sink_field("with.script")
    assert not is_sink_field("if")
    assert not is_sink_field("name")
    assert not is_sink_field("env.FOO")


def test_find_injection_sinks_ignores_env_indirection():
    raw = {
        "on": "push",
        "jobs": {
            "safe": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "env": {"TITLE": "${{ github.event.issue.title }}"},
                        "run": 'echo "$TITLE"',
                    }
                ],
            }
        },
    }
    wf = parse_workflow(raw, source_path="safe.yml")
    assert find_injection_sinks(wf) == []


def test_find_injection_sinks_flags_direct_run_interpolation():
    raw = {
        "on": "push",
        "jobs": {
            "unsafe": {
                "runs-on": "ubuntu-latest",
                "steps": [{"run": 'echo "${{ github.event.issue.title }}"'}],
            }
        },
    }
    wf = parse_workflow(raw, source_path="unsafe.yml")
    sinks = find_injection_sinks(wf)
    assert len(sinks) == 1
    job_id, tf = sinks[0]
    assert job_id == "unsafe"
    assert tf.tainted_contexts == ["github.event.issue.title"]
    assert tf.expression.source_field == "run"


def test_find_injection_sinks_flags_github_script_input():
    raw = {
        "on": "push",
        "jobs": {
            "unsafe": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "uses": "actions/github-script@v7",
                        "with": {"script": "console.log('${{ github.event.issue.title }}')"},
                    }
                ],
            }
        },
    }
    wf = parse_workflow(raw, source_path="unsafe.yml")
    sinks = find_injection_sinks(wf)
    assert len(sinks) == 1
    assert sinks[0][1].expression.source_field == "with.script"


def test_find_injection_sinks_ignores_non_sink_fields():
    raw = {
        "on": "push",
        "jobs": {
            "ok": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "if": "${{ github.event.issue.title == 'bug' }}",
                        "name": "${{ github.event.issue.title }}",
                        "run": "echo done",
                    }
                ],
            }
        },
    }
    wf = parse_workflow(raw, source_path="ok.yml")
    assert find_injection_sinks(wf) == []
