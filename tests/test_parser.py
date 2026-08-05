"""Tests for scanner/parser.py, driven by fixtures/*.yml."""

from pathlib import Path

from scanner.ir import PermissionLevel
from scanner.parser import parse_workflow_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load(name: str):
    return parse_workflow_file(str(FIXTURES_DIR / name))


def test_minimal_workflow():
    wf = _load("minimal.yml")

    assert wf.name == "Minimal"
    assert list(wf.on.keys()) == ["push"]
    assert wf.permissions.explicit is False

    assert list(wf.jobs.keys()) == ["build"]
    job = wf.jobs["build"]
    assert job.runs_on == "ubuntu-latest"
    assert job.permissions.explicit is False
    assert len(job.steps) == 1

    step = job.steps[0]
    assert step.run == 'echo "hello"'
    assert step.uses is None
    assert step.index == 0


def test_matrix_build():
    wf = _load("matrix.yml")

    job = wf.jobs["test"]
    assert job.runs_on == "${{ matrix.os }}"
    assert job.strategy is not None
    assert job.strategy.fail_fast is False
    assert job.strategy.max_parallel == 4
    assert job.strategy.matrix["os"] == ["ubuntu-latest", "windows-latest", "macos-latest"]
    assert job.strategy.matrix["python-version"] == ["3.10", "3.11", "3.12"]

    assert [s.uses for s in job.steps] == [
        "actions/checkout@v4",
        "actions/setup-python@v5",
        None,
    ]
    assert job.steps[0].action_ref == ("actions/checkout", "v4")

    setup_python = job.steps[1]
    exprs = setup_python.expressions()
    assert len(exprs) == 1
    assert exprs[0].raw == "matrix.python-version"
    assert exprs[0].source_field == "with.python-version"


def test_reusable_workflow():
    wf = _load("reusable_workflow.yml")

    assert wf.has_trigger("workflow_call")
    assert "environment" in wf.call_inputs
    assert "deploy-token" in wf.call_secrets
    assert "deployment-url" in wf.call_outputs

    setup_job = wf.jobs["setup"]
    assert setup_job.is_reusable_call is True
    assert setup_job.uses == "org/repo/.github/workflows/shared-setup.yml@v1"
    assert setup_job.secrets == "inherit"
    assert setup_job.steps == []

    deploy_job = wf.jobs["deploy"]
    assert deploy_job.is_reusable_call is False
    assert deploy_job.needs == ["setup"]
    assert deploy_job.outputs["url"] == "${{ steps.deploy.outputs.url }}"


def test_permissions_block():
    wf = _load("permissions.yml")

    assert wf.permissions.explicit is True
    assert wf.permissions.scopes["contents"] == PermissionLevel.READ
    assert wf.permissions.scopes["pull-requests"] == PermissionLevel.WRITE

    scoped = wf.jobs["scoped"].permissions
    assert scoped.explicit is True
    assert scoped.scopes["contents"] == PermissionLevel.WRITE
    assert scoped.scopes["id-token"] == PermissionLevel.WRITE

    inherits = wf.jobs["inherits"].permissions
    assert inherits.explicit is False
    assert inherits.scopes == {}

    no_perms = wf.jobs["no-perms-block"].permissions
    assert no_perms.explicit is True
    assert no_perms.scopes == {}


def test_pull_request_target():
    wf = _load("pull_request_target.yml")

    assert wf.has_trigger("pull_request_target")
    trigger = wf.on["pull_request_target"]
    assert trigger.types == ["opened", "synchronize", "reopened"]
    assert trigger.branches == ["main"]

    checkout_step = wf.jobs["build"].steps[0]
    exprs = checkout_step.expressions()
    assert len(exprs) == 1
    assert exprs[0].raw == "github.event.pull_request.head.sha"
    assert exprs[0].source_field == "with.ref"
    assert "github.event.pull_request.head.sha" in exprs[0].contexts_referenced()
