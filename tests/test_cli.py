"""Tests for scanner/cli.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.cli import discover_workflow_files, format_report, main, scan_files

FIXTURES = Path(__file__).parent / "fixtures"


def test_discover_workflow_files_expands_directory():
    files = discover_workflow_files([str(FIXTURES)])
    assert all(f.suffix in (".yml", ".yaml") for f in files)
    names = {f.name for f in files}
    assert "pull_request_target.yml" in names
    assert len(files) == len(set(files))  # deduplicated


def test_discover_workflow_files_accepts_single_file():
    files = discover_workflow_files([str(FIXTURES / "minimal.yml")])
    assert files == [FIXTURES / "minimal.yml"]


def test_discover_workflow_files_raises_on_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        discover_workflow_files([str(tmp_path / "does-not-exist.yml")])


def test_scan_files_reports_parse_error_without_aborting(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("jobs: [this is not a mapping :::", encoding="utf-8")
    good = FIXTURES / "minimal.yml"

    findings = scan_files([bad, good])

    assert any(f.rule_id == "parse-error" and f.file == str(bad) for f in findings)
    assert any(f.file == str(good) for f in findings)


def test_format_report_clean_scan():
    assert format_report([]) == "No findings. Clean scan."


def test_format_report_groups_by_file_and_sorts_by_severity():
    wf = FIXTURES / "pull_request_target.yml"
    findings = scan_files([wf])
    report = format_report(findings)
    # This fixture's `actions/checkout@v4` also trips the unpinned-action
    # detector now that all 8 detectors run, alongside the critical
    # pull-request-target-checkout finding it's here to exercise.
    assert "2 finding(s): 1 medium, 1 critical" in report
    assert "== " in report
    assert "pull-request-target-checkout" in report
    assert "unpinned-action" in report
    assert "fix:" in report


def test_format_report_no_patches_option():
    findings = scan_files([FIXTURES / "pull_request_target.yml"])
    report = format_report(findings, show_patches=False)
    assert "fix:" not in report


def test_main_exit_code_zero_when_clean(capsys):
    code = main([str(FIXTURES / "permissions.yml")])
    assert code == 0


def test_main_exit_code_one_on_high_severity_finding(capsys):
    code = main([str(FIXTURES / "pull_request_target.yml")])
    assert code == 1


def test_main_fail_on_none_always_exits_zero(capsys):
    code = main([str(FIXTURES / "pull_request_target.yml"), "--fail-on", "none"])
    assert code == 0


def test_main_missing_path_exits_two(capsys):
    code = main(["/no/such/path.yml"])
    assert code == 2
    captured = capsys.readouterr()
    assert "No such file or directory" in captured.err


def test_main_writes_sarif_file(tmp_path, capsys):
    sarif_path = tmp_path / "out.sarif"
    code = main(
        [str(FIXTURES / "pull_request_target.yml"), "--sarif", str(sarif_path), "--quiet"]
    )
    assert code == 1
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    # critical pull-request-target-checkout + medium unpinned-action (see
    # test_format_report_groups_by_file_and_sorts_by_severity above).
    assert len(data["runs"][0]["results"]) == 2
    # SARIF URIs are always forward-slash, even on Windows.
    assert "\\" not in data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_main_quiet_suppresses_text_report(capsys):
    main([str(FIXTURES / "pull_request_target.yml"), "--quiet"])
    captured = capsys.readouterr()
    assert captured.out == ""
