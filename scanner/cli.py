"""CLI runner: parse workflow file(s), run every detector, and report.

    python -m scanner.cli path/to/workflow.yml [more paths...] [options]

Paths may be individual `.yml`/`.yaml` files or directories, in which case
every `.yml`/`.yaml` file under the directory is scanned recursively.
Always prints a human-readable report to stdout; `--sarif PATH` additionally
writes a SARIF 2.1.0 file for tools that consume that format (GitHub code
scanning, most CI security dashboards). Exit code is nonzero when any
finding at or above `--fail-on` (default: high) is present, so this doubles
as a CI gate: `scanner scan .github/workflows/ --fail-on high`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scanner.detectors import DEFAULT_DETECTORS
from scanner.detectors.base import run_all
from scanner.findings import Finding, SARIFExporter, Severity
from scanner.parser import parse_workflow_file
from scanner.patcher import suggest_patch

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def discover_workflow_files(paths: list[str]) -> list[Path]:
    """Expand `paths` (files or directories) into a sorted, deduplicated
    list of workflow file paths. Directories are scanned recursively for
    `*.yml`/`*.yaml`."""
    files: set[Path] = set()
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files.update(p.rglob("*.yml"))
            files.update(p.rglob("*.yaml"))
        elif p.is_file():
            files.add(p)
        else:
            raise FileNotFoundError(f"No such file or directory: {raw}")
    return sorted(files)


def scan_files(paths: list[Path]) -> list[Finding]:
    """Parse and run every default detector over each file, in path order.
    A file that fails to parse is reported as a single INFO finding rather
    than aborting the whole scan, so one malformed workflow doesn't hide
    findings in every other file passed on the command line."""
    findings: list[Finding] = []
    detectors = list(DEFAULT_DETECTORS)
    for path in paths:
        try:
            workflow = parse_workflow_file(str(path))
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any parse failure
            findings.append(
                Finding(
                    rule_id="parse-error",
                    severity=Severity.INFO,
                    file=str(path),
                    line=None,
                    message=f"Failed to parse workflow file: {exc}",
                )
            )
            continue
        findings.extend(run_all(detectors, workflow))
    return findings


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    return counts


def format_report(findings: list[Finding], *, show_patches: bool = True) -> str:
    """Human-readable report: a summary line, then findings grouped by
    file, most severe first within each file."""
    lines: list[str] = []
    counts = _severity_counts(findings)
    total = len(findings)

    if total == 0:
        return "No findings. Clean scan."

    summary = ", ".join(
        f"{counts[s]} {_SEVERITY_LABEL[s].lower()}" for s in reversed(list(Severity)) if counts[s]
    )
    lines.append(f"{total} finding(s): {summary}")
    lines.append("")

    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for file in sorted(by_file):
        lines.append(f"== {file} ==")
        file_findings = sorted(
            by_file[file], key=lambda f: _SEVERITY_ORDER[f.severity], reverse=True
        )
        for f in file_findings:
            location = f"line {f.line}" if f.line is not None else "(no line)"
            lines.append(f"  [{_SEVERITY_LABEL[f.severity]}] {f.rule_id} @ {location}")
            lines.append(f"    {f.message}")
            if f.context:
                lines.append(f"    context: {f.context}")
            if show_patches:
                patch = suggest_patch(f)
                lines.append(f"    fix: {patch.summary}")
        lines.append("")

    return "\n".join(lines).rstrip("\n")


def write_sarif(findings: list[Finding], path: Path) -> None:
    path.write_text(SARIFExporter(findings).to_json(), encoding="utf-8")


def _parse_severity(value: str) -> Severity | None:
    if value == "none":
        return None
    try:
        return Severity(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid severity {value!r}; choose from: critical, high, medium, low, info, none"
        ) from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Static vulnerability scanner for GitHub Actions CI/CD workflows.",
    )
    parser.add_argument("paths", nargs="+", help="Workflow file(s) or directory/directories to scan")
    parser.add_argument("--sarif", metavar="PATH", help="Write SARIF 2.1.0 output to PATH")
    parser.add_argument(
        "--fail-on",
        type=_parse_severity,
        default=Severity.HIGH,
        metavar="SEVERITY",
        help="Exit nonzero if any finding at or above this severity is present "
        "(critical, high, medium, low, info, or 'none' to always exit 0). Default: high.",
    )
    parser.add_argument("--no-patches", action="store_true", help="Omit fix suggestions from the text report")
    parser.add_argument("--quiet", action="store_true", help="Suppress the text report (still writes --sarif if given)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        files = discover_workflow_files(args.paths)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if not files:
        print("No .yml/.yaml workflow files found.", file=sys.stderr)
        return 2

    findings = scan_files(files)

    if not args.quiet:
        print(format_report(findings, show_patches=not args.no_patches))

    if args.sarif:
        write_sarif(findings, Path(args.sarif))

    if args.fail_on is None:
        return 0
    threshold = _SEVERITY_ORDER[args.fail_on]
    if any(_SEVERITY_ORDER[f.severity] >= threshold for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
