"""Scan a fixed set of popular public repositories for GitHub Actions
vulnerabilities -- an external validation signal beyond the hand-written
fixtures in tests/fixtures/.

Each repo is shallow- and sparse-cloned (`--depth 1 --filter=blob:none
--sparse`, checkout restricted to `.github/workflows/`) so the run stays
fast and small regardless of the target repo's actual size -- cloning all
ten repos below this way takes seconds and a few megabytes, not the
multi-gigabyte full histories those projects actually have. Every
workflow file found is scanned with the full `DEFAULT_DETECTORS` suite
(the same code path `scanner.cli` uses), one SARIF file per repo is
written to `results/real_world_scan/`, and a markdown summary (per-repo
and aggregate severity/rule_id breakdowns) is written alongside it.

    python scripts/scan_real_repos.py
    python scripts/scan_real_repos.py --repos pallets/flask psf/requests
    python scripts/scan_real_repos.py --keep-clones   # skip cleanup, for debugging
"""

from __future__ import annotations

import argparse
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from scanner.cli import discover_workflow_files, scan_files  # noqa: E402
from scanner.findings import Finding, SARIFExporter, Severity  # noqa: E402

# Ten well-known, actively maintained open source projects, chosen to span
# several ecosystems (Python, JS/TS, C++, Go-adjacent tooling) and known in
# advance (via a throwaway sparse-checkout probe) to actually carry
# `.github/workflows/` -- some equally famous candidates (torvalds/linux,
# kubernetes/kubernetes, golang/go, ansible/ansible) use other CI systems
# (mailing lists, Prow, etc.) and have no workflows to scan at all.
REPOS: list[str] = [
    "tensorflow/tensorflow",
    "django/django",
    "facebook/react",
    "microsoft/vscode",
    "pytest-dev/pytest",
    "pallets/flask",
    "psf/requests",
    "numpy/numpy",
    "apache/airflow",
    "electron/electron",
]

RESULTS_DIR = _ROOT / "results" / "real_world_scan"

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _slug(repo: str) -> str:
    return repo.replace("/", "__")


def _onerror_force_writable(func, path, exc_info):  # noqa: ANN001
    """shutil.rmtree onerror hook: .git's object files are read-only on
    Windows, which makes plain rmtree fail on them -- clear the read-only
    bit and retry the same operation once."""
    import os

    os.chmod(path, stat.S_IWRITE)
    func(path)


def clone_workflows(repo: str, dest: Path) -> Path | None:
    """Shallow+sparse clone `repo`'s `.github/workflows/` into `dest`.

    Returns `dest` on success, or None if the clone/checkout failed or the
    repo simply has no workflows directory (not an error -- plenty of
    large, popular repos use a different CI system entirely).
    """
    url = f"https://github.com/{repo}.git"
    clone = subprocess.run(
        ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", url, str(dest)],
        capture_output=True,
        text=True,
    )
    if clone.returncode != 0:
        print(f"  ! clone failed: {clone.stderr.strip()[:200]}", file=sys.stderr)
        return None

    sparse = subprocess.run(
        ["git", "-C", str(dest), "sparse-checkout", "set", ".github/workflows"],
        capture_output=True,
        text=True,
    )
    if sparse.returncode != 0:
        print(f"  ! sparse-checkout failed: {sparse.stderr.strip()[:200]}", file=sys.stderr)
        return None

    if not (dest / ".github" / "workflows").is_dir():
        return None
    return dest


@dataclass
class RepoResult:
    repo: str
    files_scanned: int
    findings: list[Finding]


def scan_repo(repo: str, workdir: Path) -> RepoResult | None:
    dest = workdir / _slug(repo)
    root = clone_workflows(repo, dest)
    if root is None:
        return None

    wf_dir = root / ".github" / "workflows"
    files = discover_workflow_files([str(wf_dir)])
    findings = scan_files(files)

    # Rewrite absolute temp-clone paths to a stable "owner/repo/..." form
    # so the committed SARIF/summary output doesn't embed this machine's
    # temp directory layout and reads the same on any machine.
    for f in findings:
        try:
            rel = Path(f.file).relative_to(root)
        except ValueError:
            rel = Path(f.file).name
        f.file = f"{repo}/{Path(rel).as_posix()}"

    return RepoResult(repo=repo, files_scanned=len(files), findings=findings)


def _severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {s.value: counts.get(s.value, 0) for s in _SEVERITY_ORDER}


def _rule_breakdown(findings: list[Finding]) -> Counter:
    return Counter(f.rule_id for f in findings if f.rule_id != "parse-error")


def format_summary(results: list[RepoResult]) -> str:
    all_findings: list[Finding] = []
    for r in results:
        all_findings += r.findings

    lines: list[str] = ["# Real-world scan summary", ""]
    lines.append(
        f"Scanned {len(results)} repositories, "
        f"{sum(r.files_scanned for r in results)} workflow files, "
        f"{len(all_findings)} total findings."
    )
    lines.append("")
    lines.append("| Repo | Files | Findings | Critical | High | Medium | Low | Info | Most common |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for r in results:
        sev = _severity_breakdown(r.findings)
        rule_counts = _rule_breakdown(r.findings)
        top = rule_counts.most_common(1)
        top_desc = f"{top[0][0]} ({top[0][1]})" if top else "-"
        lines.append(
            f"| {r.repo} | {r.files_scanned} | {len(r.findings)} | {sev['critical']} | "
            f"{sev['high']} | {sev['medium']} | {sev['low']} | {sev['info']} | {top_desc} |"
        )
    lines.append("")

    overall_rules = _rule_breakdown(all_findings)
    lines.append("## Findings by vulnerability type (all repos)")
    lines.append("")
    lines.append("| rule_id | count |")
    lines.append("|---|---|")
    for rule_id, count in overall_rules.most_common():
        lines.append(f"| {rule_id} | {count} |")
    lines.append("")

    overall_sev = _severity_breakdown(all_findings)
    lines.append("## Findings by severity (all repos)")
    lines.append("")
    lines.append("| severity | count |")
    lines.append("|---|---|")
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {sev.value} | {overall_sev[sev.value]} |")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repos", nargs="*", default=REPOS, help="owner/repo list to scan")
    parser.add_argument(
        "--keep-clones", action="store_true", help="Don't delete cloned repos after scanning (debugging)"
    )
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="cicd-vuln-scanner-realworld-"))
    print(f"Working directory: {workdir}")

    results: list[RepoResult] = []
    try:
        for repo in args.repos:
            print(f"== {repo} ==")
            result = scan_repo(repo, workdir)
            if result is None:
                print("  skipped (no .github/workflows/ found, or clone failed)")
                continue
            print(f"  {result.files_scanned} workflow file(s), {len(result.findings)} finding(s)")
            results.append(result)

            sarif_path = RESULTS_DIR / f"{_slug(repo)}.sarif"
            sarif_path.write_text(SARIFExporter(result.findings).to_json(), encoding="utf-8")
    finally:
        if not args.keep_clones:
            try:
                shutil.rmtree(workdir, onerror=_onerror_force_writable)
            except OSError as exc:
                print(f"warning: failed to clean up {workdir}: {exc}", file=sys.stderr)

    summary = format_summary(results)
    (RESULTS_DIR / "summary.md").write_text(summary, encoding="utf-8")
    print()
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
