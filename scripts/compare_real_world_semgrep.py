"""Semgrep vs. this scanner, on the same 10 real public repositories.

`results/semgrep_comparison.md` (`baselines/run_semgrep.py`) compares the
two tools on the 20 self-authored fixtures in `tests/fixtures/eval/` --
useful as a regression check, but the ground truth there was written with
full knowledge of both tools' rules, which is exactly the kind of
self-grading a skeptical reviewer should distrust. This script instead
runs both tools against the same real, independently-authored code
already used for `docs/REAL_WORLD_FINDINGS.md` (the ten repos in
`scripts/scan_real_repos.py`) -- code that was written with no knowledge
of either tool's rules at all.

Neither tool has a labeled ground truth on this code, so this does not
compute precision/recall the way `eval/metrics.py` and
`baselines/run_semgrep.py` do. What it reports instead: raw finding
counts per taxonomy category from each tool, and every case where the two
tools structurally disagree on the same file -- which is the honest,
independent signal this project didn't have before.

    python scripts/compare_real_world_semgrep.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from baselines.run_semgrep import (  # noqa: E402
    RULESET,
    SEMGREP_RULE_TO_CATEGORY,
    find_semgrep,
    run_semgrep,
)
from eval.metrics import CATEGORIES, RULE_ID_TO_CATEGORY  # noqa: E402
from scanner.cli import discover_workflow_files, scan_files  # noqa: E402
from scripts.scan_real_repos import REPOS, _onerror_force_writable, _slug, clone_workflows  # noqa: E402

REPORT_PATH = _ROOT / "results" / "semgrep_real_world_comparison.md"


@dataclass
class RepoComparison:
    repo: str
    files_scanned: int
    our_categories: Counter = field(default_factory=Counter)
    semgrep_categories: Counter = field(default_factory=Counter)
    semgrep_unmapped: Counter = field(default_factory=Counter)
    our_file_categories: dict[str, set[str]] = field(default_factory=dict)
    semgrep_file_categories: dict[str, set[str]] = field(default_factory=dict)


def compare_repo(repo: str, workdir: Path, semgrep_bin: str) -> RepoComparison | None:
    dest = workdir / _slug(repo)
    root = clone_workflows(repo, dest)
    if root is None:
        return None
    wf_dir = root / ".github" / "workflows"
    files = discover_workflow_files([str(wf_dir)])
    if not files:
        return None

    result = RepoComparison(repo=repo, files_scanned=len(files))

    for f in scan_files(files):
        category = RULE_ID_TO_CATEGORY.get(f.rule_id)
        if category is None:  # e.g. parse-error
            continue
        result.our_categories[category] += 1
        rel = Path(f.file).relative_to(root).as_posix()
        result.our_file_categories.setdefault(rel, set()).add(category)

    semgrep_json = run_semgrep(semgrep_bin, files)
    for r in semgrep_json.get("results", []):
        check_id = r["check_id"]
        path = Path(r["path"])
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()
        category = SEMGREP_RULE_TO_CATEGORY.get(check_id)
        if category:
            result.semgrep_categories[category] += 1
            result.semgrep_file_categories.setdefault(rel, set()).add(category)
        else:
            result.semgrep_unmapped[check_id] += 1

    return result


def format_report(results: list[RepoComparison]) -> str:
    lines: list[str] = ["# Semgrep vs. this scanner -- real-world repositories", ""]
    lines.append(
        f"Both tools run against the identical clone of each of the same {len(results)} "
        "repositories used in `docs/REAL_WORLD_FINDINGS.md` (semgrep with its public "
        f"`{RULESET}` ruleset). Unlike `results/semgrep_comparison.md`, there is no "
        "hand-written label set here -- this is raw finding counts and structural "
        "disagreement on code neither tool's rules had any influence over, not a "
        "precision/recall claim."
    )
    lines.append("")

    total_files = sum(r.files_scanned for r in results)
    our_total = sum(sum(r.our_categories.values()) for r in results)
    semgrep_total = sum(sum(r.semgrep_categories.values()) for r in results)
    semgrep_unmapped_total = sum(sum(r.semgrep_unmapped.values()) for r in results)
    lines.append(
        f"**{total_files} workflow files across {len(results)} repos.** Ours: "
        f"{our_total} findings mapped to the 8 taxonomy categories. Semgrep: "
        f"{semgrep_total} findings mapped to those same 8 categories, plus "
        f"{semgrep_unmapped_total} findings in categories outside this project's scope "
        "entirely (see below)."
    )
    lines.append("")

    lines.append("## Per-category totals, all 10 repos combined")
    lines.append("")
    lines.append("| Category | Ours | Semgrep |")
    lines.append("|---|---|---|")
    for cat in CATEGORIES:
        ours = sum(r.our_categories.get(cat, 0) for r in results)
        theirs = sum(r.semgrep_categories.get(cat, 0) for r in results)
        lines.append(f"| {cat} | {ours} | {theirs} |")
    lines.append(f"| **Total** | {our_total} | {semgrep_total} |")
    lines.append("")

    categories_with_a_rule = set(SEMGREP_RULE_TO_CATEGORY.values())
    no_coverage = [cat for cat in CATEGORIES if cat not in categories_with_a_rule]
    lines.append(
        "Semgrep has no rule at all (not "
        "\"didn't find any,\" no rule that attempts it) for: "
        + ", ".join(no_coverage)
        + ". Those rows are structurally 0 for semgrep regardless of what's in the code."
    )
    lines.append("")

    lines.append("## Per-repo breakdown")
    lines.append("")
    lines.append("| Repo | Files | Ours | Semgrep |")
    lines.append("|---|---|---|---|")
    for r in results:
        lines.append(
            f"| {r.repo} | {r.files_scanned} | {sum(r.our_categories.values())} | "
            f"{sum(r.semgrep_categories.values())} |"
        )
    lines.append("")

    lines.append("## Where the two tools disagree on the same file")
    lines.append("")
    lines.append(
        "Restricted to the 4 categories semgrep has at least one rule for "
        "(`script_injection`, `pull_request_target`, `secret_leakage`, `unpinned_action`) "
        "-- the other 4 always show as \"we flag, semgrep doesn't\" simply because "
        "semgrep never attempts them, which isn't a meaningful disagreement and is "
        "already covered above. This table is restricted to cases where both tools "
        "*could* have flagged the same thing and didn't."
    )
    lines.append("")
    lines.append("| Repo | File | We flag, semgrep doesn't | Semgrep flags, we don't |")
    lines.append("|---|---|---|---|")
    any_rows = False
    for r in results:
        all_files = sorted(set(r.our_file_categories) | set(r.semgrep_file_categories))
        for filename in all_files:
            ours = {c for c in r.our_file_categories.get(filename, set()) if c in categories_with_a_rule}
            theirs = {c for c in r.semgrep_file_categories.get(filename, set()) if c in categories_with_a_rule}
            we_only = sorted(ours - theirs)
            they_only = sorted(theirs - ours)
            if not we_only and not they_only:
                continue
            any_rows = True
            lines.append(
                f"| {r.repo} | {filename} | {', '.join(we_only) or '-'} | "
                f"{', '.join(they_only) or '-'} |"
            )
    if not any_rows:
        lines.append("| (no disagreements) | | | |")
    lines.append("")

    lines.append("## What the disagreements actually are")
    lines.append("")
    lines.append(
        "Counting rows isn't enough to know which tool is right, so four "
        "representative disagreements were read by hand:"
    )
    lines.append("")
    lines.append(
        "1. **`secrets: inherit` -- a real gap in our coverage.** Semgrep's "
        "`secrets-inherit` rule fired 13 times in electron/electron alone (mostly "
        "`.github/workflows/build.yml`), flagging reusable-workflow calls that pass "
        "*every* secret the caller has to the called workflow, violating least "
        "privilege. Nothing in this project's 8 categories checks for `secrets: "
        "inherit` at all -- a legitimate, real pattern this scanner should probably "
        "grow a 9th category for."
    )
    lines.append(
        "2. **Workflow-level `env:` holding a secret -- also a real gap.** Semgrep's "
        "`gha-workflow-env-secret` rule caught apache/airflow's `ci-amd.yml` (lines 62, "
        "65) placing `${{ secrets.* }}` in the *workflow-level* `env:` block, making it "
        "available to every job and step in the file. `scanner/detectors/secrets.py` "
        "only inspects step-level `run:`/`with:`/`env:` text, so a workflow-level `env:` "
        "block is currently invisible to it -- a second real, specific gap, not a false "
        "positive on semgrep's part."
    )
    lines.append(
        "3. **Taint doesn't cross `workflow_call` input boundaries.** Semgrep flagged "
        "`facebook/react/.github/workflows/shared_check_maintainer.yml` (line 33) for "
        "interpolating `${{ inputs.actor }}` directly into a `with.script` sink. "
        "`scanner/taint.py`'s `TAINTED_CONTEXTS` only covers `github.event.*` and "
        "`github.head_ref` -- it has no model at all for whether a reusable workflow's "
        "`inputs:` were populated from a tainted source by the caller. Whether this "
        "specific instance is exploitable depends on how `actor` gets set at the call "
        "site (out of scope of the single file semgrep and we both see); either way, "
        "input-boundary taint tracking is a real, named limitation this project doesn't "
        "currently have and semgrep's rule is more conservative about."
    )
    lines.append(
        "4. **The inverse case: semgrep is arguably over-broad here.** Semgrep flagged "
        "`tensorflow/tensorflow/.github/workflows/release-branch-cherrypick.yml` (line 57) "
        "for interpolating `${{ github.event.inputs.git_commit }}` into `run:`. That "
        "context is a `workflow_dispatch` input, which can only be populated by someone "
        "with write access to the repository triggering the workflow manually -- not by "
        "an anonymous forked PR the way `github.event.issue.title` or `.pull_request.body` "
        "can be. `scanner/taint.py`'s `TAINTED_CONTEXTS` allowlist was built to cover "
        "fork-reachable event fields (PR/issue/comment/review text) and simply never "
        "included `workflow_dispatch` inputs -- not flagging them wasn't a deliberate, "
        "reasoned exclusion in the code, but it happens to be the more precise call here: "
        "an input only a trusted, write-access operator can populate isn't "
        "\"attacker-controlled\" in the same sense the rest of the allowlist is. Worth "
        "documenting as the actual reasoning going forward, since right now it's correct "
        "by omission rather than by design."
    )
    lines.append("")

    lines.append("## Semgrep findings outside this project's taxonomy")
    lines.append("")
    lines.append(
        "Rules in `p/github-actions` that check for real issues this project's 8 "
        "categories don't attempt at all (curl\\|bash execution, deprecated workflow "
        "commands, a known-worm IOC signature -- see `baselines/run_semgrep.py`)."
    )
    lines.append("")
    overall_unmapped: Counter = Counter()
    for r in results:
        overall_unmapped.update(r.semgrep_unmapped)
    if overall_unmapped:
        lines.append("| Rule | Count |")
        lines.append("|---|---|")
        for rule_id, count in overall_unmapped.most_common():
            lines.append(f"| {rule_id} | {count} |")
    else:
        lines.append("(none fired across any of the 10 repos)")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    semgrep_bin = find_semgrep()
    workdir = Path(tempfile.mkdtemp(prefix="cicd-vuln-scanner-semgrep-realworld-"))
    print(f"Working directory: {workdir}")

    results: list[RepoComparison] = []
    try:
        for repo in REPOS:
            print(f"== {repo} ==")
            result = compare_repo(repo, workdir, semgrep_bin)
            if result is None:
                print("  skipped (no .github/workflows/ found, or clone failure)")
                continue
            print(
                f"  {result.files_scanned} file(s) -- ours: "
                f"{sum(result.our_categories.values())}, semgrep: "
                f"{sum(result.semgrep_categories.values())}"
            )
            results.append(result)
    finally:
        try:
            shutil.rmtree(workdir, onerror=_onerror_force_writable)
        except OSError as exc:
            print(f"warning: failed to clean up {workdir}: {exc}", file=sys.stderr)

    report = format_report(results)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print()
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
