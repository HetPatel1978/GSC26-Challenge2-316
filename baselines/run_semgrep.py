"""Semgrep baseline comparison.

Runs semgrep's public `p/github-actions` ruleset against the same 20
hand-labeled fixtures `eval/metrics.py` scores this project's own
detectors against (`tests/fixtures/eval/`, ground truth in
`tests/fixtures/eval/labels.json`), computes the same precision/recall/F1
per taxonomy category, and writes a side-by-side comparison to
`results/semgrep_comparison.md`.

Semgrep is deliberately **not** in `requirements.txt`: installing it
alongside this project's own dependencies pulled in `opentelemetry-*`,
`click`, and `mcp` version bumps that conflicted with unrelated tooling
already in this environment during development. Install it in its own
throwaway virtualenv instead:

    python -m venv .venv-semgrep
    .venv-semgrep/bin/pip install semgrep          # or Scripts\\pip.exe on Windows
    python baselines/run_semgrep.py                # run with the *project's* Python, not .venv-semgrep's

This script itself needs the project's own dependencies (`scanner`,
`eval`) importable, so run it with the same Python/environment as
everything else in this repo -- it only shells out to semgrep as a
subprocess (looking for an executable in `.venv-semgrep/` first, then
falling back to whatever `semgrep` is on `PATH`), never imports it as a
library, so the two environments never need to mix.

Fixtures are passed to semgrep as an explicit file list, not a directory:
`semgrep --config p/github-actions <directory>` scans zero files in this
repo layout (it reported "Files matching .semgrepignore patterns: 21" and
skipped everything) even with no `.semgrepignore` present and
`--no-git-ignore` passed, for reasons that didn't repay further digging;
pointing it at each file explicitly reliably scans all 20.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from eval.metrics import CATEGORIES, FIXTURES_DIR, Counts, evaluate, load_labels  # noqa: E402

REPORT_PATH = _ROOT / "results" / "semgrep_comparison.md"
RULESET = "p/github-actions"

# Every rule_id in p/github-actions that maps onto one of this project's 8
# taxonomy categories, built empirically by running the full ruleset
# (12 yaml rules as of semgrep 1.172.0 / this ruleset's pinned revision)
# against tests/fixtures/eval/ and reading what each rule actually checks.
# Rules with no entry here (curl-eval, gha-curl-pipe-shell,
# detect-shai-hulud-backdoor, allowed-unsecure-commands,
# unsafe-add-mask-workflow-command) check for real issues outside this
# project's 8-category scope entirely -- they're not "missed" categories,
# they're categories this project doesn't attempt, and are reported
# separately rather than silently dropped.
SEMGREP_RULE_TO_CATEGORY: dict[str, str] = {
    "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag": "unpinned_action",
    "yaml.github-actions.security.github-script-injection.github-script-injection": "script_injection",
    "yaml.github-actions.security.run-shell-injection.run-shell-injection": "script_injection",
    "yaml.github-actions.security.pull-request-target-code-checkout.pull-request-target-code-checkout": "pull_request_target",
    "yaml.github-actions.security.workflow-run-target-code-checkout.workflow-run-target-code-checkout": "pull_request_target",
    "yaml.github-actions.security.gha-workflow-env-secret.gha-workflow-env-secret": "secret_leakage",
    "yaml.github-actions.security.secrets-inherit.secrets-inherit": "secret_leakage",
}


def find_semgrep() -> str:
    for candidate in (
        _ROOT / ".venv-semgrep" / "Scripts" / "semgrep.exe",  # Windows venv
        _ROOT / ".venv-semgrep" / "bin" / "semgrep",  # POSIX venv
    ):
        if candidate.is_file():
            return str(candidate)
    on_path = shutil.which("semgrep")
    if on_path:
        return on_path
    raise RuntimeError(
        "semgrep not found. Install it in an isolated venv first:\n"
        "  python -m venv .venv-semgrep\n"
        "  .venv-semgrep/bin/pip install semgrep   # or Scripts\\pip.exe on Windows"
    )


def run_semgrep(semgrep_bin: str, files: list[Path]) -> dict:
    result = subprocess.run(
        [semgrep_bin, "--config", RULESET, "--json", "--metrics=off", *[str(f) for f in files]],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode not in (0, 1):  # 1 == findings present, still valid output
        raise RuntimeError(f"semgrep failed (exit {result.returncode}): {result.stderr[:2000]}")
    return json.loads(result.stdout)


def predicted_categories_by_file(semgrep_json: dict) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Returns (mapped, unmapped): for each filename, the set of taxonomy
    categories semgrep flagged, and separately the set of raw rule_ids
    that fired but fall outside this project's 8 categories."""
    mapped: dict[str, set[str]] = {}
    unmapped: dict[str, set[str]] = {}
    for r in semgrep_json.get("results", []):
        filename = Path(r["path"]).name
        check_id = r["check_id"]
        category = SEMGREP_RULE_TO_CATEGORY.get(check_id)
        if category:
            mapped.setdefault(filename, set()).add(category)
        else:
            unmapped.setdefault(filename, set()).add(check_id)
    return mapped, unmapped


def score(labels: dict[str, list[str]], predictions: dict[str, set[str]]) -> dict[str, Counts]:
    per_category: dict[str, Counts] = {cat: Counts() for cat in CATEGORIES}
    for filename, expected in labels.items():
        predicted = predictions.get(filename, set())
        expected_set = set(expected)
        for cat in CATEGORIES:
            is_pred = cat in predicted
            is_exp = cat in expected_set
            if is_pred and is_exp:
                per_category[cat].tp += 1
            elif is_pred and not is_exp:
                per_category[cat].fp += 1
            elif not is_pred and is_exp:
                per_category[cat].fn += 1
    return per_category


def format_comparison(
    our_scores: dict[str, Counts],
    semgrep_scores: dict[str, Counts],
    labels: dict[str, list[str]],
    our_predictions: dict[str, set[str]],
    semgrep_predictions: dict[str, set[str]],
    semgrep_unmapped: dict[str, set[str]],
) -> str:
    lines: list[str] = ["# Semgrep baseline comparison", ""]
    lines.append(
        f"Both tools scored against the same {len(labels)} hand-labeled fixtures in "
        f"`tests/fixtures/eval/`, semgrep using its public `{RULESET}` ruleset. "
        "See `baselines/run_semgrep.py` for the rule_id -> category mapping and why "
        "5 of semgrep's 12 rules in this pack (curl|bash execution, deprecated "
        "workflow commands, a known-worm IOC signature) fall outside this project's "
        "8-category scope entirely rather than being \"missed.\""
    )
    lines.append("")
    lines.append("| Category | Ours P/R/F1 | Semgrep P/R/F1 | Ours TP/FP/FN | Semgrep TP/FP/FN |")
    lines.append("|---|---|---|---|---|")
    for cat in CATEGORIES:
        o, s = our_scores[cat], semgrep_scores[cat]
        lines.append(
            f"| {cat} | {o.precision:.2f}/{o.recall:.2f}/{o.f1:.2f} | "
            f"{s.precision:.2f}/{s.recall:.2f}/{s.f1:.2f} | {o.tp}/{o.fp}/{o.fn} | {s.tp}/{s.fp}/{s.fn} |"
        )
    our_overall = Counts(
        tp=sum(c.tp for c in our_scores.values()),
        fp=sum(c.fp for c in our_scores.values()),
        fn=sum(c.fn for c in our_scores.values()),
    )
    semgrep_overall = Counts(
        tp=sum(c.tp for c in semgrep_scores.values()),
        fp=sum(c.fp for c in semgrep_scores.values()),
        fn=sum(c.fn for c in semgrep_scores.values()),
    )
    lines.append(
        f"| **Overall (micro)** | {our_overall.precision:.2f}/{our_overall.recall:.2f}/{our_overall.f1:.2f} | "
        f"{semgrep_overall.precision:.2f}/{semgrep_overall.recall:.2f}/{semgrep_overall.f1:.2f} | "
        f"{our_overall.tp}/{our_overall.fp}/{our_overall.fn} | "
        f"{semgrep_overall.tp}/{semgrep_overall.fp}/{semgrep_overall.fn} |"
    )
    lines.append("")

    lines.append("## Categories semgrep's p/github-actions pack doesn't attempt")
    lines.append("")
    categories_with_a_rule = set(SEMGREP_RULE_TO_CATEGORY.values())
    no_coverage = [cat for cat in CATEGORIES if cat not in categories_with_a_rule]
    if no_coverage:
        lines.append(
            "No rule in this ruleset maps to: " + ", ".join(no_coverage) + ". "
            "Semgrep's recall on these is structurally 0 via this pack -- not a "
            "detection failure on a specific case, an absence of any rule that tries."
        )
    else:
        lines.append("(none -- every category had at least one semgrep rule attempt it)")
    lines.append("")
    attempted_but_missed = [
        cat
        for cat in CATEGORIES
        if cat in categories_with_a_rule and semgrep_scores[cat].tp == 0 and semgrep_scores[cat].fn > 0
    ]
    if attempted_but_missed:
        lines.append(
            "Attempted but missed on this fixture set (a rule exists for the category, "
            "but didn't match the specific pattern in our labeled example): "
            + ", ".join(attempted_but_missed)
            + "."
        )
        lines.append("")

    lines.append("## Where the two tools disagree, per file")
    lines.append("")
    lines.append("| File | Expected | We catch, semgrep misses | Semgrep catches, we miss |")
    lines.append("|---|---|---|---|")
    any_disagreement = False
    for filename, expected in labels.items():
        ours = our_predictions.get(filename, set())
        theirs = semgrep_predictions.get(filename, set())
        we_only = sorted(ours - theirs)
        they_only = sorted(theirs - ours)
        if not we_only and not they_only:
            continue
        any_disagreement = True
        exp_str = ", ".join(sorted(expected)) if expected else "(clean)"
        lines.append(
            f"| {filename} | {exp_str} | {', '.join(we_only) or '-'} | {', '.join(they_only) or '-'} |"
        )
    if not any_disagreement:
        lines.append("| (no disagreements within the 8 shared categories) | | | |")
    lines.append("")

    lines.append("## Semgrep findings outside this project's taxonomy")
    lines.append("")
    if semgrep_unmapped:
        lines.append("| File | Rule (unmapped) |")
        lines.append("|---|---|")
        for filename, rule_ids in semgrep_unmapped.items():
            for rule_id in sorted(rule_ids):
                lines.append(f"| {filename} | {rule_id} |")
    else:
        lines.append("(none fired on this fixture set)")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    semgrep_bin = find_semgrep()
    labels = load_labels()
    files = [FIXTURES_DIR / filename for filename in labels]

    semgrep_json = run_semgrep(semgrep_bin, files)
    semgrep_predictions, semgrep_unmapped = predicted_categories_by_file(semgrep_json)
    semgrep_scores = score(labels, semgrep_predictions)

    our_result = evaluate()
    our_predictions = {f: cats for f, cats in our_result.per_file_predictions.items()}
    our_scores = our_result.per_category

    report = format_comparison(
        our_scores, semgrep_scores, labels, our_predictions, semgrep_predictions, semgrep_unmapped
    )
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
