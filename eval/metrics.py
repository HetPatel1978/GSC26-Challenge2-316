"""Precision/recall/F1 evaluation harness.

Scores `scanner.detectors.DEFAULT_DETECTORS` against
`tests/fixtures/eval/` -- 10 hand-crafted vulnerable workflows (covering
all 8 taxonomy categories, two categories represented twice) and 10
hand-crafted clean workflows, each realistic enough to plausibly be an
actual CI config rather than a one-line toy case.

Ground truth lives in `tests/fixtures/eval/labels.json`: for each
fixture, the list of taxonomy categories that fixture is deliberately
vulnerable to (empty for the clean ones). Category, not exact rule_id or
line number, is the scored unit -- the 8 taxonomy categories are the
coverage this project promises, per-rule true/false-positive cases
already have dedicated unit tests in `tests/test_detectors.py`, and
pinning eval ground truth to exact line numbers would make it brittle to
incidental formatting without testing anything beyond what those unit
tests already cover.

    python -m eval.metrics    # print + write results/eval_report.md
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scanner.detectors import DEFAULT_DETECTORS  # noqa: E402
from scanner.detectors.base import run_all  # noqa: E402
from scanner.parser import parse_workflow_file  # noqa: E402

FIXTURES_DIR = _ROOT / "tests" / "fixtures" / "eval"
LABELS_PATH = FIXTURES_DIR / "labels.json"
REPORT_PATH = _ROOT / "results" / "eval_report.md"

# Maps every rule_id a detector can emit to the taxonomy.md category it
# belongs to. Kept here rather than derived from Detector.category because
# several detectors emit more than one specific rule_id under a single
# category (see e.g. secrets.py's hardcoded-secret / secret-echoed-to-log
# / secret-inline-interpolation / secret-in-url), and this mapping is the
# evaluation's ground-truth vocabulary, not the detectors' own bookkeeping.
RULE_ID_TO_CATEGORY: dict[str, str] = {
    "script-injection": "script_injection",
    "pull-request-target-checkout": "pull_request_target",
    "excess-permissions": "excess_permissions",
    "hardcoded-secret": "secret_leakage",
    "secret-echoed-to-log": "secret_leakage",
    "secret-inline-interpolation": "secret_leakage",
    "secret-in-url": "secret_leakage",
    "unpinned-action": "unpinned_action",
    "pip-extra-index-url": "dependency_confusion",
    "unscoped-private-package": "dependency_confusion",
    "cache-poisoning": "cache_poisoning",
    "predictable-cache-key": "cache_poisoning",
    "self-hosted-runner-fork-trigger": "self_hosted_runner",
}

CATEGORIES: tuple[str, ...] = (
    "script_injection",
    "pull_request_target",
    "excess_permissions",
    "secret_leakage",
    "unpinned_action",
    "dependency_confusion",
    "cache_poisoning",
    "self_hosted_runner",
)


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def load_labels() -> dict[str, list[str]]:
    return json.loads(LABELS_PATH.read_text(encoding="utf-8"))


def predicted_categories(path: Path) -> set[str]:
    """Every taxonomy category `DEFAULT_DETECTORS` flags in the workflow
    at `path`, deduplicated (a file can trip a category via more than one
    finding, e.g. both cache-poisoning and predictable-cache-key -- that
    still counts as one (file, category) prediction)."""
    workflow = parse_workflow_file(str(path))
    findings = run_all(list(DEFAULT_DETECTORS), workflow)
    return {RULE_ID_TO_CATEGORY[f.rule_id] for f in findings if f.rule_id in RULE_ID_TO_CATEGORY}


@dataclass
class EvalResult:
    per_category: dict[str, Counts]
    overall: Counts
    per_file_predictions: dict[str, set[str]]
    per_file_labels: dict[str, list[str]]


def evaluate() -> EvalResult:
    labels = load_labels()
    per_category: dict[str, Counts] = {cat: Counts() for cat in CATEGORIES}
    per_file_predictions: dict[str, set[str]] = {}

    for filename, expected in labels.items():
        predicted = predicted_categories(FIXTURES_DIR / filename)
        per_file_predictions[filename] = predicted
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

    overall = Counts(
        tp=sum(c.tp for c in per_category.values()),
        fp=sum(c.fp for c in per_category.values()),
        fn=sum(c.fn for c in per_category.values()),
    )
    return EvalResult(
        per_category=per_category,
        overall=overall,
        per_file_predictions=per_file_predictions,
        per_file_labels=labels,
    )


def format_report(result: EvalResult) -> str:
    lines: list[str] = ["# Evaluation report", ""]
    lines.append(
        f"Scored against {len(result.per_file_labels)} hand-labeled fixtures in "
        "`tests/fixtures/eval/` (10 vulnerable across all 8 taxonomy categories, "
        "10 clean), at (file, category) granularity -- see `eval/metrics.py` for why "
        "category, not exact rule_id or line, is the scored unit."
    )
    lines.append("")
    lines.append("| Category | TP | FP | FN | Precision | Recall | F1 |")
    lines.append("|---|---|---|---|---|---|---|")
    for cat in CATEGORIES:
        c = result.per_category[cat]
        lines.append(
            f"| {cat} | {c.tp} | {c.fp} | {c.fn} | {c.precision:.2f} | {c.recall:.2f} | {c.f1:.2f} |"
        )
    o = result.overall
    macro_p = sum(result.per_category[c].precision for c in CATEGORIES) / len(CATEGORIES)
    macro_r = sum(result.per_category[c].recall for c in CATEGORIES) / len(CATEGORIES)
    macro_f1 = sum(result.per_category[c].f1 for c in CATEGORIES) / len(CATEGORIES)
    lines.append(
        f"| **Overall (micro)** | {o.tp} | {o.fp} | {o.fn} | {o.precision:.2f} | "
        f"{o.recall:.2f} | {o.f1:.2f} |"
    )
    lines.append(f"| **Overall (macro)** | -- | -- | -- | {macro_p:.2f} | {macro_r:.2f} | {macro_f1:.2f} |")
    lines.append("")

    lines.append("## Per-file predictions vs. ground truth")
    lines.append("")
    lines.append("| File | Expected | Predicted | Match |")
    lines.append("|---|---|---|---|")
    for filename, expected in result.per_file_labels.items():
        predicted_sorted = sorted(result.per_file_predictions[filename])
        expected_sorted = sorted(expected)
        match = "yes" if set(predicted_sorted) == set(expected_sorted) else "no"
        exp_str = ", ".join(expected_sorted) if expected_sorted else "(clean)"
        pred_str = ", ".join(predicted_sorted) if predicted_sorted else "(none)"
        lines.append(f"| {filename} | {exp_str} | {pred_str} | {match} |")
    lines.append("")

    lines.append("## Interpreting this report")
    lines.append("")
    lines.append(
        "A perfect score here means the detectors behave exactly as designed on the "
        "patterns this project's own taxonomy defines -- it is a conformance check "
        "against hand-labeled ground truth, not an independent measurement of "
        "precision/recall on arbitrary real-world code. The fixtures were written "
        "with knowledge of the detector logic (the same relationship "
        "`tests/test_detectors.py`'s fixtures have to their detectors), so 1.00 here "
        "says \"the implementation matches its own spec,\" not \"this tool never "
        "misses a real vulnerability or never flags a false positive in the wild.\" "
        "For that, see [`docs/REAL_WORLD_FINDINGS.md`](../docs/REAL_WORLD_FINDINGS.md), "
        "which runs these same detectors against ten popular public repositories "
        "and documents cases where a correctly-triggered rule turned out to have a "
        "real-world mitigating factor the detector can't see, and a specific gap "
        "(`predictable-cache-key` missing a hardcoded, non-templated cache key in "
        "django/django) found only by reading real code."
    )
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    result = evaluate()
    report = format_report(result)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
