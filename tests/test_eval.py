"""Regression test for eval/metrics.py: if a future detector change
silently breaks one of the 20 hand-labeled tests/fixtures/eval/ cases (or
the labels.json ground truth drifts out of sync with them), this fails
loudly instead of only showing up as a changed number in results/eval_report.md.
"""

from __future__ import annotations

from eval.metrics import CATEGORIES, evaluate


def test_eval_fixtures_match_ground_truth_exactly():
    result = evaluate()
    for category in CATEGORIES:
        counts = result.per_category[category]
        assert counts.fp == 0, f"{category}: unexpected false positive(s) on eval fixtures"
        assert counts.fn == 0, f"{category}: unexpected false negative(s) on eval fixtures"


def test_eval_covers_all_eight_categories_in_vulnerable_fixtures():
    result = evaluate()
    covered = {cat for expected in result.per_file_labels.values() for cat in expected}
    assert covered == set(CATEGORIES)


def test_eval_has_ten_vulnerable_and_ten_clean_fixtures():
    result = evaluate()
    vulnerable = [f for f, labels in result.per_file_labels.items() if labels]
    clean = [f for f, labels in result.per_file_labels.items() if not labels]
    assert len(vulnerable) == 10
    assert len(clean) == 10
