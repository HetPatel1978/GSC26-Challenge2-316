# Evaluation report

Scored against 20 hand-labeled fixtures in `tests/fixtures/eval/` (10 vulnerable across all 8 taxonomy categories, 10 clean), at (file, category) granularity -- see `eval/metrics.py` for why category, not exact rule_id or line, is the scored unit.

| Category | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| script_injection | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| pull_request_target | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| excess_permissions | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| secret_leakage | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| unpinned_action | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| dependency_confusion | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| cache_poisoning | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| self_hosted_runner | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **Overall (micro)** | 12 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **Overall (macro)** | -- | -- | -- | 1.00 | 1.00 | 1.00 |

## Per-file predictions vs. ground truth

| File | Expected | Predicted | Match |
|---|---|---|---|
| vuln_01_script_injection.yml | script_injection | script_injection | yes |
| vuln_02_pull_request_target.yml | pull_request_target | pull_request_target | yes |
| vuln_03_excess_permissions.yml | excess_permissions | excess_permissions | yes |
| vuln_04_secret_leakage.yml | secret_leakage | secret_leakage | yes |
| vuln_05_unpinned_action.yml | unpinned_action | unpinned_action | yes |
| vuln_06_dependency_confusion.yml | dependency_confusion | dependency_confusion | yes |
| vuln_07_cache_poisoning.yml | cache_poisoning | cache_poisoning | yes |
| vuln_08_self_hosted_runner.yml | self_hosted_runner | self_hosted_runner | yes |
| vuln_09_script_injection_github_script.yml | script_injection | script_injection | yes |
| vuln_10_multi_category.yml | excess_permissions, pull_request_target, secret_leakage | excess_permissions, pull_request_target, secret_leakage | yes |
| clean_01_lint.yml | (clean) | (none) | yes |
| clean_02_matrix_tests.yml | (clean) | (none) | yes |
| clean_03_docs_build.yml | (clean) | (none) | yes |
| clean_04_release_oidc.yml | (clean) | (none) | yes |
| clean_05_dependabot_automerge.yml | (clean) | (none) | yes |
| clean_06_docker_build_ghcr.yml | (clean) | (none) | yes |
| clean_07_reusable_workflow.yml | (clean) | (none) | yes |
| clean_08_scheduled_cleanup.yml | (clean) | (none) | yes |
| clean_09_codeql_analysis.yml | (clean) | (none) | yes |
| clean_10_manual_deploy_approval.yml | (clean) | (none) | yes |

## Interpreting this report

A perfect score here means the detectors behave exactly as designed on the patterns this project's own taxonomy defines -- it is a conformance check against hand-labeled ground truth, not an independent measurement of precision/recall on arbitrary real-world code. The fixtures were written with knowledge of the detector logic (the same relationship `tests/test_detectors.py`'s fixtures have to their detectors), so 1.00 here says "the implementation matches its own spec," not "this tool never misses a real vulnerability or never flags a false positive in the wild." For that, see [`docs/REAL_WORLD_FINDINGS.md`](../docs/REAL_WORLD_FINDINGS.md), which runs these same detectors against ten popular public repositories and documents cases where a correctly-triggered rule turned out to have a real-world mitigating factor the detector can't see, and a specific gap (`predictable-cache-key` missing a hardcoded, non-templated cache key in django/django) found only by reading real code.
