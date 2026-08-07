# Semgrep baseline comparison

Both tools scored against the same 20 hand-labeled fixtures in `tests/fixtures/eval/`, semgrep using its public `p/github-actions` ruleset. See `baselines/run_semgrep.py` for the rule_id -> category mapping and why 5 of semgrep's 12 rules in this pack (curl|bash execution, deprecated workflow commands, a known-worm IOC signature) fall outside this project's 8-category scope entirely rather than being "missed."

| Category | Ours P/R/F1 | Semgrep P/R/F1 | Ours TP/FP/FN | Semgrep TP/FP/FN |
|---|---|---|---|---|
| script_injection | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 2/0/0 | 2/0/0 |
| pull_request_target | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 2/0/0 | 2/0/0 |
| excess_permissions | 1.00/1.00/1.00 | 0.00/0.00/0.00 | 2/0/0 | 0/0/2 |
| secret_leakage | 1.00/1.00/1.00 | 0.00/0.00/0.00 | 2/0/0 | 0/0/2 |
| unpinned_action | 1.00/1.00/1.00 | 1.00/1.00/1.00 | 1/0/0 | 1/0/0 |
| dependency_confusion | 1.00/1.00/1.00 | 0.00/0.00/0.00 | 1/0/0 | 0/0/1 |
| cache_poisoning | 1.00/1.00/1.00 | 0.00/0.00/0.00 | 1/0/0 | 0/0/1 |
| self_hosted_runner | 1.00/1.00/1.00 | 0.00/0.00/0.00 | 1/0/0 | 0/0/1 |
| **Overall (micro)** | 1.00/1.00/1.00 | 1.00/0.42/0.59 | 12/0/0 | 5/0/7 |

## Categories semgrep's p/github-actions pack doesn't attempt

No rule in this ruleset maps to: excess_permissions, dependency_confusion, cache_poisoning, self_hosted_runner. Semgrep's recall on these is structurally 0 via this pack -- not a detection failure on a specific case, an absence of any rule that tries.

Attempted but missed on this fixture set (a rule exists for the category, but didn't match the specific pattern in our labeled example): secret_leakage.

## Where the two tools disagree, per file

| File | Expected | We catch, semgrep misses | Semgrep catches, we miss |
|---|---|---|---|
| vuln_03_excess_permissions.yml | excess_permissions | excess_permissions | - |
| vuln_04_secret_leakage.yml | secret_leakage | secret_leakage | - |
| vuln_06_dependency_confusion.yml | dependency_confusion | dependency_confusion | - |
| vuln_07_cache_poisoning.yml | cache_poisoning | cache_poisoning | - |
| vuln_08_self_hosted_runner.yml | self_hosted_runner | self_hosted_runner | - |
| vuln_10_multi_category.yml | excess_permissions, pull_request_target, secret_leakage | excess_permissions, secret_leakage | - |

## Semgrep findings outside this project's taxonomy

(none fired on this fixture set)
