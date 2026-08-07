# Real-world scan summary

Scanned 10 repositories, 218 workflow files, 293 total findings.

| Repo | Files | Findings | Critical | High | Medium | Low | Info | Most common |
|---|---|---|---|---|---|---|---|---|
| tensorflow/tensorflow | 17 | 1 | 0 | 0 | 1 | 0 | 0 | secret-inline-interpolation (1) |
| django/django | 21 | 76 | 0 | 13 | 63 | 0 | 0 | unpinned-action (59) |
| facebook/react | 22 | 193 | 1 | 21 | 171 | 0 | 0 | unpinned-action (171) |
| microsoft/vscode | 16 | 12 | 5 | 3 | 4 | 0 | 0 | self-hosted-runner-fork-trigger (5) |
| pytest-dev/pytest | 6 | 0 | 0 | 0 | 0 | 0 | 0 | - |
| pallets/flask | 5 | 2 | 0 | 2 | 0 | 0 | 0 | cache-poisoning (2) |
| psf/requests | 8 | 1 | 0 | 1 | 0 | 0 | 0 | cache-poisoning (1) |
| numpy/numpy | 23 | 6 | 0 | 6 | 0 | 0 | 0 | cache-poisoning (6) |
| apache/airflow | 50 | 2 | 2 | 0 | 0 | 0 | 0 | secret-echoed-to-log (2) |
| electron/electron | 50 | 0 | 0 | 0 | 0 | 0 | 0 | - |

## Findings by vulnerability type (all repos)

| rule_id | count |
|---|---|
| unpinned-action | 230 |
| cache-poisoning | 46 |
| excess-permissions | 8 |
| self-hosted-runner-fork-trigger | 5 |
| secret-echoed-to-log | 2 |
| secret-inline-interpolation | 1 |
| script-injection | 1 |

## Findings by severity (all repos)

| severity | count |
|---|---|
| critical | 8 |
| high | 46 |
| medium | 239 |
| low | 0 |
| info | 0 |
