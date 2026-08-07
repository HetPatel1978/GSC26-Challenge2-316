# cicd-vuln-scanner

Static vulnerability scanner for GitHub Actions CI/CD workflows. Built for
IEEE Computer Society Global Student Challenge 2026 — Challenge 2.

## Problem statement

GitHub Actions workflows are executable code with access to repository
secrets and, often, write access to the repository itself — but they're
authored as YAML, reviewed like config, and rarely threat-modeled like the
code they actually are. A handful of misuse patterns show up constantly in
real-world workflows and each one is enough on its own to fully compromise
a repository or its CI infrastructure from an untrusted pull request:

1. **Script injection** — attacker-controlled `github.event.*` text (a PR
   title, an issue comment, a branch name) interpolated directly into a
   `run:` step, executed as shell.
2. **`pull_request_target` misuse** — a workflow trigger that runs with the
   base repo's secrets and token, combined with checking out and executing
   the fork's untrusted PR content.
3. **Excess `GITHUB_TOKEN` permissions** — no explicit `permissions:`
   block (silently inheriting a possibly broad default) or `write-all`.
4. **Secret/token leakage** — hardcoded credentials, secrets echoed to
   logs, secrets embedded in URLs.
5. **Unpinned third-party actions** — `uses: org/action@v4` (mutable tag)
   instead of a pinned commit SHA.
6. **Dependency confusion** — install patterns (`pip --extra-index-url`,
   unscoped private package names) that let a public-registry package
   masquerade as an internal one.
7. **Cache poisoning** — writing to the Actions cache from a
   fork-triggered `pull_request` job, which a later privileged base-branch
   run can then restore and trust.
8. **Self-hosted runner misuse** — `runs-on: self-hosted` in a workflow
   triggered by `pull_request` or `pull_request_target`, letting forked
   PRs execute on persistent self-hosted infrastructure.

This scanner parses workflow YAML into a structured IR, runs a rule-based
detector per category (backed by a small taint-tracking engine for the
injection case), and reports findings as both a human-readable report and
SARIF 2.1.0 (the format GitHub code scanning and most CI security
dashboards consume), with a suggested before/after patch for each finding.

Full detection logic, taint sources/sinks, vulnerable/safe examples,
false-positive reasoning, and a real CVE or incident per category lives in
[`taxonomy.md`](taxonomy.md) and the docstring at the top of each detector
module. The scanner has also been run against ten popular public
repositories (not just hand-written fixtures) — see [Real-world
results](#real-world-results) below and
[`docs/REAL_WORLD_FINDINGS.md`](docs/REAL_WORLD_FINDINGS.md).

## Architecture

```
scanner/ir.py               Workflow/Job/Step/Expression dataclasses (the IR)
scanner/parser.py           YAML -> IR, with line tracking for findings
scanner/taint.py            Tainted-context classification + sink detection
scanner/findings.py         Finding, Severity, SARIF export
scanner/patcher.py          Before/after patch suggestion per rule_id
scanner/cli.py              CLI entry point (scan -> report + SARIF)
scanner/detectors/
  base.py                   Detector ABC
  injection.py               #1 script injection (uses taint.py)
  pull_request_target.py     #2 pull_request_target misuse
  permissions.py              #3 excess GITHUB_TOKEN permissions
  secrets.py                  #4 secret/token leakage
  pinning.py                  #5 unpinned third-party actions
  dependency_confusion.py     #6 dependency confusion
  cache_poisoning.py          #7 cache poisoning
  runner.py                   #8 self-hosted runner misuse
eval/metrics.py              Precision/recall/F1 harness against tests/fixtures/eval/
baselines/run_semgrep.py     Same harness run against semgrep's p/github-actions ruleset
scripts/scan_real_repos.py   Scans 10 popular public repos, writes results/real_world_scan/
docs/REAL_WORLD_FINDINGS.md  Deep dives on the interesting real findings above
results/                     Generated output: SARIF, eval report, semgrep comparison
```

Each detector is a pure function of the IR (`Workflow -> list[Finding]`),
so they run in any order, compose freely, and are unit-tested in isolation
against fixtures in `tests/fixtures/`.

## Setup

```bash
pip install -r requirements.txt
```

The scanner itself only needs `pyyaml` and the standard library.
`eval/metrics.py` and `scripts/scan_real_repos.py` need nothing beyond
this file either. The rest of `requirements.txt` (anthropic, pandas,
matplotlib, PyGithub, ...) belongs to the LLM-assisted patching and
corpus-collection tooling under `patcher/` and `collect/`, which remain
not-yet-implemented scaffolding — see Known limitations.
`baselines/run_semgrep.py` needs `semgrep`, deliberately installed
separately (see that script's docstring for why).

## Running

```bash
# Scan one file, or a directory (recursively finds *.yml / *.yaml)
python -m scanner.cli path/to/workflow.yml
python -m scanner.cli .github/workflows/

# Also write a SARIF report
python -m scanner.cli .github/workflows/ --sarif results.sarif

# Use as a CI gate: nonzero exit if any finding >= the given severity
python -m scanner.cli .github/workflows/ --fail-on high

# Text report only, no inline fix suggestions
python -m scanner.cli .github/workflows/ --no-patches
```

Exit codes: `0` clean (or nothing at/above `--fail-on`), `1` findings
at/above `--fail-on` (default: `high`), `2` bad arguments / no files found.

### Example output

```
$ python -m scanner.cli tests/fixtures/pull_request_target.yml tests/fixtures/script_injection.yml --fail-on none

4 finding(s): 2 medium, 2 critical

== tests/fixtures/pull_request_target.yml ==
  [CRITICAL] pull-request-target-checkout @ line 12
    `pull_request_target` workflow checks out the fork PR's head content, combining base-repo
    secrets/token access with untrusted code -- any later step that builds, tests, or otherwise
    executes that checkout runs attacker-controlled code with privileged access.
    context: jobs.build.steps[0].with.ref
    fix: Stop checking out the fork PR's head content in a privileged trigger.
  [MEDIUM] unpinned-action @ line 12
    `actions/checkout@v4` is pinned to a mutable ref, not a commit SHA -- whoever controls that
    tag or branch can repoint it to different content at any time, and the next run of this
    workflow executes whatever it now resolves to.
    context: jobs.build.steps[0].uses
    fix: Pin the action to a full commit SHA instead of a mutable tag.

== tests/fixtures/script_injection.yml ==
  [CRITICAL] script-injection @ line 9
    Untrusted github.event.comment.body is interpolated directly into a run: command, allowing
    arbitrary shell/script injection from a crafted PR title, issue body, comment, or branch name.
    context: jobs.unsafe.steps[0].run
    fix: Break the interpolation by routing through env: indirection.
  [MEDIUM] excess-permissions @ (no line)
    No `permissions:` block at workflow or job level; GITHUB_TOKEN falls back to the
    repository/organization default, which may grant broad read/write access to every step
    in every job.
    context: (workflow-level)
    fix: Add an explicit, minimal permissions: block.
```

`--sarif results.sarif` on the same input produces a standard SARIF 2.1.0
document (`scanner.findings.SARIFExporter`) suitable for upload via
`github/codeql-action/upload-sarif` or any SARIF-consuming dashboard.

### Real-world demo

The example above uses this project's own test fixtures. Here's the same
CLI, unmodified, run against `django/django`'s actual, currently-live
`.github/workflows/benchmark.yml` (fetched straight from GitHub, saved
locally, nothing edited):

```
$ python -m scanner.cli django-django-benchmark.yml --fail-on none

3 finding(s): 2 medium, 1 high

== django-django-benchmark.yml ==
  [HIGH] cache-poisoning @ line 30
    `actions/cache` writes to the Actions cache in a `pull_request`-triggered job; GitHub's cache restore rules let a same-branch-hierarchy base-branch run later restore an entry written by a forked PR run, letting a malicious PR poison what a privileged build later trusts.
    context: jobs.Run_benchmarks.steps[3]
    fix: Don't write cache from fork-triggered pull_request jobs.
  [MEDIUM] unpinned-action @ line 16
    `actions/checkout@v7` is pinned to a mutable ref, not a commit SHA -- whoever controls that tag or branch can repoint it to different content at any time, and the next run of this workflow executes whatever it now resolves to.
    context: jobs.Run_benchmarks.steps[0].uses
    fix: Pin the action to a full commit SHA instead of a mutable tag.
  [MEDIUM] unpinned-action @ line 30
    `actions/cache@v6` is pinned to a mutable ref, not a commit SHA -- whoever controls that tag or branch can repoint it to different content at any time, and the next run of this workflow executes whatever it now resolves to.
    context: jobs.Run_benchmarks.steps[3].uses
    fix: Pin the action to a full commit SHA instead of a mutable tag.
```

The full write-up for this file — including why the `if:` label gate and
the content-hash-free cache key matter, and a real gap this exposed in
the `predictable-cache-key` sub-rule — is in
[`docs/REAL_WORLD_FINDINGS.md`](docs/REAL_WORLD_FINDINGS.md#5-djangodjango----cache-poisoning-with-a-maximally-predictable-key).

## Real-world results

`scripts/scan_real_repos.py` shallow/sparse-clones ten popular, actively
maintained open source repositories and scans every `.github/workflows/`
file in each with the full detector suite — an external check beyond this
project's own fixtures.

| Repo | Files | Findings | Critical | High | Medium | Most common |
|---|---|---|---|---|---|---|
| tensorflow/tensorflow | 17 | 1 | 0 | 0 | 1 | secret-inline-interpolation |
| django/django | 21 | 76 | 0 | 13 | 63 | unpinned-action |
| facebook/react | 22 | 193 | 1 | 21 | 171 | unpinned-action |
| microsoft/vscode | 16 | 12 | 5 | 3 | 4 | self-hosted-runner-fork-trigger |
| pytest-dev/pytest | 6 | 0 | 0 | 0 | 0 | -- |
| pallets/flask | 5 | 2 | 0 | 2 | 0 | cache-poisoning |
| psf/requests | 8 | 1 | 0 | 1 | 0 | cache-poisoning |
| numpy/numpy | 23 | 6 | 0 | 6 | 0 | cache-poisoning |
| apache/airflow | 50 | 2 | 2 | 0 | 0 | secret-echoed-to-log |
| electron/electron | 50 | 0 | 0 | 0 | 0 | -- |

**293 findings across 218 workflow files in 10 repos** (8 critical, 46
high, 239 medium). Per-repo SARIF is in
[`results/real_world_scan/`](results/real_world_scan/); the full
human-reviewed write-up — exact file/line, whether each finding is
realistically exploitable as written, and honest notes where a
correctly-triggered rule turned out to have a real mitigating factor
(VS Code's ephemeral 1ES runner pools, a GitHub charset restriction that
neuters one tainted context in React's CI, a `docker login --password-stdin`
pattern in Airflow's CI that isn't quite what "echoed to log" implies) —
is in [`docs/REAL_WORLD_FINDINGS.md`](docs/REAL_WORLD_FINDINGS.md). The
230 `unpinned-action` findings in django and react, and the 46
`cache-poisoning` findings spread across five repos, are the same
primitives behind real incidents: [CVE-2025-30066](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3)
(tj-actions/changed-files) and the [cache-poisoning research that broke
Angular's CI in March 2024](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/),
respectively — see `taxonomy.md` for the full incident references.

## Evaluation

Two independent measurements, kept deliberately separate because they
answer different questions:

- **[`results/eval_report.md`](results/eval_report.md)** (`eval/metrics.py`) —
  precision/recall/F1 per taxonomy category against 20 hand-labeled
  fixtures in `tests/fixtures/eval/` (10 vulnerable across all 8
  categories, 10 clean). Scores 1.00 across the board — this is a
  conformance check against this project's own spec, not a claim about
  real-world accuracy; the report says so explicitly and points at
  real-world results for that.
- **[`results/semgrep_comparison.md`](results/semgrep_comparison.md)**
  (`baselines/run_semgrep.py`) — the same 20 fixtures, same methodology,
  scored against semgrep's public `p/github-actions` ruleset instead.
  Semgrep has no rule at all for 4 of our 8 categories
  (`excess_permissions`, `dependency_confusion`, `cache_poisoning`,
  `self_hosted_runner`) and a `secret_leakage` rule that exists but
  doesn't match the direct "secret interpolated into `run:`" pattern —
  0.42 recall vs. this project's 1.00 on the shared fixture set, both at
  1.00 precision (neither tool false-positives here).

## Tests

```bash
pytest tests/ -v
```

74 tests across the IR, parser, findings/SARIF export, taint engine, all
eight detectors (true-positive and true-negative cases per category, plus
permission-inheritance edge cases), the patcher, the CLI, and the eval
harness (a regression guard: fails loudly if a detector change silently
breaks one of the 20 labeled eval fixtures).

## Known limitations

- **`patcher/` (LLM-assisted patch generation + verification) and
  `collect/` (corpus collection for that patcher)** are earlier
  scaffolding for a more ambitious version of this project and remain
  `Not yet implemented` stubs. `scanner/patcher.py` (rule-based patch
  suggestions per finding, used throughout this README and the CLI) is
  the patching functionality actually shipped in this submission and does
  not depend on either. `eval/metrics.py` and `baselines/run_semgrep.py`
  — the other two items in that original stub list — are now fully
  implemented; see Evaluation above.
- All detection is static and rule-/heuristic-based (dependency confusion
  and cache poisoning in particular are pattern-matching heuristics, not
  full data-flow analysis) — expect some false negatives on obfuscated or
  unusually structured workflows, by design favoring low false positives
  over exhaustive recall.
- **Self-hosted runner misuse (`runner.py`)** flags any `pull_request` /
  `pull_request_target`-triggered job on `runs-on: self-hosted`; the
  scanner has no way to know from the workflow file alone whether the
  repository is actually public (where forked PRs are the real attacker
  surface) or private (where the risk is much lower), so it always treats
  the trigger as fork-reachable.
