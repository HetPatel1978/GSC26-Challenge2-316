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

Full detection logic and false-positive reasoning per category lives in
[`taxonomy.md`](taxonomy.md) and the docstring at the top of each detector
module.

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
```

Each detector is a pure function of the IR (`Workflow -> list[Finding]`),
so they run in any order, compose freely, and are unit-tested in isolation
against fixtures in `tests/fixtures/`.

## Setup

```bash
pip install -r requirements.txt
```

The scanner itself only needs `pyyaml` and the standard library. The rest
of `requirements.txt` (anthropic, pandas, matplotlib, PyGithub, ...)
belongs to the LLM-assisted patching and corpus-evaluation tooling under
`patcher/`, `collect/`, and `eval/`, which is separate, not-yet-implemented
scaffolding — see Known limitations.

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

## Tests

```bash
pytest tests/ -v
```

71 tests across the IR, parser, findings/SARIF export, taint engine, all
eight detectors (true-positive and true-negative cases per category, plus
permission-inheritance edge cases), the patcher, and the CLI.

## Known limitations

- **`patcher/` (LLM-assisted patch generation + verification), `eval/`
  (precision/recall against a labeled corpus), `collect/` (corpus
  collection), and `baselines/` (zizmor/semgrep comparison)** are earlier
  scaffolding for a more ambitious version of this project and remain
  `Not yet implemented` stubs. `scanner/patcher.py` (rule-based patch
  suggestions per finding) is the patching functionality actually shipped
  in this submission; it does not depend on any of the above.
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
