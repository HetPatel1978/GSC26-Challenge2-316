# Semgrep vs. this scanner -- real-world repositories

Both tools run against the identical clone of each of the same 10 repositories used in `docs/REAL_WORLD_FINDINGS.md` (semgrep with its public `p/github-actions` ruleset). Unlike `results/semgrep_comparison.md`, there is no hand-written label set here -- this is raw finding counts and structural disagreement on code neither tool's rules had any influence over, not a precision/recall claim.

**220 workflow files across 10 repos.** Ours: 293 findings mapped to the 8 taxonomy categories. Semgrep: 349 findings mapped to those same 8 categories, plus 3 findings in categories outside this project's scope entirely (see below).

## Per-category totals, all 10 repos combined

| Category | Ours | Semgrep |
|---|---|---|
| script_injection | 1 | 31 |
| pull_request_target | 0 | 0 |
| excess_permissions | 8 | 0 |
| secret_leakage | 3 | 88 |
| unpinned_action | 230 | 230 |
| dependency_confusion | 0 | 0 |
| cache_poisoning | 46 | 0 |
| self_hosted_runner | 5 | 0 |
| **Total** | 293 | 349 |

Semgrep has no rule at all (not "didn't find any," no rule that attempts it) for: excess_permissions, dependency_confusion, cache_poisoning, self_hosted_runner. Those rows are structurally 0 for semgrep regardless of what's in the code.

## Per-repo breakdown

| Repo | Files | Ours | Semgrep |
|---|---|---|---|
| tensorflow/tensorflow | 17 | 1 | 1 |
| django/django | 21 | 76 | 59 |
| facebook/react | 22 | 193 | 187 |
| microsoft/vscode | 16 | 12 | 1 |
| pytest-dev/pytest | 6 | 0 | 0 |
| pallets/flask | 5 | 2 | 0 |
| psf/requests | 8 | 1 | 0 |
| numpy/numpy | 23 | 6 | 0 |
| apache/airflow | 50 | 2 | 16 |
| electron/electron | 52 | 0 | 85 |

## Where the two tools disagree on the same file

Restricted to the 4 categories semgrep has at least one rule for (`script_injection`, `pull_request_target`, `secret_leakage`, `unpinned_action`) -- the other 4 always show as "we flag, semgrep doesn't" simply because semgrep never attempts them, which isn't a meaningful disagreement and is already covered above. This table is restricted to cases where both tools *could* have flagged the same thing and didn't.

| Repo | File | We flag, semgrep doesn't | Semgrep flags, we don't |
|---|---|---|---|
| tensorflow/tensorflow | .github/workflows/arm-cd.yml | secret_leakage | - |
| tensorflow/tensorflow | .github/workflows/release-branch-cherrypick.yml | - | script_injection |
| facebook/react | .github/workflows/compiler_prereleases.yml | - | script_injection, secret_leakage |
| facebook/react | .github/workflows/devtools_regression_tests.yml | - | script_injection |
| facebook/react | .github/workflows/runtime_build_and_test.yml | script_injection | - |
| facebook/react | .github/workflows/runtime_commit_artifacts.yml | - | script_injection |
| facebook/react | .github/workflows/runtime_release_from_ci.yml | - | script_injection |
| facebook/react | .github/workflows/shared_check_maintainer.yml | - | script_injection |
| microsoft/vscode | .github/workflows/chat-perf.yml | - | script_injection |
| apache/airflow | .github/workflows/ci-amd.yml | - | secret_leakage |
| apache/airflow | .github/workflows/ci-arm.yml | - | secret_leakage |
| apache/airflow | .github/workflows/ci-duration-monitor.yml | - | secret_leakage |
| apache/airflow | .github/workflows/ci-notification.yml | - | secret_leakage |
| apache/airflow | .github/workflows/e2e-flaky-tests-report.yml | - | secret_leakage |
| apache/airflow | .github/workflows/release_dockerhub_image.yml | - | secret_leakage |
| apache/airflow | .github/workflows/update-constraints-on-push-stable.yml | - | secret_leakage |
| apache/airflow | .github/workflows/update-constraints-on-push.yml | - | secret_leakage |
| apache/airflow | .github/workflows/upgrade-check.yml | - | secret_leakage |
| electron/electron | .github/workflows/build.yml | - | secret_leakage |
| electron/electron | .github/workflows/linux-publish.yml | - | secret_leakage |
| electron/electron | .github/workflows/macos-publish.yml | - | secret_leakage |
| electron/electron | .github/workflows/pgo-generation.yml | - | secret_leakage |
| electron/electron | .github/workflows/pipeline-electron-build-and-test-and-nan.yml | - | secret_leakage |
| electron/electron | .github/workflows/pipeline-electron-build-and-test.yml | - | secret_leakage |
| electron/electron | .github/workflows/pipeline-electron-build-and-tidy-and-test-and-nan.yml | - | secret_leakage |
| electron/electron | .github/workflows/pipeline-electron-build-and-tidy-and-test.yml | - | secret_leakage |
| electron/electron | .github/workflows/pipeline-electron-lint.yml | - | secret_leakage |
| electron/electron | .github/workflows/pipeline-segment-electron-build.yml | - | script_injection, secret_leakage |
| electron/electron | .github/workflows/pipeline-segment-electron-clang-tidy.yml | - | script_injection |
| electron/electron | .github/workflows/pipeline-segment-electron-gn-check.yml | - | script_injection, secret_leakage |
| electron/electron | .github/workflows/pipeline-segment-electron-publish.yml | - | script_injection, secret_leakage |
| electron/electron | .github/workflows/pipeline-segment-electron-test-64k.yml | - | script_injection |
| electron/electron | .github/workflows/pipeline-segment-electron-test.yml | - | script_injection, secret_leakage |
| electron/electron | .github/workflows/pipeline-segment-node-nan-test.yml | - | script_injection, secret_leakage |
| electron/electron | .github/workflows/release-build.yml | - | secret_leakage |
| electron/electron | .github/workflows/windows-publish.yml | - | secret_leakage |

## What the disagreements actually are

Counting rows isn't enough to know which tool is right, so four representative disagreements were read by hand:

1. **`secrets: inherit` -- a real gap in our coverage.** Semgrep's `secrets-inherit` rule fired 13 times in electron/electron alone (mostly `.github/workflows/build.yml`), flagging reusable-workflow calls that pass *every* secret the caller has to the called workflow, violating least privilege. Nothing in this project's 8 categories checks for `secrets: inherit` at all -- a legitimate, real pattern this scanner should probably grow a 9th category for.
2. **Workflow-level `env:` holding a secret -- also a real gap.** Semgrep's `gha-workflow-env-secret` rule caught apache/airflow's `ci-amd.yml` (lines 62, 65) placing `${{ secrets.* }}` in the *workflow-level* `env:` block, making it available to every job and step in the file. `scanner/detectors/secrets.py` only inspects step-level `run:`/`with:`/`env:` text, so a workflow-level `env:` block is currently invisible to it -- a second real, specific gap, not a false positive on semgrep's part.
3. **Taint doesn't cross `workflow_call` input boundaries.** Semgrep flagged `facebook/react/.github/workflows/shared_check_maintainer.yml` (line 33) for interpolating `${{ inputs.actor }}` directly into a `with.script` sink. `scanner/taint.py`'s `TAINTED_CONTEXTS` only covers `github.event.*` and `github.head_ref` -- it has no model at all for whether a reusable workflow's `inputs:` were populated from a tainted source by the caller. Whether this specific instance is exploitable depends on how `actor` gets set at the call site (out of scope of the single file semgrep and we both see); either way, input-boundary taint tracking is a real, named limitation this project doesn't currently have and semgrep's rule is more conservative about.
4. **The inverse case: semgrep is arguably over-broad here.** Semgrep flagged `tensorflow/tensorflow/.github/workflows/release-branch-cherrypick.yml` (line 57) for interpolating `${{ github.event.inputs.git_commit }}` into `run:`. That context is a `workflow_dispatch` input, which can only be populated by someone with write access to the repository triggering the workflow manually -- not by an anonymous forked PR the way `github.event.issue.title` or `.pull_request.body` can be. `scanner/taint.py`'s `TAINTED_CONTEXTS` allowlist was built to cover fork-reachable event fields (PR/issue/comment/review text) and simply never included `workflow_dispatch` inputs -- not flagging them wasn't a deliberate, reasoned exclusion in the code, but it happens to be the more precise call here: an input only a trusted, write-access operator can populate isn't "attacker-controlled" in the same sense the rest of the allowlist is. Worth documenting as the actual reasoning going forward, since right now it's correct by omission rather than by design.

## Semgrep findings outside this project's taxonomy

Rules in `p/github-actions` that check for real issues this project's 8 categories don't attempt at all (curl\|bash execution, deprecated workflow commands, a known-worm IOC signature -- see `baselines/run_semgrep.py`).

| Rule | Count |
|---|---|
| yaml.github-actions.security.audit.unsafe-add-mask-workflow-command.unsafe-add-mask-workflow-command | 2 |
| yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell | 1 |
