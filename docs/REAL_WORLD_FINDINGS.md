# Real-world findings

`scripts/scan_real_repos.py` shallow/sparse-clones ten popular, actively
maintained open source repositories (chosen to span several ecosystems --
Python, JS/TS, C++, and mixed -- and confirmed in advance to actually carry
`.github/workflows/`; a few equally famous candidates, `torvalds/linux`,
`kubernetes/kubernetes`, `golang/go`, and `ansible/ansible`, use other CI
systems entirely and have no workflows to scan), runs the full detector
suite against every workflow file, and writes one SARIF file per repo to
[`results/real_world_scan/`](../results/real_world_scan/) plus a summary
table at [`results/real_world_scan/summary.md`](../results/real_world_scan/summary.md).

This document is the human-reviewed follow-up: for each finding worth a
closer look, we pulled the actual source line, worked out whether it's
realistically exploitable as written, and noted it honestly when a
correctly-triggered rule turned out to have a mitigating factor the
detector itself can't see. A tool that only ever tells you "look how much
it found" is less useful, and less trustworthy, than one that also tells
you which of those findings actually matter.

**Scan snapshot** (2026-08-06, HEAD of each repo's default branch at scan
time): 10 repos, 218 workflow files, 293 findings -- 8 critical, 46 high,
239 medium.

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

## Deep dives

### 1. microsoft/vscode -- self-hosted runners on `pull_request`

**File:** [`.github/workflows/pr.yml`](https://github.com/microsoft/vscode/blob/main/.github/workflows/pr.yml), lines 21, 198, 243, 262, 356
**Rule:** `self-hosted-runner-fork-trigger` -- critical

```yaml
on:
  pull_request:
    branches: [main, 'release/*']

jobs:
  compile:
    name: Compile & Hygiene
    runs-on: [ self-hosted, 1ES.Pool=1es-vscode-oss-ubuntu-22.04-x64, "JobId=compile-${{ github.run_id }}-..." ]
```

Five jobs in this workflow (`compile`, `copilot-check-test-cache`,
`copilot-check-telemetry`, `copilot-linux-tests`, `copilot-windows-tests`)
run on a `self-hosted` runner pool, unconditionally, on a bare
`pull_request` trigger with no `if:` guard restricting them to
same-repository PRs. That means every job -- including `npm ci` and a
telemetry-extractor `npx` invocation -- runs on Microsoft's infrastructure
for any forked pull request, not just internal ones.

**Why we're not calling this an open door:** the runner label is
`1ES.Pool=...` -- Microsoft's 1ES (internal Azure DevOps-based) *ephemeral*
runner pools, which are explicitly designed to provision a clean VM per job
and destroy it afterward. That's a real, meaningful mitigation against the
"persistent box, secrets left behind for the next job" scenario our finding
message describes, and it's the opposite of the raw, long-lived
self-hosted boxes that made the PyTorch/TensorFlow/GitHub research below
so damaging. What it does *not* mitigate: network/cloud-metadata pivot
risk from *inside* the ephemeral VM during the job itself, and the
class of attack is exactly the one GitHub's own guidance calls out --
["self-hosted runners... should almost never be used for public
repositories"](https://docs.github.com/en/actions/reference/security/secure-use),
full stop, regardless of ephemerality. This is a legitimate flag; the
practical severity is lower than the generic message implies precisely
*because* Microsoft already invested in the specific mitigation (ephemeral,
managed pools) that a smaller project running literal `self-hosted` on a
persistent box would not have. Our detector has no way to see "1ES.Pool="
and know it means "ephemeral" -- that's a real limitation, not a bug, and
we call it out here rather than let the CRITICAL label overstate it.

### 2. facebook/react -- tainted context in a `run:` sink, with a twist

**File:** [`.github/workflows/runtime_build_and_test.yml`](https://github.com/facebook/react/blob/main/.github/workflows/runtime_build_and_test.yml), line 906
**Rule:** `script-injection` -- critical

```yaml
- run: |
    GH_TOKEN=${{ github.token }} scripts/release/download-experimental-build.js --commit=$(git rev-parse ${{ github.event.pull_request.base.sha }}) ${{ (github.event.pull_request.head.repo.full_name != github.repository && '--noVerify') || ''}}
```

`github.event.pull_request.head.repo.full_name` is on our tainted-context
allowlist (an attacker picks their own fork's `owner/repo`), and it's
interpolated directly into a `run:` sink -- exactly the shape our taint
engine exists to catch. It's a correct match against the rule as defined.

**Why it's still worth a second look:** GitHub repository full names are
restricted to `[A-Za-z0-9-_.]` for the repo part and a similarly narrow
alphabet for the owner -- no spaces, quotes, backticks, `$`, `;`, `|`, or
`&` are legal in either. That means *this specific* tainted value cannot
carry shell metacharacters to break out of the surrounding `${{ }}`
boolean expression, no matter what an attacker names their fork. The
pattern our detector flags -- untrusted context landing raw in a shell
sink -- is real and worth fixing on principle (route it through `env:`
regardless, since the next person to copy this pattern may interpolate a
field that *isn't* charset-restricted), but as written today this
particular instance isn't a working injection primitive. We'd rather say
that plainly than let a critical-severity label imply an exploit that
isn't actually there.

### 3. tensorflow/tensorflow -- credential as a bare CLI argument

**File:** [`.github/workflows/arm-cd.yml`](https://github.com/tensorflow/tensorflow/blob/master/.github/workflows/arm-cd.yml), line 68
**Rule:** `secret-inline-interpolation` -- medium

```yaml
- name: Upload pip wheel to PyPI
  run: python3 -m twine upload --verbose /home/ubuntu/actions-runner/_work/tensorflow/tensorflow/whl/* -u "__token__" -p ${{ secrets.AWS_PYPI_ACCOUNT_TOKEN }}
```

No caveat needed here -- this is the textbook case the rule exists for.
The PyPI upload token is passed as a literal `-p` command-line argument
to `twine`. Process argument lists are visible to any other process on
the same runner (`ps aux`, `/proc/<pid>/cmdline`) for the lifetime of the
`twine` invocation, and the fully-substituted command (secret included)
is also what shows up if step debug logging or `set -x` is ever enabled
on this job. `env: TWINE_PASSWORD: ${{ secrets.AWS_PYPI_ACCOUNT_TOKEN }}`
(twine already reads that variable) would remove the exposure with no
functional change.

### 4. apache/airflow -- `secrets.*` piped into `docker login`

**File:** [`.github/workflows/release_single_dockerhub_image.yml`](https://github.com/apache/airflow/blob/main/.github/workflows/release_single_dockerhub_image.yml), lines 89 and 183
**Rule:** `secret-echoed-to-log` -- critical

```yaml
- name: "Login to hub.docker.com"
  run: >
    echo ${{ secrets.DOCKERHUB_TOKEN }} |
    docker login --password-stdin --username ${{ secrets.DOCKERHUB_USER }}
```

This is Docker's own documented `--password-stdin` pattern, and in the
common case `echo`'s output goes straight into the pipe -- it never
actually reaches the rendered log the way our "printed" framing suggests.
We flagged it because our heuristic (a `secrets.*` expression plus an
echo-shaped command in the same `run:` block) can't distinguish "printed
to stdout" from "piped to stdin," and that's a real precision gap worth
naming rather than hiding.

That said, this is still a legitimate finding on the underlying principle,
just for a different reason than the message implies: `${{ secrets.X }}`
is substituted by the Actions runner directly into the literal script text
it writes to disk for the step, *before* bash ever runs it -- independent
of whether the script itself prints anything. That substituted script is
what step-debug logging (`ACTIONS_STEP_DEBUG`), a `set -x` added later by
someone debugging a flaky job, or any tracing wrapper action would expose.
GitHub's own guidance is to avoid inline `${{ secrets.* }}` in `run:`
for exactly this reason, independent of whether the immediate command
happens to echo it to the terminal. `env: DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}`
plus `echo "$DOCKERHUB_TOKEN" | docker login ...` closes both the narrow
"echoed" case and the broader "lives in the generated script" case at once.

### 5. django/django -- cache poisoning with a maximally predictable key

**File:** [`.github/workflows/benchmark.yml`](https://github.com/django/django/blob/main/.github/workflows/benchmark.yml), line 30
**Rule:** `cache-poisoning` -- high (and a detector gap worth naming)

```yaml
on:
  pull_request:
    types: [labeled, synchronize, opened, reopened]

jobs:
  Run_benchmarks:
    if: contains(github.event.pull_request.labels.*.name, 'benchmark')
    steps:
      - uses: actions/cache@v6
        with:
          path: Django/*
          key: Django
```

Correctly flagged: a `pull_request`-triggered job writes to the Actions
cache. The `if:` gate (a maintainer has to apply the `benchmark` label
before this runs) narrows *who* can trigger a write, but doesn't change
the underlying mechanism once it fires.

The more interesting detail is the key itself: `key: Django` is a bare
string literal, not derived from anything -- every run of this job,
forever, writes to the exact same cache slot. That is strictly more
predictable than the "derived from attacker-controlled context" case our
`predictable-cache-key` sub-check looks for (see `scanner/detectors/cache_poisoning.py`),
and yet it doesn't trip that sub-check, because the sub-check only fires
on a `key:`/`restore-keys:` value containing a tainted `${{ }}`
expression -- a hardcoded literal has no expression to inspect at all.
The base `cache-poisoning` write-in-PR-job check still catches the real
risk here, but this is a genuine gap in the more specific sub-rule, now
tracked as a known limitation rather than silently missed.

### 6. Cache poisoning and unpinned actions at scale

Beyond the deep dives above, two patterns showed up broadly enough to be
worth calling out in aggregate rather than file-by-file:

- **`cache-poisoning` (46 occurrences across django, react, flask,
  requests, numpy):** `actions/cache` (or a setup-* action's built-in
  `cache:` input) writing from a `pull_request`-triggered job is common
  enough across very different projects that it reads less like isolated
  mistakes and more like an ecosystem default nobody's pushed back on.
  This is exactly the mechanism [Adnan Khan's GitHub Actions cache
  poisoning research](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/)
  demonstrated against Angular in March 2024 (a poisoned cache entry broke
  Angular's CI), before GitHub tightened cache-write scoping in late 2024.
- **`unpinned-action` (230 occurrences, mostly django and react):**
  individually medium severity, but this is precisely the supply-chain
  primitive behind [CVE-2025-30066](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3):
  in March 2025, attackers compromised the `tj-actions/changed-files`
  maintainer's token and repointed every version tag (`v1` through
  `v45.0.7`) to a malicious commit that dumped CI runner memory --
  including secrets -- into public workflow logs, across more than 23,000
  repositories that had pinned the action by tag rather than by commit
  SHA. Every one of these 230 findings is a workflow one compromised
  maintainer account away from the same outcome.

## Methodology notes

- Repos are scanned at whatever commit is HEAD of the default branch at
  scan time (shallow clone, depth 1) -- findings reflect a snapshot, not a
  permanent state, and may already be fixed by the time you read this.
- `scripts/scan_real_repos.py` reuses `scanner.cli.scan_files` (the same
  code path the CLI and test suite exercise), so these results are
  produced by the same detector logic covered by `tests/`, not a separate
  code path.
- We did not open issues or PRs against any of these projects for this
  writeup -- these are published, public workflow files, and several of
  the findings above (the `vscode` and `django` cases especially) turned
  out to already have real, if partial, mitigations in place.
