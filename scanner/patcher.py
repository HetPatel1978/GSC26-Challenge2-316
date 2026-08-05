"""Patch suggestion generator: turns a Finding into a concrete before/after
YAML snippet plus an explanation, one template per rule_id.

Findings carry a `fix_hint` (one sentence, written by the detector that
produced them) already. This module goes one level further for the rule
ids common enough to have a single canonical fix shape -- an actual
before/after code sample the user can paste in -- and falls back to the
finding's own `fix_hint` for anything without a template (a subtype the
templates below don't cover, or a future detector that hasn't been given
one yet). That fallback means `suggest_patch` never returns nothing for a
finding produced by one of this project's detectors.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.findings import Finding


@dataclass
class PatchSuggestion:
    """A human-reviewable fix for one Finding. Not an auto-applied diff --
    the `before`/`after` snippets are illustrative templates keyed off the
    rule_id, not a rewrite of the user's actual file, since a Finding alone
    doesn't carry enough of the surrounding YAML to regenerate one safely
    (see `context` on Finding: a dotted path, not a parse tree)."""

    finding: Finding
    summary: str
    before: str | None
    after: str | None
    explanation: str

    def render(self) -> str:
        parts = [f"[{self.finding.rule_id}] {self.summary}"]
        if self.before is not None and self.after is not None:
            parts.append("--- before ---\n" + self.before.rstrip("\n"))
            parts.append("--- after ---\n" + self.after.rstrip("\n"))
        parts.append(self.explanation)
        return "\n\n".join(parts)


def _script_injection(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Break the interpolation by routing through env: indirection.",
        before='- run: echo "Title: ${{ github.event.issue.title }}"',
        after=(
            "- env:\n"
            "    ISSUE_TITLE: ${{ github.event.issue.title }}\n"
            '  run: echo "Title: $ISSUE_TITLE"'
        ),
        explanation=(
            "The tainted value is substituted by the shell as a plain environment variable "
            "instead of by the Actions expression engine directly into the command string, so "
            "it can no longer break out of quoting to inject arbitrary shell syntax."
        ),
    )


def _pull_request_target_checkout(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Stop checking out the fork PR's head content in a privileged trigger.",
        before="- uses: actions/checkout@v4\n  with:\n    ref: ${{ github.event.pull_request.head.sha }}",
        after="- uses: actions/checkout@v4",
        explanation=(
            "Dropping the explicit `ref:` leaves checkout on the base branch, which is safe to "
            "combine with `pull_request_target`'s elevated token. If you specifically need to "
            "inspect fork content, do it in a separate job with no `secrets:` access and "
            "`permissions: {}`, and never execute (build/test/run) what you check out there."
        ),
    )


def _excess_permissions(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Add an explicit, minimal permissions: block.",
        before="# (no permissions: key present)",
        after="permissions:\n  contents: read",
        explanation=(
            "An explicit `permissions:` block overrides the repository/org default, so a "
            "compromised step's token is capped at exactly what's listed here. Add write scopes "
            "only on the individual jobs that need them, not at the workflow level."
        ),
    )


def _hardcoded_secret(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Move the literal credential into a GitHub Actions secret.",
        before="env:\n  AWS_KEY: AKIAABCDEFGHIJKLMNOP",
        after="env:\n  AWS_KEY: ${{ secrets.AWS_KEY }}",
        explanation=(
            "Store the value with `gh secret set AWS_KEY` (or the repo Settings UI), reference "
            "it via the secrets context, and rotate the credential that was committed -- it's "
            "compromised the moment it's in git history, patch or not."
        ),
    )


def _secret_echoed_to_log(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Never print a secret; use env: indirection if it must reach the shell at all.",
        before='- run: echo "token is ${{ secrets.DEPLOY_TOKEN }}"',
        after=(
            "- env:\n"
            "    DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
            '  run: curl -H "Authorization: token $DEPLOY_TOKEN" https://api.example.com'
        ),
        explanation=(
            "GitHub's log masking is a string match on the exact secret value, and it can be "
            "defeated by printing the value partially, transformed, or char-by-char -- treat "
            "\"don't print it\" as the actual control, not the masking."
        ),
    )


def _secret_in_url(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Pass the credential out-of-band instead of embedding it in the URL.",
        before="git clone https://user:${{ secrets.DEPLOY_TOKEN }}@example.com/repo.git",
        after=(
            "env:\n  GIT_ASKPASS_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
            "run: |\n"
            '  git -c http.extraHeader="Authorization: Basic $(echo -n "x:$GIT_ASKPASS_TOKEN" | base64)" \\\n'
            "    clone https://example.com/repo.git"
        ),
        explanation=(
            "URLs are logged in full by many tools (curl -v, git errors, shell history, "
            ".netrc) and don't get the same masking treatment as command output; an auth "
            "header keeps the credential out of anything that logs \"the URL that was fetched\"."
        ),
    )


def _pip_extra_index_url(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Replace --extra-index-url with --index-url for internal packages.",
        before="pip install internal-pkg --extra-index-url https://pypi.internal.example.com/simple",
        after="pip install internal-pkg --index-url https://pypi.internal.example.com/simple",
        explanation=(
            "`--index-url` fully replaces the default PyPI index for that install, so pip has "
            "no public copy of the internal name to accidentally prefer. If the install also "
            "needs public packages, use per-package index configuration or a proxying private "
            "registry instead of `--extra-index-url`."
        ),
    )


def _unscoped_private_package(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Install the internal package under its configured scope.",
        before="npm config set @myorg:registry=https://npm.internal.example.com\nnpm install internal-widget",
        after=(
            "npm config set @myorg:registry=https://npm.internal.example.com\n"
            "npm install @myorg/internal-widget"
        ),
        explanation=(
            "Only the scoped name (`@myorg/...`) is routed to the private registry by the "
            "`@myorg:registry=` config; an unscoped name always resolves against the public "
            "npm registry, which is exactly what a dependency-confusion attack relies on."
        ),
    )


def _cache_poisoning(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Don't write cache from fork-triggered pull_request jobs.",
        before="- uses: actions/cache@v4\n  with:\n    key: npm-${{ github.head_ref }}",
        after="- uses: actions/cache/restore@v4\n  with:\n    key: npm-${{ hashFiles('package-lock.json') }}",
        explanation=(
            "Switching to `actions/cache/restore` makes the job read-only with respect to the "
            "cache, so a malicious PR run can no longer seed an entry for a later, privileged "
            "base-branch run to trust. Save from a base-branch (push) workflow instead, and key "
            "on content hashes rather than branch names."
        ),
    )


def _predictable_cache_key(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Derive the cache key from content, not attacker-controlled context.",
        before="key: npm-${{ github.head_ref }}",
        after="key: npm-${{ hashFiles('package-lock.json') }}",
        explanation=(
            "A content hash makes the key unpredictable to an attacker and ties the cache "
            "entry to what's actually in it, instead of a value the attacker can choose "
            "(their own branch name) to target a specific cache slot."
        ),
    )


def _unpinned_action(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Pin the action to a full commit SHA instead of a mutable tag.",
        before="- uses: actions/checkout@v4",
        after="- uses: actions/checkout@a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 # v4",
        explanation=(
            "A commit SHA always resolves to the exact content that was reviewed; a tag or "
            "branch name can be repointed by the action's maintainer -- or by whoever "
            "compromises their account or publishing pipeline -- to different content at any "
            "time, and the next run silently executes whatever it now points to."
        ),
    )


def _self_hosted_runner_fork_trigger(finding: Finding) -> PatchSuggestion:
    return PatchSuggestion(
        finding=finding,
        summary="Move the job off self-hosted infrastructure, or drop the fork-triggerable event.",
        before="on: pull_request\njobs:\n  build:\n    runs-on: self-hosted",
        after="on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest",
        explanation=(
            "A GitHub-hosted runner is a fresh, ephemeral VM torn down after the job, so a "
            "malicious PR gains nothing persistent by running on one. If self-hosted "
            "infrastructure is required, restrict the job to a non-fork-triggerable event (e.g. "
            "`push` to protected branches) or gate it behind an explicit maintainer approval."
        ),
    )


_TEMPLATES = {
    "script-injection": _script_injection,
    "pull-request-target-checkout": _pull_request_target_checkout,
    "excess-permissions": _excess_permissions,
    "hardcoded-secret": _hardcoded_secret,
    "secret-echoed-to-log": _secret_echoed_to_log,
    "secret-inline-interpolation": _secret_echoed_to_log,
    "secret-in-url": _secret_in_url,
    "unpinned-action": _unpinned_action,
    "pip-extra-index-url": _pip_extra_index_url,
    "unscoped-private-package": _unscoped_private_package,
    "cache-poisoning": _cache_poisoning,
    "predictable-cache-key": _predictable_cache_key,
    "self-hosted-runner-fork-trigger": _self_hosted_runner_fork_trigger,
}


def suggest_patch(finding: Finding) -> PatchSuggestion:
    """Return a `PatchSuggestion` for `finding`. Always succeeds: rule ids
    without a dedicated template fall back to the finding's own `fix_hint`
    with no before/after snippet, rather than raising or returning None."""
    template = _TEMPLATES.get(finding.rule_id)
    if template is not None:
        return template(finding)
    return PatchSuggestion(
        finding=finding,
        summary=finding.fix_hint or "No template available for this rule.",
        before=None,
        after=None,
        explanation=finding.fix_hint or finding.message,
    )


def suggest_patches(findings: list[Finding]) -> list[PatchSuggestion]:
    return [suggest_patch(f) for f in findings]
