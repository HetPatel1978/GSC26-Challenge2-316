# Vulnerability Taxonomy

Detection priority order. To be filled in with detailed detection logic, taint
sources/sinks, false-positive risks, and references per category.

## 1. Script injection

Attacker-controlled `github.event.*` expressions interpolated directly into `run:` steps.

## 2. `pull_request_target` misuse

Workflow trigger runs in base-repo context (with secrets) while checking out
fork HEAD content — allows secret exfiltration or code execution against
protected branches.

## 3. Excess `GITHUB_TOKEN` permissions

Missing `permissions:` block (defaults to broad access) or explicit `write-all` scope.

## 4. Secret/token leakage

Hardcoded credentials, secrets echoed to logs, secrets embedded in URLs.

## 5. Unpinned third-party actions

`uses: org/action@tag` (mutable ref) instead of a pinned full commit SHA.

## 6. Dependency confusion

Unscoped private package names that are resolvable from public registries.

## 7. Cache poisoning

Shared cache keys across security boundaries (e.g. PR and base-branch builds).

## 8. Self-hosted runner misuse

Public repositories triggering jobs on persistent self-hosted runners, allowing
arbitrary code execution on infrastructure via a forked PR.
