"""Detector registry.

`DEFAULT_DETECTORS` lists every implemented detector in taxonomy.md
priority order; `scanner/cli.py` and `eval/` run through this list rather
than importing individual detector modules, so adding a new detector only
requires wiring it in here.

`pinning.py` (unpinned third-party actions) and `runner.py` (self-hosted
runner misuse) are scaffolded but not yet implemented -- see README.md's
"Known limitations" section -- and are intentionally left out of this list.
"""

from __future__ import annotations

from scanner.detectors.base import Detector
from scanner.detectors.cache_poisoning import CachePoisoningDetector
from scanner.detectors.dependency_confusion import DependencyConfusionDetector
from scanner.detectors.injection import ScriptInjectionDetector
from scanner.detectors.permissions import ExcessPermissionsDetector
from scanner.detectors.pull_request_target import PullRequestTargetDetector
from scanner.detectors.secrets import SecretLeakageDetector

DEFAULT_DETECTORS: tuple[Detector, ...] = (
    ScriptInjectionDetector(),
    PullRequestTargetDetector(),
    ExcessPermissionsDetector(),
    SecretLeakageDetector(),
    DependencyConfusionDetector(),
    CachePoisoningDetector(),
)

__all__ = ["DEFAULT_DETECTORS", "Detector"]
