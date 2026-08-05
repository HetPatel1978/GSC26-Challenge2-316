"""Detector registry.

`DEFAULT_DETECTORS` lists every implemented detector in taxonomy.md
priority order; `scanner/cli.py` and `eval/` run through this list rather
than importing individual detector modules, so adding a new detector only
requires wiring it in here.
"""

from __future__ import annotations

from scanner.detectors.base import Detector
from scanner.detectors.cache_poisoning import CachePoisoningDetector
from scanner.detectors.dependency_confusion import DependencyConfusionDetector
from scanner.detectors.injection import ScriptInjectionDetector
from scanner.detectors.permissions import ExcessPermissionsDetector
from scanner.detectors.pinning import UnpinnedActionDetector
from scanner.detectors.pull_request_target import PullRequestTargetDetector
from scanner.detectors.runner import SelfHostedRunnerDetector
from scanner.detectors.secrets import SecretLeakageDetector

DEFAULT_DETECTORS: tuple[Detector, ...] = (
    ScriptInjectionDetector(),
    PullRequestTargetDetector(),
    ExcessPermissionsDetector(),
    SecretLeakageDetector(),
    UnpinnedActionDetector(),
    DependencyConfusionDetector(),
    CachePoisoningDetector(),
    SelfHostedRunnerDetector(),
)

__all__ = ["DEFAULT_DETECTORS", "Detector"]
