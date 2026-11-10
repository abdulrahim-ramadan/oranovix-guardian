"""
Runs every scan engine against one target and merges the output.

``ScanOrchestrator`` is the single entry point for a full scan: one
scanner per language found in the target, then the secrets detector,
then the rule engine.  The GUI only calls ``scan`` and renders progress.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional

from .base import BaseScanner, Language, ScanResult, ScanStatus
from .factory import ScannerFactory
from .issue_merger import IssueMerger
from .rule_engine import RuleEngine
from .secrets_detector import SecretsDetector


class ScanStage(Enum):
    """Phases of a full scan, in execution order."""

    LANGUAGE_SCAN = "language_scan"
    SECRETS = "secrets"
    RULES = "rules"
    FINISHED = "finished"


@dataclass(frozen=True)
class ScanProgress:
    """One progress update emitted while a scan runs."""

    stage: ScanStage
    message: str
    fraction: float
    level: str = "scan"


ProgressListener = Callable[[ScanProgress], None]


class ScanOrchestrator:
    """Coordinates language scanners, secrets detection and custom rules."""

    def __init__(
        self,
        secrets_detector: Optional[BaseScanner] = None,
        rule_engine: Optional[RuleEngine] = None,
        on_progress: Optional[ProgressListener] = None,
    ) -> None:
        self._secrets_detector = secrets_detector or SecretsDetector()
        self._rule_engine = rule_engine
        self._on_progress = on_progress
        self._merger = IssueMerger()

    def scan(self, target: str) -> ScanResult:
        """Scan *target* with every applicable engine and return one result."""
        result = ScanResult(
            target_path=target,
            scan_id=str(uuid.uuid4()),
            status=ScanStatus.RUNNING,
        )
        scanners = ScannerFactory.scanners_for_target(target)
        result.scanner_name = " + ".join(s.name for s in scanners) or "No language scanner"

        self._run_language_scanners(scanners, target, result)
        self._run_secrets_detector(target, result)
        self._run_rule_engine(target, result)

        result.issues = self._merger.merge(result.issues)
        result.status = ScanStatus.COMPLETED
        result.finished_at = datetime.now()
        self._report(ScanStage.FINISHED, "Scan finished.", 1.0, "done")
        return result

    # ------------------------------------------------------------------
    # Stages
    # ------------------------------------------------------------------

    def _run_language_scanners(
        self, scanners: List[BaseScanner], target: str, result: ScanResult
    ) -> None:
        for index, scanner in enumerate(scanners):
            fraction = 0.15 + 0.45 * (index / max(len(scanners), 1))
            self._report(
                ScanStage.LANGUAGE_SCAN,
                f"Engine: {scanner.name} ({scanner.language.value})",
                fraction,
            )
            partial = scanner.scan(target)
            result.files_scanned += partial.files_scanned
            result.issues.extend(partial.issues)
            self._collect_warnings(scanner.name, partial, result, ScanStage.LANGUAGE_SCAN, fraction)

    def _run_secrets_detector(self, target: str, result: ScanResult) -> None:
        self._report(ScanStage.SECRETS, "Running Secrets Detector on all files...", 0.65)
        partial = self._secrets_detector.scan(target)
        result.issues.extend(partial.issues)
        self._collect_warnings(
            self._secrets_detector.name, partial, result, ScanStage.SECRETS, 0.65
        )

    def _run_rule_engine(self, target: str, result: ScanResult) -> None:
        try:
            engine = self._rule_engine or RuleEngine()
        except Exception as exc:
            self._warn(result, f"Rule Engine could not load: {exc}", ScanStage.RULES, 0.85)
            return
        active = [rule for rule in engine.rules if rule.enabled]
        if not active:
            return
        self._report(ScanStage.RULES, f"Rule Engine: applying {len(active)} rule(s)...", 0.85)
        extensions = ScannerFactory.all_supported_extensions()
        for file_path in BaseScanner.collect_files(target, extensions):
            language = Language.from_extension(Path(file_path).suffix)
            result.issues.extend(engine.scan_file(file_path, language))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _collect_warnings(
        self,
        engine_name: str,
        partial: ScanResult,
        result: ScanResult,
        stage: ScanStage,
        fraction: float,
    ) -> None:
        """Copy an engine's warnings and failure into the merged result."""
        for warning in partial.engine_warnings:
            self._warn(result, warning, stage, fraction)
        if partial.status == ScanStatus.FAILED:
            self._warn(
                result, f"{engine_name} failed: {partial.error_message}", stage, fraction
            )

    def _warn(
        self, result: ScanResult, warning: str, stage: ScanStage, fraction: float
    ) -> None:
        result.engine_warnings.append(warning)
        self._report(stage, warning, fraction, "error")

    def _report(
        self, stage: ScanStage, message: str, fraction: float, level: str = "scan"
    ) -> None:
        if self._on_progress:
            self._on_progress(ScanProgress(stage, message, fraction, level))
