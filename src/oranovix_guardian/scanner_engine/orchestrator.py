"""
Runs every scan engine against one target and merges the output.

``ScanOrchestrator`` is the single entry point for a full scan: one
scanner per language found in the target, then the Django template
scanner, the secrets detector, the rule engine and the dependency
scanner.  The GUI only calls ``scan`` and renders progress.
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import Event
from typing import Callable, List, Optional

from .base import BaseScanner, Language, ScanCancelled, ScanResult, ScanStatus, check_scan_cancelled, scan_stop
from .deps.dependency_scanner import DependencyScanner
from .django_template_rules import DjangoTemplateScanner
from .factory import ScannerFactory
from .issue_merger import IssueMerger
from .rule_engine import RuleEngine
from .secrets_detector import SecretsDetector


class ScanStage(Enum):
    """Phases of a full scan, in execution order."""

    DISCOVERY = "discovery"
    LANGUAGE_SCAN = "language_scan"
    TEMPLATES = "templates"
    SECRETS = "secrets"
    RULES = "rules"
    DEPENDENCIES = "dependencies"
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
    """Coordinates language scanners, template rules, secrets and custom rules."""

    def __init__(
        self,
        secrets_detector: Optional[BaseScanner] = None,
        rule_engine: Optional[RuleEngine] = None,
        on_progress: Optional[ProgressListener] = None,
        template_scanner: Optional[BaseScanner] = None,
        dependency_scanner: Optional[BaseScanner] = None,
    ) -> None:
        self._secrets_detector = secrets_detector or SecretsDetector()
        self._template_scanner = template_scanner or DjangoTemplateScanner()
        self._dependency_scanner = dependency_scanner or DependencyScanner()
        self._rule_engine = rule_engine
        self._on_progress = on_progress
        self._merger = IssueMerger()

    def scan(self, target: str, *, cancel: Optional[Event] = None) -> ScanResult:
        """Scan *target* with every applicable engine and return one result."""
        result = ScanResult(
            target_path=target,
            scan_id=str(uuid.uuid4()),
            status=ScanStatus.RUNNING,
        )
        token = scan_stop.set(cancel)
        try:
            self._report(ScanStage.DISCOVERY, "Discovering files", 0.0)
            inventory = self.scannable_files(target)
            discovered = {os.path.normpath(path) for path in inventory}
            scanners = ScannerFactory.scanners_for_target(target)
            result.scanner_name = " + ".join(s.name for s in scanners) or "No language scanner"

            self._run_language_scanners(scanners, target, result)
            self._run_template_scanner(target, result)
            self._run_secrets_detector(target, result)
            self._run_rule_engine(target, result)
            self._run_dependency_scanner(target, result)
            check_scan_cancelled()

            result.issues = self._merger.merge(result.issues)
            result.processed_files = {os.path.normpath(path) for path in result.processed_files}
            result.skipped_files = {os.path.normpath(path) for path in result.skipped_files}
            result.failed_files = {os.path.normpath(path) for path in result.failed_files}
            tracked = result.processed_files | result.skipped_files | result.failed_files
            # Files can disappear after discovery, or an engine can fail before reporting a path.
            missing = discovered - tracked
            for path in sorted(missing):
                BaseScanner.not_analysed(result, path, "no applicable engine completed")
            result.discovered_files = len(discovered | tracked)
            result.files_scanned = len(result.processed_files)
            self._report(ScanStage.FINISHED, "Scan finished.", 1.0, "done")
            result.status = ScanStatus.COMPLETED
        except ScanCancelled:
            result.status = ScanStatus.CANCELLED
        finally:
            result.finished_at = datetime.now()
            scan_stop.reset(token)
        return result

    @staticmethod
    def scannable_files(target: str) -> List[str]:
        """Every file any engine would look at: source files, secret-bearing
        config and dependency manifests."""
        files = BaseScanner.collect_files(
            target,
            [
                *ScannerFactory.all_supported_extensions(),
                *SecretsDetector.SUPPORTED_EXTENSIONS,
                *DjangoTemplateScanner.SUPPORTED_EXTENSIONS,
            ],
            SecretsDetector.SUPPORTED_FILE_NAMES,
        )
        return sorted({*files, *DependencyScanner.manifest_files(target)})

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
            result.issues.extend(partial.issues)
            self._collect_warnings(scanner.name, partial, result, ScanStage.LANGUAGE_SCAN, fraction)

    def _run_template_scanner(self, target: str, result: ScanResult) -> None:
        scanner = self._template_scanner
        if not BaseScanner.collect_files(target, DjangoTemplateScanner.SUPPORTED_EXTENSIONS):
            return
        self._report(ScanStage.TEMPLATES, f"Engine: {scanner.name}", 0.62)
        partial = scanner.scan(target)
        result.issues.extend(partial.issues)
        self._collect_warnings(scanner.name, partial, result, ScanStage.TEMPLATES, 0.62)

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
        for message in engine.last_rejected:
            self._warn(result, f"Custom rule skipped: {message}", ScanStage.RULES, 0.85)
        active = [rule for rule in engine.rules if rule.enabled]
        if not active:
            return
        self._report(ScanStage.RULES, f"Rule Engine: applying {len(active)} rule(s)...", 0.85)
        extensions = ScannerFactory.all_supported_extensions()
        files = BaseScanner.within_size_limit(BaseScanner.collect_files(target, extensions), result)
        engine.incomplete_files.clear()
        for file_path in files:
            language = Language.from_extension(Path(file_path).suffix)
            result.issues.extend(BaseScanner.isolated(
                result, file_path, lambda p=file_path, lang=language: engine.scan_file(p, lang, strict_read=True), "rule engine"
            ))
        for file_path in engine.incomplete_files:
            BaseScanner.not_analysed(result, file_path, "custom rules did not complete")
        for message in getattr(engine, "warnings", []):
            self._warn(result, message, ScanStage.RULES, 0.85)

    def _run_dependency_scanner(self, target: str, result: ScanResult) -> None:
        scanner = self._dependency_scanner
        manifests = DependencyScanner.manifest_files(target)
        if not manifests:
            return
        self._report(
            ScanStage.DEPENDENCIES,
            f"Engine: {scanner.name} ({len(manifests)} manifest file(s))",
            0.92,
        )
        partial = scanner.scan(target)
        result.issues.extend(partial.issues)
        self._collect_warnings(scanner.name, partial, result, ScanStage.DEPENDENCIES, 0.92)

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
        result.processed_files.update(partial.processed_files)
        result.skipped_files.update(partial.skipped_files)
        result.failed_files.update(partial.failed_files)
        for warning in partial.engine_warnings:
            self._warn(result, warning, stage, fraction)
        if partial.status == ScanStatus.FAILED:
            self._warn(
                result, f"{engine_name} failed: {partial.error_message}", stage, fraction
            )

    def _warn(
        self, result: ScanResult, warning: str, stage: ScanStage, fraction: float
    ) -> None:
        if warning in result.engine_warnings:
            return              # e.g. a file above the size cap, seen by several engines
        result.engine_warnings.append(warning)
        self._report(stage, warning, fraction, "error")

    def _report(
        self, stage: ScanStage, message: str, fraction: float, level: str = "scan"
    ) -> None:
        check_scan_cancelled()
        if self._on_progress:
            self._on_progress(ScanProgress(stage, message, fraction, level))
        check_scan_cancelled()
