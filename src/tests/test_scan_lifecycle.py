from pathlib import Path
from threading import Event

from oranovix_guardian.scanner_engine.base import BaseScanner, ScanStatus
from oranovix_guardian.scanner_engine.orchestrator import ScanOrchestrator, ScanStage


def test_coverage_distinguishes_skips_from_failed_reads(tmp_path, monkeypatch):
    (tmp_path / "ok.js").write_text("const answer = 42;\n", encoding="utf-8")
    (tmp_path / "unreadable.js").touch()
    with (tmp_path / "oversized.js").open("wb") as handle:
        handle.truncate(BaseScanner.MAX_FILE_BYTES + 1)

    read_text = Path.read_text

    def mock_read_text(path, *args, **kwargs):
        if path.name == "unreadable.js":
            raise PermissionError("test fixture")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", mock_read_text)
    result = ScanOrchestrator().scan(str(tmp_path))

    assert result.files_scanned == 1
    assert result.coverage_counts == {
        "discovered": 3, "analyzed": 1, "partial": 0, "skipped": 1, "failed": 1,
    }
    assert any("PermissionError" in warning for warning in result.engine_warnings)
    assert any("5 MB" in warning for warning in result.engine_warnings)


def test_cancellation_stops_at_a_checkpoint_and_leaves_next_scan_usable(tmp_path):
    (tmp_path / "app.js").write_text("const answer = 42;\n", encoding="utf-8")
    stop = Event()
    stages = []

    def on_progress(progress):
        stages.append(progress.stage)
        if progress.stage == ScanStage.LANGUAGE_SCAN:
            stop.set()

    scanner = ScanOrchestrator(on_progress=on_progress)
    canceled = scanner.scan(str(tmp_path), cancel=stop)
    assert stages == [ScanStage.DISCOVERY, ScanStage.LANGUAGE_SCAN]
    assert canceled.status is ScanStatus.CANCELLED
    assert canceled.finished_at is not None
    assert canceled.coverage_counts is None
    assert scanner.scan(str(tmp_path)).status is ScanStatus.COMPLETED
