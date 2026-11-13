"""Large files: chunked signature scan with overlap, and the 50 MB limit.

Payloads are assembled at runtime and scanned from memory; the only file
written to disk is a sparse file of zeros.
"""
from __future__ import annotations

import io
from pathlib import Path

import pytest

from live_defense.base import ChangeType
from live_defense.baseline import Baseline
from live_defense.file_integrity import ChangeClassifier, FileIntegrityMonitor
from live_defense.webshell import WebShellDetector
from scanner_engine.base import Severity

MB = 1024 * 1024
PAYLOAD = ("<?php " + "ev" + "al(base64_" + "decode($_" + "POST['x'])); ?>\n").encode("latin-1")


class MemoryKeyStore:
    def __init__(self) -> None:
        self.value = ""

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value

    def is_available(self) -> bool:
        return True


def padding(size: int) -> bytes:
    """*size* bytes of 100-byte lines."""
    line = b"x" * 99 + b"\n"
    return (line * (size // 100 + 1))[:size]


def rules(data: bytes, limit: int = WebShellDetector.MAX_BYTES) -> dict:
    return {hit.rule: hit.line for hit in WebShellDetector.scan_stream(io.BytesIO(data), limit)}


def test_limits() -> None:
    assert WebShellDetector.CHUNK == 1 * MB
    assert WebShellDetector.OVERLAP == 256
    assert WebShellDetector.MAX_BYTES == 50 * MB


def test_payload_after_6_mb_of_padding_is_found() -> None:
    data = padding(6 * MB) + PAYLOAD

    found = rules(data)

    assert "php-eval-base64" in found
    assert found["php-eval-base64"] == data.count(b"\n", 0, 6 * MB) + 1


@pytest.mark.parametrize("cut", [8, 12, 16, 22])
def test_payload_across_a_chunk_border_is_found(cut: int) -> None:
    # The 3 MB chunk border falls *cut* bytes into the signature text.
    data = padding(3 * MB - cut) + PAYLOAD + padding(MB)

    assert "php-eval-base64" in rules(data)


def test_line_numbers_stay_right_in_later_chunks() -> None:
    data = padding(4 * MB + 50) + b"\n" + PAYLOAD

    assert rules(data)["php-eval-base64"] == data.count(b"\n", 0, len(data) - len(PAYLOAD)) + 1


def test_first_hit_of_each_rule_is_kept() -> None:
    data = PAYLOAD + padding(2 * MB) + PAYLOAD

    assert rules(data)["php-eval-base64"] == 1


def test_nothing_is_read_past_the_limit() -> None:
    data = padding(3 * MB) + PAYLOAD

    assert rules(data, limit=2 * MB) == {}


def test_too_large() -> None:
    assert not WebShellDetector.too_large(50 * MB)
    assert WebShellDetector.too_large(50 * MB + 1)


@pytest.mark.parametrize(
    "relative, severity",
    [("data/dump.bin", Severity.MEDIUM), ("uploads/movie.mp4", Severity.MEDIUM),
     ("uploads/x.php", Severity.CRITICAL)],
)
def test_too_large_is_at_least_medium(relative: str, severity: Severity) -> None:
    rated, reasons = ChangeClassifier().classify(ChangeType.NEW, relative, too_large=True)

    assert rated is severity
    assert "File too large to scan fully" in reasons


def test_monitor_flags_a_file_over_50_mb(tmp_path: Path) -> None:
    root = tmp_path / "site"
    (root / "data").mkdir(parents=True)
    (root / "readme.txt").write_text("hi\n", encoding="utf-8")
    baseline = Baseline(str(root), str(tmp_path / "integrity.db"), MemoryKeyStore())
    baseline.create()
    monitor = FileIntegrityMonitor(baseline, file_scanner=lambda path: [])
    with open(root / "data" / "dump.bin", "wb") as handle:
        handle.truncate(51 * MB)

    (event,) = monitor.check()

    assert event.severity is Severity.MEDIUM
    assert "File too large to scan fully" in event.reasons
