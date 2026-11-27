"""Shared fixtures: a tiny OSV database built from ``tests/fixtures/osv``.

All data the code under test writes by default (settings.json, the
databases, custom rules, reports) goes to a temporary data folder, never
into the project root of the developer running the tests.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

import pytest

from oranovix_guardian.scanner_engine.deps.osv_db import OSVDatabase
from oranovix_guardian.scanner_engine.deps.versions import Ecosystem

OSV_FIXTURES = Path(__file__).parent / "fixtures" / "osv"

_TEST_DATA_DIR = tempfile.mkdtemp(prefix="oranovix-test-data-")


def pytest_configure(config: pytest.Config) -> None:
    os.environ["ORANOVIX_DATA_DIR"] = _TEST_DATA_DIR


def pytest_unconfigure(config: pytest.Config) -> None:
    shutil.rmtree(_TEST_DATA_DIR, ignore_errors=True)


@pytest.fixture
def osv_records() -> Dict[Ecosystem, List[Dict[str, Any]]]:
    return {
        ecosystem: json.loads((OSV_FIXTURES / f"{ecosystem.value}.json").read_text("utf-8"))
        for ecosystem in Ecosystem
    }


@pytest.fixture
def osv_db(tmp_path: Path, osv_records: Dict[Ecosystem, List[Dict[str, Any]]]) -> OSVDatabase:
    database = OSVDatabase(str(tmp_path / "osv.db"))
    database.import_records(osv_records)
    return database


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any attempt to open a connection fails the test."""
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network access during a test")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
