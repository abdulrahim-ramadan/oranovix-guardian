"""Shared fixtures: a tiny OSV database built from ``tests/fixtures/osv``."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from scanner_engine.deps.osv_db import OSVDatabase
from scanner_engine.deps.versions import Ecosystem

OSV_FIXTURES = Path(__file__).parent / "fixtures" / "osv"


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
