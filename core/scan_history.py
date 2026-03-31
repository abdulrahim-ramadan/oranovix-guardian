"""
ScanHistory — SQLite-backed persistence for scan results.
Provides aggregate stats for the home dashboard (Bug 5).
"""
from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List


class ScanHistory:
    """
    Singleton.  Persists every scan to a local SQLite database and exposes
    aggregate stats (total scans, avg score, last scan date, …).
    """

    _instance:     "ScanHistory | None" = None
    _initialized:  bool = False

    def __new__(cls) -> "ScanHistory":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._db_path = self._resolve_db_path()
        self._create_tables()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_db_path() -> str:
        if getattr(sys, "frozen", False):
            base = os.path.dirname(sys.executable)  # next to the exe
        else:
            base = str(Path(__file__).parent.parent)
        return os.path.join(base, "scan_history.db")

    def _create_tables(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date       TEXT    NOT NULL,
                    target_path     TEXT    NOT NULL,
                    files_scanned   INTEGER DEFAULT 0,
                    total_issues    INTEGER DEFAULT 0,
                    critical_count  INTEGER DEFAULT 0,
                    high_count      INTEGER DEFAULT 0,
                    medium_count    INTEGER DEFAULT 0,
                    low_count       INTEGER DEFAULT 0,
                    risk_score      INTEGER DEFAULT 0,
                    duration_secs   REAL    DEFAULT 0.0
                )
            """)
            conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save_scan(self, result) -> None:
        """Persist a ScanResult to the database."""
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("""
                    INSERT INTO scans
                      (scan_date, target_path, files_scanned, total_issues,
                       critical_count, high_count, medium_count, low_count,
                       risk_score, duration_secs)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    str(result.target_path),
                    result.files_scanned,
                    result.total_issues,
                    result.critical_count,
                    result.high_count,
                    result.medium_count,
                    result.low_count,
                    result.risk_score,
                    result.duration_seconds,
                ))
                conn.commit()
        except Exception:
            pass

    def get_stats(self) -> Dict:
        """Return aggregate stats across all historical scans."""
        try:
            with sqlite3.connect(self._db_path) as conn:
                row = conn.execute("""
                    SELECT
                        COUNT(*)         AS total_scans,
                        COALESCE(SUM(files_scanned), 0)  AS total_files,
                        COALESCE(SUM(total_issues),  0)  AS total_issues,
                        COALESCE(AVG(risk_score),    0)  AS avg_score,
                        MAX(scan_date)               AS last_scan,
                        (SELECT target_path FROM scans
                         ORDER BY id DESC LIMIT 1)   AS last_target
                    FROM scans
                """).fetchone()
        except Exception:
            row = None

        if not row or row[0] == 0:
            return {
                "total_scans":  0,
                "total_files":  0,
                "total_issues": 0,
                "avg_score":    0,
                "last_scan":    "Never",
                "last_target":  "—",
            }
        return {
            "total_scans":  int(row[0] or 0),
            "total_files":  int(row[1] or 0),
            "total_issues": int(row[2] or 0),
            "avg_score":    int(row[3] or 0),
            "last_scan":    (row[4] or "")[:10] or "Never",
            "last_target":  os.path.basename(row[5]) if row[5] else "—",
        }

    def get_recent(self, limit: int = 5) -> List[Dict]:
        """Return the N most-recent scan records."""
        try:
            with sqlite3.connect(self._db_path) as conn:
                rows = conn.execute("""
                    SELECT scan_date, target_path, files_scanned,
                           total_issues, risk_score
                    FROM scans ORDER BY id DESC LIMIT ?
                """, (limit,)).fetchall()
        except Exception:
            rows = []
        return [
            {
                "date":   (r[0] or "")[:10],
                "target": os.path.basename(r[1]) if r[1] else "—",
                "files":  r[2] or 0,
                "issues": r[3] or 0,
                "score":  r[4] or 0,
            }
            for r in rows
        ]
