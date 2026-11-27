"""Desktop regressions for target selection and bounded result rendering."""
import tkinter as tk
from concurrent.futures import Future
from unittest.mock import MagicMock

import pytest

from oranovix_guardian.gui.pages.results_page import IssueAccordion, ResultsPage
from oranovix_guardian.gui.pages.scanner_page import ScannerPage
from oranovix_guardian.scanner_engine.base import Issue, Language, ScanResult, Severity


def test_pending_scan_only_launches_for_latest_selection():
    page = MagicMock()
    stale = Future()
    current = Future()
    page._preview = current
    page._start_requested = True
    stale.set_result((1, [Language.PYTHON], False))
    ScannerPage._poll_preview(page, stale)
    page._launch_scan.assert_not_called()
    ScannerPage._poll_preview(page, current)
    page.after.assert_called_once()
    current.set_result((2, [Language.JAVA], False))
    ScannerPage._poll_preview(page, current)
    page._launch_scan.assert_called_once()
    assert not page._start_requested


def test_result_pages_only_construct_visible_rows_and_expanded_details(monkeypatch):
    import customtkinter as ctk
    from oranovix_guardian.gui.pages import results_page
    try:
        root = ctk.CTk()
    except tk.TclError:
        pytest.skip("Tk display unavailable")
    history = MagicMock()
    history.return_value.get_stats.return_value = {}
    history.return_value.get_recent.return_value = []
    monkeypatch.setattr(results_page, "ScanHistory", history)
    try:
        page = ResultsPage(root, on_status=lambda *_: None)
        issues = [Issue("Example", "Example", "", Severity.LOW, "example.py", i) for i in range(1, 1001)]
        page._render_issues(ScanResult(".", "example", issues=issues), "ALL")
        page._show_issue_page(996)  # also cancels the previous page's pending batches
        root.after(150, root.quit)
        root.mainloop()
        batch = page._issue_frame.winfo_children()[-1]
        rows = [row for row in batch.winfo_children() if isinstance(row, IssueAccordion)]
        assert [row._issue.line_number for row in rows] == [997, 998, 999, 1000]
        assert not any(row._detail_ready for row in rows)
        rows[0]._toggle()
        assert rows[0]._detail_ready
    finally:
        root.destroy()


def test_slow_filter_read_is_replaced_by_latest_selection():
    from collections import deque
    from threading import Event
    import time
    from oranovix_guardian.gui.page_updates import PageRead

    callbacks = deque()
    widget = MagicMock()
    widget.after.side_effect = lambda delay, callback: callbacks.append(callback)
    gate = Event()
    results = []
    reads = PageRead(widget, pytest.fail)
    try:
        reads.request(lambda: gate.wait(2), results.append, key="all")
        reads.request(lambda: "intermediate", results.append, key="medium")
        reads.request(lambda: "latest", results.append, key="high")
        gate.set()
        deadline = time.monotonic() + 2
        while callbacks and time.monotonic() < deadline:
            callbacks.popleft()()
            time.sleep(.002)
        assert results == ["latest"]
    finally:
        gate.set()
        reads.close()
