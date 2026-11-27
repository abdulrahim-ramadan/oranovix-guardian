"""Measure Tk callback delay while Guardian scans files and analyses access logs.

Run from the repository root: python -m src.build_tools.check_desktop_workload
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import tempfile
import time

from main import AppPaths, CodeGuardianApp
from oranovix_guardian.scanner_engine.base import ScanResult


def measure(app: CodeGuardianApp, start, finished) -> dict:
    interval_ms = 20
    delays = []
    started = time.perf_counter()
    scheduled = started
    timeout = app.after(120_000, app.quit)

    def sample():
        nonlocal scheduled
        now = time.perf_counter()
        delays.append(max(0.0, (now - scheduled) * 1000 - interval_ms))
        if finished():
            app.quit()
        else:
            scheduled = time.perf_counter()
            app.after(interval_ms, sample)

    app.after(interval_ms, sample)
    app.after(0, start)
    app.mainloop()
    app.after_cancel(timeout)
    if not finished():
        raise RuntimeError("Workload did not complete within two minutes")
    p95 = sorted(delays)[math.ceil(len(delays) * .95) - 1]
    return {
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
        "samples": len(delays),
        "p95_callback_delay_ms": round(p95, 2),
        "max_callback_delay_ms": round(max(delays), 2),
        "callbacks_delayed_over_250ms": sum(delay > 250 for delay in delays),
    }


def run(folder: Path, files: int, lines: int) -> dict:
    data = folder / "data"
    data.mkdir()
    (data / "settings.json").write_text('{"threat_feed":{"enabled":false,"asked":true}}', encoding="utf-8")
    project = folder / "project"
    project.mkdir()
    for index in range(files):
        (project / f"module_{index}.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    log = folder / "benchmark.log"
    sample = AppPaths.resource("assets", "sample_access.log").read_text(
        encoding="utf-8",
    ).splitlines()
    with log.open("w", encoding="utf-8") as handle:
        for index in range(lines):
            handle.write(sample[index % len(sample)] + "\n")

    os.environ["ORANOVIX_DATA_DIR"] = str(data)
    app = CodeGuardianApp()
    callback_errors = []
    app.report_callback_exception = lambda _kind, error, _traceback: callback_errors.append(error)
    app.update_idletasks()
    try:
        scan = measure(app, lambda: app._scan_project(str(project)),
                       lambda: app._scan_result is not None or bool(callback_errors))
        if callback_errors:
            raise RuntimeError("Scan callback failed") from callback_errors[0]
        result = app._scan_result
        if not isinstance(result, ScanResult) or result.files_scanned != files:
            raise RuntimeError("The scanner did not cover the generated project")

        app._navigate("log_sentinel")
        page = app._pages["log_sentinel"]
        controller = page._controller

        def log_rendered():
            if callback_errors:
                return True
            report = controller._last_report
            return (report is not None and not controller._analysing
                    and not page._reads.running and not app._state_jobs)

        logs = measure(app, lambda: controller.analyse_file(str(log)), log_rendered)
        if callback_errors:
            raise RuntimeError("Log callback failed") from callback_errors[0]
        report = controller._last_report
        if (report is None or report.error or not report.files
                or report.files[0].lines != lines or not report.new_events):
            raise RuntimeError(f"Log analysis did not cover the generated lines: {report}")
        return {"scan": {"files": files, **scan},
                "logs": {"lines": lines, "new_events": len(report.new_events), **logs}}
    finally:
        app._on_close()
        app.mainloop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=5000)
    parser.add_argument("--lines", type=int, default=50000)
    args = parser.parse_args()
    if args.files < 1 or args.lines < 1000:
        parser.error("use at least one source file and 1000 log lines")
    with tempfile.TemporaryDirectory(prefix="guardian-benchmark-") as temporary:
        results = run(Path(temporary), args.files, args.lines)
    summary = json.dumps(results, indent=2)
    print(summary)
    if report := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(report, "a", encoding="utf-8") as handle:
            handle.write(f"### Desktop workload measurements\n\n```json\n{summary}\n```\n")


if __name__ == "__main__":
    main()
