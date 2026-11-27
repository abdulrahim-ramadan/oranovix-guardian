"""Measure launch, idle window response and graceful exit of an installed Windows build."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def check_launch(executable: Path, data: Path) -> dict:
    import psutil
    import win32con
    import win32gui
    import win32process

    started = time.perf_counter()
    process = subprocess.Popen([str(executable)], cwd=data,
                               env={**os.environ, "ORANOVIX_DATA_DIR": str(data)})
    try:
        root = psutil.Process(process.pid)
        handles = []
        while not handles:
            if process.poll() is not None:
                raise RuntimeError(f"Exited during startup: {process.returncode}")
            if time.perf_counter() - started > 90:
                raise TimeoutError("Main window did not appear within 90 seconds")
            owned = {root.pid, *(child.pid for child in root.children(recursive=True))}

            def collect(hwnd, _):
                if (win32process.GetWindowThreadProcessId(hwnd)[1] in owned
                        and win32gui.IsWindowVisible(hwnd)
                        and win32gui.GetWindowText(hwnd) == "Oranovix Guardian"):
                    handles.append(hwnd)
                return True

            win32gui.EnumWindows(collect, None)
            if not handles:
                time.sleep(.05)

        window = handles[0]

        def ping():
            before = time.perf_counter()
            win32gui.SendMessageTimeout(window, win32con.WM_NULL, 0, 0, win32con.SMTO_BLOCK, 5000)
            return (time.perf_counter() - before) * 1000

        ping()
        launch_ms = round((time.perf_counter() - started) * 1000)
        replies = []
        for _ in range(30):
            time.sleep(.1)
            replies.append(ping())
        close = time.perf_counter()
        win32gui.PostMessage(window, win32con.WM_CLOSE, 0, 0)
        if process.wait(timeout=30):
            raise RuntimeError(f"Unclean exit: {process.returncode}")
        return dict(launch_ms=launch_ms, max_idle_reply_ms=round(max(replies), 2),
                    exit_ms=round((time.perf_counter() - close) * 1000))
    finally:
        if process.poll() is None:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], check=False)


def main() -> None:
    executable = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory() as folder:
        data = Path(folder)
        (data / "settings.json").write_text(json.dumps({"threat_feed": {"enabled": False, "asked": True}}))
        results = [check_launch(executable, data) for _ in range(3)]
    summary = json.dumps(results, indent=2)
    print(summary)
    if report := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(report, "a", encoding="utf-8") as handle:
            handle.write(f"### Installed Windows measurements\n\n```json\n{summary}\n```\n")


if __name__ == "__main__":
    main()
