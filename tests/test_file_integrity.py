"""File integrity monitor: detection, severity, timestomping, tampering, alarms.

No sleeps and no GUI: every test calls ``check()`` directly. Shell-shaped
test content is assembled at runtime and never written to disk: an
antivirus would lock or quarantine such a file. Files on disk hold a
marker; the detector's file reader puts the real payload back in memory,
so the real signature rules still run on the real text.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import List, Optional

import pytest

from core.alarm_center import Alarm, AlarmCenter, AlarmChannel, AlarmLevel, SqliteSeenFindingStore
from live_defense.base import ChangeType, IntegrityEvent
from live_defense.baseline import Baseline
from live_defense.file_integrity import ChangeClassifier, FileIntegrityMonitor
from live_defense.webshell import WebShellDetector
from scanner_engine.base import Issue, Severity
from scanner_engine.categories import IssueCategory

PHP_EVAL_SHELL = "<?php " + "ev" + "al(base64_" + "decode($_POST['x'])); ?>\n"
PHP_SYSTEM_SHELL = "<?php @" + "sys" + "tem($_" + "GET['c']); ?>\n"
PY_EXEC_SHELL = "import base64\n" + "ex" + "ec(base64." + "b64decode(payload))\n"
PY_REQUEST_SHELL = "import os\ndef run(request):\n    os." + "popen(request." + "GET['cmd'])\n"
JSP_SHELL = "<% Runtime." + "getRuntime()." + "exec(request." + "getParameter(\"c\")); %>\n"
LONG_BASE64 = "blob = '" + ("QUJD" * 600) + "'\n"

PAYLOADS = {
    "PHP_EVAL_SHELL": PHP_EVAL_SHELL,
    "PHP_SYSTEM_SHELL": PHP_SYSTEM_SHELL,
    "PY_EXEC_SHELL": PY_EXEC_SHELL,
    "PY_REQUEST_SHELL": PY_REQUEST_SHELL,
}


def marker(name: str) -> str:
    """What goes on disk instead of a shell payload."""
    return f"@@{name}@@"


@pytest.fixture(autouse=True)
def payloads_in_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    def scan_file(path: str) -> list:
        try:
            text = Path(path).read_bytes().decode("latin-1")
        except OSError:
            return []
        for name, payload in PAYLOADS.items():
            text = text.replace(marker(name), payload)
        return WebShellDetector.scan_text(text)

    monkeypatch.setattr(WebShellDetector, "scan_file", staticmethod(scan_file))


class MemoryKeyStore:
    def __init__(self) -> None:
        self.value = ""

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value

    def is_available(self) -> bool:
        return True


class RecordingChannel(AlarmChannel):
    def __init__(self) -> None:
        self.alarms: List[Alarm] = []

    def deliver(self, alarm: Alarm) -> None:
        self.alarms.append(alarm)


def write(path: Path, text: str = "x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def modify(path: Path, text: str) -> None:
    """Change content and make sure the mtime moves, whatever the clock resolution."""
    before = path.stat().st_mtime_ns
    path.write_text(text, encoding="utf-8")
    os.utime(path, ns=(before + 2_000_000_000, before + 2_000_000_000))


@pytest.fixture
def root(tmp_path: Path) -> Path:
    site = tmp_path / "site"
    write(site / "manage.py", "import sys\n")
    write(site / "shop" / "settings.py", "DEBUG = False\n")
    write(site / "shop" / "views.py", "def index(request):\n    return None\n")
    write(site / "media" / "uploads" / "logo.png", "png\n")
    write(site / "README.md", "# Shop\n")
    return site


@pytest.fixture
def channel() -> RecordingChannel:
    return RecordingChannel()


@pytest.fixture
def baseline(root: Path, tmp_path: Path) -> Baseline:
    created = Baseline(str(root), str(tmp_path / "integrity.db"), MemoryKeyStore())
    created.create()
    return created


@pytest.fixture
def monitor(baseline: Baseline, tmp_path: Path, channel: RecordingChannel) -> FileIntegrityMonitor:
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [channel])
    return FileIntegrityMonitor(baseline, alarm_center=center, file_scanner=lambda path: [])


def only(events: List[IntegrityEvent]) -> IntegrityEvent:
    assert len(events) == 1, [e.event_id for e in events]
    return events[0]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_unchanged_folder_has_no_events(monitor: FileIntegrityMonitor) -> None:
    assert monitor.check() == []
    assert monitor.check(full=True) == []


def test_new_file_is_detected(monitor: FileIntegrityMonitor, root: Path) -> None:
    write(root / "notes.txt", "hello\n")

    event = only(monitor.check())

    assert event.change is ChangeType.NEW
    assert event.relative_path == "notes.txt"
    assert event.severity is Severity.LOW
    assert event.old_sha256 == "" and len(event.new_sha256) == 64


def test_modified_file_is_detected(monitor: FileIntegrityMonitor, root: Path) -> None:
    modify(root / "shop" / "views.py", "def index(request):\n    return 1\n")

    event = only(monitor.check())

    assert event.change is ChangeType.MODIFIED
    assert event.relative_path == "shop/views.py"
    assert event.severity is Severity.MEDIUM
    assert event.reasons[0] == "Source file changed"
    assert event.old_sha256 != event.new_sha256


def test_deleted_file_is_detected(monitor: FileIntegrityMonitor, root: Path) -> None:
    (root / "README.md").unlink()

    event = only(monitor.check())

    assert event.change is ChangeType.DELETED
    assert event.severity is Severity.MEDIUM
    assert event.new_sha256 == ""


def test_touch_without_content_change_is_not_an_event(monitor: FileIntegrityMonitor, root: Path) -> None:
    target = root / "README.md"
    later = target.stat().st_mtime_ns + 5_000_000_000
    os.utime(target, ns=(later, later))

    assert monitor.check() == []


def test_unreadable_new_file_is_still_reported(
    monitor: FileIntegrityMonitor, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from live_defense.baseline import UNREADABLE, FileTree

    monkeypatch.setattr(FileTree, "hash", lambda self, relative, is_link=False: UNREADABLE)
    write(root / "media" / "uploads" / "locked.php", "x\n")

    event = only(monitor.check())

    assert event.severity is Severity.CRITICAL
    assert event.reasons[-1] == "Content could not be read (locked, or removed by an antivirus?)"


def test_files_in_venv_and_node_modules_are_ignored(monitor: FileIntegrityMonitor, root: Path) -> None:
    write(root / "venv" / "Lib" / "evil.py", marker("PY_EXEC_SHELL"))
    write(root / "node_modules" / "pkg" / "index.js", "x\n")
    write(root / "shop" / "__pycache__" / "views.cpython-313.pyc", "x\n")
    write(root / "server.log", "x\n")

    assert monitor.check(full=True) == []


@pytest.mark.parametrize(
    "relative",
    ["public/build/shell.php", "static/dist/shell.php", ".git/hooks/post-merge",
     "shop/migrations/0002_auto.py", "build/lib/x.py", "env/Scripts/activate"],
)
def test_folders_the_scanner_skips_are_watched(
    monitor: FileIntegrityMonitor, root: Path, relative: str
) -> None:
    write(root / relative, marker("PHP_EVAL_SHELL"))

    event = only(monitor.check(full=True))

    assert event.change is ChangeType.NEW
    assert event.relative_path == relative


def test_node_modules_outside_public_folders_is_skipped(monitor: FileIntegrityMonitor, root: Path) -> None:
    write(root / "frontend" / "node_modules" / "pkg" / "shell.php", marker("PHP_EVAL_SHELL"))
    write(root / ".git" / "objects" / "ab" / "cdef", "blob\n")
    write(root / "env" / "Lib" / "site-packages" / "pkg" / "x.py", "x\n")

    assert monitor.check(full=True) == []


def test_node_modules_under_static_is_watched(monitor: FileIntegrityMonitor, root: Path) -> None:
    write(root / "static" / "node_modules" / "pkg" / "shell.php", marker("PHP_EVAL_SHELL"))

    event = only(monitor.check(full=True))

    assert event.relative_path == "static/node_modules/pkg/shell.php"
    assert event.severity is Severity.CRITICAL


def test_user_ignore_patterns_apply(baseline: Baseline, monitor: FileIntegrityMonitor, root: Path) -> None:
    baseline.set_ignore_patterns(["cache/", "*.tmp"])
    write(root / "cache" / "page.html", "x\n")
    write(root / "upload.tmp", "x\n")

    assert monitor.check() == []


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def test_eval_shell_in_uploads_is_critical(monitor: FileIntegrityMonitor, root: Path) -> None:
    write(root / "media" / "uploads" / "shell.php", marker("PHP_EVAL_SHELL"))

    event = only(monitor.check())

    assert event.change is ChangeType.NEW
    assert event.severity is Severity.CRITICAL
    assert event.reasons[0] == "Web shell signature: PHP eval() of base64-decoded data (line 1)"
    assert "New executable file in the media/ folder" in event.reasons
    assert event.line_number == 1


def test_double_extension_is_critical(monitor: FileIntegrityMonitor, root: Path) -> None:
    write(root / "media" / "uploads" / "image.php.jpg", "\xff\xd8 not really an image\n")

    event = only(monitor.check())

    assert event.severity is Severity.CRITICAL
    assert event.reasons[0] == "Executable extension .php hidden behind .jpg"


def test_modified_settings_is_high(monitor: FileIntegrityMonitor, root: Path) -> None:
    modify(root / "shop" / "settings.py", "DEBUG = True\nALLOWED_HOSTS = ['*']\n")

    event = only(monitor.check())

    assert event.severity is Severity.HIGH
    assert event.reasons[0] == "Sensitive configuration file changed"


def test_deleted_sensitive_file_is_high(monitor: FileIntegrityMonitor, root: Path) -> None:
    (root / "shop" / "settings.py").unlink()

    assert only(monitor.check()).severity is Severity.HIGH


@pytest.mark.parametrize(
    "change, relative, severity",
    [
        (ChangeType.NEW, "public/x.php", Severity.CRITICAL),
        (ChangeType.NEW, "static/js/app.js", Severity.CRITICAL),
        (ChangeType.NEW, "tmp/run.sh", Severity.CRITICAL),
        (ChangeType.NEW, "Uploads/tool.EXE", Severity.CRITICAL),
        (ChangeType.NEW, "media/a.phtml", Severity.CRITICAL),
        (ChangeType.NEW, "static/logo.png", Severity.LOW),
        (ChangeType.NEW, "app/helpers.py", Severity.MEDIUM),
        (ChangeType.NEW, "media/.htaccess", Severity.HIGH),
        (ChangeType.NEW, "docs/guide.pdf", Severity.LOW),
        (ChangeType.NEW, "docs/report.pdf.exe", Severity.MEDIUM),
        (ChangeType.NEW, "static/js/app.js.map", Severity.LOW),
        (ChangeType.NEW, "media/cv.docx", Severity.LOW),
        (ChangeType.NEW, "media/shell.PHP.png", Severity.CRITICAL),
        (ChangeType.MODIFIED, ".env", Severity.HIGH),
        (ChangeType.MODIFIED, ".env.production", Severity.HIGH),
        (ChangeType.MODIFIED, "shop/wsgi.py", Severity.HIGH),
        (ChangeType.MODIFIED, "shop/asgi.py", Severity.HIGH),
        (ChangeType.MODIFIED, "shop/urls.py", Severity.HIGH),
        (ChangeType.MODIFIED, "public/.htaccess", Severity.HIGH),
        (ChangeType.MODIFIED, "deploy/nginx/site.conf", Severity.HIGH),
        (ChangeType.MODIFIED, "etc/apache2/sites-enabled/000-default", Severity.HIGH),
        (ChangeType.MODIFIED, "Dockerfile", Severity.HIGH),
        (ChangeType.MODIFIED, "shop/settings/production.py", Severity.HIGH),
        (ChangeType.MODIFIED, "shop/models.py", Severity.MEDIUM),
        (ChangeType.MODIFIED, "README.md", Severity.LOW),
        (ChangeType.DELETED, "README.md", Severity.MEDIUM),
        (ChangeType.DELETED, "Dockerfile", Severity.HIGH),
    ],
)
def test_classifier(change: ChangeType, relative: str, severity: Severity) -> None:
    assert ChangeClassifier().classify(change, relative)[0] is severity


# ---------------------------------------------------------------------------
# Web shell signatures
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "content, rule",
    [
        (PHP_EVAL_SHELL, "php-eval-base64"),
        ("<?php " + "EV" + "AL( @base64_" + "decode ('Zm9v')); ?>", "php-eval-base64"),
        (PHP_SYSTEM_SHELL, "php-command-on-input"),
        ("<?php pass" + "thru($_" + "REQUEST['c']);", "php-command-on-input"),
        ("<?php shell" + "_exec($_" + "POST['c']);", "php-command-on-input"),
        ("<?php as" + "sert($_" + "GET['c']);", "php-command-on-input"),
        (PY_EXEC_SHELL, "python-exec-base64"),
        ("ex" + "ec(__import__('base64')." + "b64decode(p))", "python-exec-base64"),
        (PY_REQUEST_SHELL, "python-command-on-request"),
        ("subprocess." + "run(request." + "POST['c'], shell=True)", "python-command-on-request"),
        ("os." + "system(request." + "args.get('c'))", "python-command-on-request"),
        (JSP_SHELL, "java-runtime-exec-parameter"),
        (LONG_BASE64, "long-base64-literal"),
    ],
)
def test_web_shell_signatures(content: str, rule: str) -> None:
    hits = WebShellDetector.scan_text(content)

    assert rule in {hit.rule for hit in hits}


@pytest.mark.parametrize(
    "content",
    [
        "<?php echo base64_decode($data); ?>",
        "<?php system('ls'); ?>",
        "data = base64.b64decode(payload)\nexec_count = 1\n",
        "os.system('make build')\nvalue = request.GET['q']\n",
        "Runtime.getRuntime().exec(\"ls\");",
        "blob = '" + ("QUJD" * 400) + "'\n",
        "img = 'data:image/png;base64," + ("QUJD" * 800) + "'\n",
    ],
    ids=["decode-only", "fixed-command", "no-exec", "separate-lines", "fixed-java", "short-base64", "data-uri"],
)
def test_harmless_code_has_no_signature(content: str) -> None:
    assert WebShellDetector.scan_text(content) == []


def test_signature_reports_its_line() -> None:
    (hit,) = WebShellDetector.scan_text("<?php\n// x\n\n" + PHP_EVAL_SHELL)

    assert hit.line == 4


def test_signature_in_a_modified_file_is_critical(monitor: FileIntegrityMonitor, root: Path) -> None:
    modify(root / "shop" / "views.py", marker("PY_REQUEST_SHELL"))

    event = only(monitor.check())

    assert event.severity is Severity.CRITICAL
    assert event.reasons[0].startswith("Web shell signature: Python os.popen")


# ---------------------------------------------------------------------------
# Quick pass and full re-hash
# ---------------------------------------------------------------------------

def test_timestomped_change_is_found_by_the_full_rehash(monitor: FileIntegrityMonitor, root: Path) -> None:
    target = root / "shop" / "views.py"
    original = target.stat()
    same_size = target.read_text(encoding="utf-8").replace("None", "evil")
    assert len(same_size) == len(target.read_text(encoding="utf-8"))
    target.write_text(same_size, encoding="utf-8")
    os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
    assert target.stat().st_size == original.st_size
    assert target.stat().st_mtime_ns == original.st_mtime_ns

    for cycle in range(1, FileIntegrityMonitor.FULL_EVERY):
        assert monitor.check() == [], f"quick pass {cycle} should not see the change"
        assert monitor.last_pass_was_full is False

    event = only(monitor.check())

    assert monitor.last_pass_was_full is True
    assert event.change is ChangeType.MODIFIED
    assert event.relative_path == "shop/views.py"


def test_quick_pass_hashes_only_changed_files(
    monitor: FileIntegrityMonitor, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from live_defense.baseline import FileTree

    hashed: List[str] = []
    original = FileTree.hash

    def counting(self: FileTree, relative: str, is_link: bool = False) -> str:
        hashed.append(relative)
        return original(self, relative, is_link)

    monkeypatch.setattr(FileTree, "hash", counting)
    modify(root / "README.md", "# Shop v2\n")

    monitor.check()
    assert hashed == ["README.md"]

    hashed.clear()
    monitor.check(full=True)
    assert len(hashed) == 5


def test_first_cycle_after_start_is_full(baseline: Baseline) -> None:
    monitor = FileIntegrityMonitor(baseline, file_scanner=lambda path: [])

    monitor.first_check()

    assert monitor.last_pass_was_full is True


# ---------------------------------------------------------------------------
# Tampering
# ---------------------------------------------------------------------------

def tamper(baseline: Baseline, sql: str) -> None:
    with closing(sqlite3.connect(baseline.db_path)) as conn:
        conn.execute(sql.replace("{table}", baseline._table))
        conn.commit()


def test_edited_baseline_is_a_critical_tamper_event(
    monitor: FileIntegrityMonitor, baseline: Baseline, root: Path, channel: RecordingChannel
) -> None:
    write(root / "media" / "uploads" / "shell.php", marker("PHP_EVAL_SHELL"))
    tamper(baseline, "INSERT INTO {table} VALUES ('media/uploads/shell.php', 'x', 1, 1)")

    event = only(monitor.check())

    assert event.change is ChangeType.TAMPERED
    assert event.severity is Severity.CRITICAL
    assert event.reasons[0] == "Baseline was modified outside the app"
    assert event.can_accept is False
    assert channel.alarms[-1].level is AlarmLevel.CRITICAL
    # Still tampered on the next cycle: listed, but no second alarm.
    alarms = len(channel.alarms)
    assert monitor.check() == []
    assert len(channel.alarms) == alarms
    assert [e.change for e in monitor.open_events()] == [ChangeType.TAMPERED]


def test_tamper_event_clears_when_a_new_baseline_is_created(
    monitor: FileIntegrityMonitor, baseline: Baseline
) -> None:
    tamper(baseline, "UPDATE {table} SET size = size + 1")
    monitor.check()

    baseline.create()

    assert monitor.check() == []
    assert monitor.open_events() == []


# ---------------------------------------------------------------------------
# Alarms
# ---------------------------------------------------------------------------

def test_same_unchanged_state_alarms_once(
    monitor: FileIntegrityMonitor, root: Path, channel: RecordingChannel
) -> None:
    write(root / "media" / "uploads" / "shell.php", marker("PHP_EVAL_SHELL"))

    assert len(monitor.check()) == 1
    assert len(channel.alarms) == 1
    assert channel.alarms[0].level is AlarmLevel.CRITICAL

    assert monitor.check() == []
    assert monitor.check(full=True) == []
    assert len(channel.alarms) == 1
    assert len(monitor.open_events()) == 1


def test_a_second_change_to_the_same_file_alarms_again(
    monitor: FileIntegrityMonitor, root: Path, channel: RecordingChannel
) -> None:
    shell = write(root / "media" / "uploads" / "shell.php", marker("PHP_EVAL_SHELL"))
    monitor.check()

    modify(shell, marker("PHP_SYSTEM_SHELL"))
    event = only(monitor.check())

    assert event.change is ChangeType.NEW
    assert len(channel.alarms) == 2
    assert len(monitor.open_events()) == 2


def test_a_fresh_monitor_does_not_repeat_old_alarms(
    baseline: Baseline, root: Path, tmp_path: Path, channel: RecordingChannel
) -> None:
    write(root / "media" / "uploads" / "shell.php", marker("PHP_EVAL_SHELL"))
    store = SqliteSeenFindingStore(str(tmp_path / "alarms.db"))
    first = FileIntegrityMonitor(baseline, alarm_center=AlarmCenter(store, [channel]), file_scanner=lambda p: [])
    first.check()

    restarted = FileIntegrityMonitor(baseline, alarm_center=AlarmCenter(store, [channel]), file_scanner=lambda p: [])

    assert len(restarted.check()) == 1      # listed again as open
    assert len(channel.alarms) == 1         # but not announced twice


def test_low_and_medium_events_are_listed_but_silent(
    monitor: FileIntegrityMonitor, root: Path, channel: RecordingChannel
) -> None:
    write(root / "notes.txt")
    (root / "README.md").unlink()

    assert len(monitor.check()) == 2
    assert channel.alarms == []


def test_deleted_shell_stays_listed_as_evidence(monitor: FileIntegrityMonitor, root: Path) -> None:
    shell = write(root / "media" / "uploads" / "shell.php", marker("PHP_EVAL_SHELL"))
    monitor.check()

    shell.unlink()

    assert monitor.check() == []
    (open_event,) = monitor.open_events()
    assert open_event.severity is Severity.CRITICAL


# ---------------------------------------------------------------------------
# Code scan of changed files
# ---------------------------------------------------------------------------

def test_new_code_file_is_scanned_and_findings_alarm(
    baseline: Baseline, root: Path, tmp_path: Path, channel: RecordingChannel
) -> None:
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [channel])
    monitor = FileIntegrityMonitor(baseline, alarm_center=center)       # real scan engine
    write(root / "shop" / "tools.py", "import os\n\ndef run(cmd):\n    os.system(cmd)\n")

    event = only(monitor.check())

    assert event.findings, "the scan engine should report os.system"
    assert all(f.finding_key.endswith(event.state_key) for f in event.findings)
    assert any("Code scan:" in reason for reason in event.reasons)
    assert any(r.category is IssueCategory.COMMAND_EXEC for r in event.findings)


def test_deleted_files_are_not_scanned(monitor: FileIntegrityMonitor, root: Path) -> None:
    scanned: List[str] = []
    monitor._scan_file = lambda path: scanned.append(path) or []        # type: ignore[assignment]
    write(root / "shop" / "forms.py", "x = 1\n")
    (root / "README.md").unlink()

    monitor.check()

    assert [Path(p).name for p in scanned] == ["forms.py"]


def test_engine_scan_skips_files_it_cannot_scan(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from live_defense.file_integrity import OrchestratorFileScanner
    from scanner_engine import orchestrator

    def forbidden(self: object, target: str) -> None:
        raise AssertionError(f"scan engine started for {target}")

    monkeypatch.setattr(orchestrator.ScanOrchestrator, "scan", forbidden)
    photo = write(root / "media" / "uploads" / "photo.jpg", "jpg\n")

    assert OrchestratorFileScanner()(str(photo)) == []


def test_scan_findings_are_attached(baseline: Baseline, root: Path) -> None:
    finding = Issue(
        rule_id="B605", title="os.system", description="", severity=Severity.HIGH,
        file_path=str(root / "shop" / "tools.py"), line_number=4, category=IssueCategory.COMMAND_EXEC,
    )
    monitor = FileIntegrityMonitor(baseline, file_scanner=lambda path: [finding])
    write(root / "shop" / "tools.py", "x = 1\n")

    event = only(monitor.check())

    assert event.findings == [finding]
    assert event.reasons[-1] == "Code scan: 1 finding(s), worst HIGH"
