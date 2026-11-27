"""Leftovers from the audit review: ReDoS in custom rules, eval aliases,
B605 severity, encoder-wrapped output, the README privacy limit, an honest
startup console and a shutdown that always closes the window."""
from __future__ import annotations

import ast
import json
import logging
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from oranovix_guardian.scanner_engine.ast_analyzer import ASTAnalyzer
from oranovix_guardian.scanner_engine.bandit_runner import BanditFinding
from oranovix_guardian.scanner_engine.base import Issue, Language, Severity
from oranovix_guardian.scanner_engine.categories import IssueCategory
from oranovix_guardian.scanner_engine.js_scanner import JSScanner
from oranovix_guardian.scanner_engine.php_scanner import PHPScanner
from oranovix_guardian.scanner_engine.python_scanner import BanditSeverityPolicy
from oranovix_guardian.scanner_engine.rule_engine import Rule, RuleEngine, check_pattern

ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# 1. Custom rule ReDoS
# ---------------------------------------------------------------------------

SLOW_COUNTED = [r"(.*a){8}X", r"(.*,){10}X", r"(?:.*=){6}X", r"(\w*b){3,}c", r"(a.+){2,5}z", r"(?:x\s*y+){4}"]


@pytest.mark.parametrize("pattern", SLOW_COUNTED)
def test_counted_repeat_of_an_unbounded_group_is_refused(pattern: str) -> None:
    assert "repeat" in check_pattern(pattern)


@pytest.mark.parametrize("pattern", [
    r"(\d{1,3}\.){3}\d{1,3}",      # an IP address: the inner repeat is bounded
    r"(ab){3}",
    r"(.*a){1}X",                  # counted once
    r"(?:[a-z]+\.)?example",       # optional, not counted
    r"password\s*=\s*\S+",
])
def test_harmless_counted_patterns_are_accepted(pattern: str) -> None:
    assert check_pattern(pattern) == ""


def test_importing_the_slow_rule_refuses_it(tmp_path: Path) -> None:
    path = tmp_path / "import.json"
    path.write_text(json.dumps({"rules": [
        {"id": "X1", "name": "slow", "pattern": r"(.*a){8}X", "severity": "LOW", "language": "ALL"},
    ]}), encoding="utf-8")
    engine = RuleEngine(str(tmp_path / "rules"))

    assert engine.import_rules(str(path)) == 0
    assert engine.last_rejected and "X1" in engine.last_rejected[0]


def _engine_with_unchecked_rule(tmp_path: Path, pattern: str) -> RuleEngine:
    """A custom rule that got past the static check (e.g. a shape it does not know)."""
    engine = RuleEngine(str(tmp_path / "rules"))
    engine.rules.append(Rule(id="X1", name="slow", description="", pattern=pattern,
                             severity="LOW", language="ALL", is_builtin=False))
    return engine


# The slow pattern can keep a thread busy for minutes, and a thread cannot be
# stopped. These checks run in a child process that is killed after a timeout.
_CHILD = r'''
import json, os, sys, time
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from oranovix_guardian.scanner_engine.base import Language
from oranovix_guardian.scanner_engine.rule_engine import Rule, RuleEngine
tmp = Path(sys.argv[2])
# Slow even for the regex module (which defuses (.*a){8}X on its own).
SLOW = r"(.*a){20}X"
engine = RuleEngine(str(tmp / "rules"))
engine.rules.append(Rule(id="X1", name="slow", description="", pattern=SLOW,
                         severity="LOW", language="ALL", is_builtin=False))
out = {}
started = time.perf_counter()
issues = engine.scan_file(str(tmp / "slow.py"), Language.PYTHON)
out["elapsed"] = time.perf_counter() - started
out["slow_hits"] = [i.line_number for i in issues if i.rule_id == "X1"]
out["fine_hits"] = [i.line_number for i in engine.scan_file(str(tmp / "fine.py"), Language.PYTHON)
                    if i.rule_id == "X1"]
out["warnings"] = list(engine.warnings)
if sys.argv[3] == "orchestrator":
    from oranovix_guardian.scanner_engine.orchestrator import ScanOrchestrator
    project = tmp / "project"
    project.mkdir()
    (project / "slow.js").write_text("a" * 200 + "b" * 800 + "\n", encoding="utf-8")
    engine2 = RuleEngine(str(tmp / "rules2"))
    engine2.rules.append(Rule(id="X1", name="slow", description="", pattern=SLOW,
                              severity="LOW", language="ALL", is_builtin=False))
    out["engine_warnings"] = ScanOrchestrator(rule_engine=engine2).scan(str(project)).engine_warnings
print(json.dumps(out))
'''


def _run_slow_rule(tmp_path: Path, mode: str = "engine") -> dict:
    import os
    import subprocess
    import sys
    (tmp_path / "slow.py").write_text("a" * 200 + "b" * 800 + "\n" + "a" * 20 + "X\n", encoding="utf-8")
    (tmp_path / "fine.py").write_text("a" * 20 + "X\n", encoding="utf-8")
    try:
        done = subprocess.run(
            [sys.executable, "-c", _CHILD, str(ROOT / "src"), str(tmp_path), mode],
            capture_output=True, text=True, timeout=60, env=dict(os.environ),
        )
    except subprocess.TimeoutExpired:
        pytest.fail("the scan with the slow rule did not finish within 60 s")
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_a_slow_custom_rule_is_stopped_and_reported(tmp_path: Path) -> None:
    pytest.importorskip("regex")
    out = _run_slow_rule(tmp_path)

    assert out["elapsed"] < 2.0, f"{out['elapsed']:.1f} s"
    assert [w for w in out["warnings"] if "X1" in w and "too slow" in w]
    assert out["slow_hits"] == [], "skipped for the rest of the file"


def test_a_stopped_rule_runs_again_on_the_next_file(tmp_path: Path) -> None:
    pytest.importorskip("regex")
    out = _run_slow_rule(tmp_path)

    assert out["fine_hits"] == [1]
    assert len(out["warnings"]) == 1, "one warning per rule"


def test_the_scan_result_carries_the_slow_rule_warning(tmp_path: Path) -> None:
    pytest.importorskip("regex")
    out = _run_slow_rule(tmp_path, "orchestrator")

    assert [w for w in out["engine_warnings"] if "X1" in w and "too slow" in w]


def test_regex_is_a_requirement_and_bundled() -> None:
    requirements = (ROOT / "src" / "requirements.txt").read_text(encoding="utf-8")
    assert any(line.strip().startswith("regex") for line in requirements.splitlines())
    build = (ROOT / "src" / "build_tools" / "build.ps1").read_text(encoding="utf-8")
    assert "regex" in build


# ---------------------------------------------------------------------------
# 2. eval / exec aliases
# ---------------------------------------------------------------------------

ALIASES = {
    "getattr_builtins": ('import builtins\ngetattr(builtins, "eval")(user_input)\n', 2),
    "assigned_alias": ("e = eval; e(user_input)\n", 1),
    "getattr_dunder": ('fn = getattr(__builtins__, "exec")\n', 1),
    "getattr_dunder_called": ('fn = getattr(__builtins__, "exec")\nfn(code)\n', 2),
    "globals_dict": ('globals()["__builtins__"]["eval"](x)\n', 1),
    "module_alias": ("import builtins as b; b.exec(x)\n", 1),
    "from_import_alias": ("from builtins import eval as ev\nev(x)\n", 2),
    "dunder_import": ('__import__("builtins").eval(x)\n', 1),
}


def code_exec_lines(code: str) -> List[Issue]:
    return [i for i in ASTAnalyzer.analyze(code, "app.py") if i.category is IssueCategory.CODE_EXEC]


@pytest.mark.parametrize("case", sorted(ALIASES))
def test_eval_and_exec_aliases_are_reported_like_eval(case: str) -> None:
    code, line = ALIASES[case]

    issues = code_exec_lines(code)

    hits = [i for i in issues if i.line_number == line]
    assert hits, (case, [(i.rule_id, i.line_number) for i in issues])
    assert all(i.severity is Severity.CRITICAL for i in hits)


@pytest.mark.parametrize("code", [
    'getattr(model, "eval")(batch)\n',
    "e = model.eval\ne()\n",
    'handlers = {}\nhandlers["eval"](x)\n',
    "import re\nc = re.compile\nc(pattern)\n",
    'getattr(builtins_like, "eval")\n',
])
def test_lookalikes_of_the_aliases_stay_quiet(code: str) -> None:
    assert code_exec_lines(code) == []


def test_plain_eval_still_behaves_as_before() -> None:
    (issue,) = code_exec_lines("eval(user_input)\n")
    assert issue.severity is Severity.CRITICAL
    (constant,) = code_exec_lines('eval("1 + 1")\n')
    assert constant.severity is Severity.MEDIUM


# ---------------------------------------------------------------------------
# 3. B605 severity
# ---------------------------------------------------------------------------

def b605(tmp_path: Path, code: str) -> Severity:
    path = tmp_path / "tool.py"
    path.write_text("import os\n" + code + "\n", encoding="utf-8")
    finding = BanditFinding(
        test_id="B605", test_name="start_process_with_a_shell", severity="HIGH", confidence="HIGH",
        line_number=2, file_path=str(path),
        text="Starting a process with a shell, possible injection detected, security issue.",
        code=code,
    )
    return BanditSeverityPolicy().severity(finding)


@pytest.mark.parametrize("code", [
    'os.system("defaults write -g NSRequiresAquaSystemAppearance -bool No")',
    "os.system('defaults delete -g NSRequiresAquaSystemAppearance')",
    'os.popen("uname -a").read()',
])
def test_b605_with_a_constant_command_is_medium(tmp_path: Path, code: str) -> None:
    assert b605(tmp_path, code) is Severity.MEDIUM


@pytest.mark.parametrize("code", [
    'os.system("rm -rf " + path)',
    "os.system(command)",
    'os.popen(f"ls {folder}")',
    'os.system("ping %s" % host)',
])
def test_b605_with_a_built_command_stays_critical(tmp_path: Path, code: str) -> None:
    assert b605(tmp_path, code) is Severity.CRITICAL


def test_b607_on_a_constant_shell_command_is_not_promoted(tmp_path: Path) -> None:
    """os.system("defaults ...") is also B607 (partial path); promoted to HIGH it
    would outrank the MEDIUM B605 when the two are merged on that line."""
    path = tmp_path / "tool.py"
    code = 'os.system("defaults write -g NSRequiresAquaSystemAppearance -bool No")'
    path.write_text("import os\n" + code + "\n", encoding="utf-8")
    finding = BanditFinding(
        test_id="B607", test_name="start_process_with_partial_path", severity="LOW", confidence="HIGH",
        line_number=2, file_path=str(path), text="Starting a process with a partial executable path",
        code=code,
    )
    assert BanditSeverityPolicy().severity(finding) is Severity.LOW


def test_customtkinter_window_code_has_no_critical_finding(tmp_path: Path) -> None:
    import importlib.util
    from oranovix_guardian.scanner_engine.python_scanner import PythonScanner

    spec = importlib.util.find_spec("customtkinter")
    if spec is None or not spec.submodule_search_locations:
        pytest.skip("customtkinter is not installed")
    windows = Path(list(spec.submodule_search_locations)[0]) / "windows"
    target = tmp_path / "windows"
    target.mkdir()
    for name in ("ctk_tk.py", "ctk_toplevel.py"):
        shutil.copy(windows / name, target / name)

    issues = PythonScanner().scan(str(target)).issues

    assert [(i.rule_id, i.line_number) for i in issues if i.severity is Severity.CRITICAL] == []
    assert any(i.rule_id == "B605" and i.severity is Severity.MEDIUM for i in issues)


# ---------------------------------------------------------------------------
# 4. JS017 with an encoder
# ---------------------------------------------------------------------------

def scan_one(tmp_path: Path, name: str, code: str) -> List[Issue]:
    target = tmp_path / name
    target.write_text(code + "\n", encoding="utf-8")
    scanner = JSScanner() if name.endswith(".js") else PHPScanner()
    return list(scanner.scan(str(target)).issues)


ENCODED_JS = [
    "res.send(escapeHtml(req.query.n));",
    "res.send(escape(req.query.n));",
    "res.send(encodeURIComponent(req.query.n));",
    "res.send(he.encode(req.query.n));",
    "res.send(validator.escape(req.body.comment));",
    "res.send(DOMPurify.sanitize(req.body.html));",
    "res.send(xss(req.body.html));",
    "res.send(sanitizeHtml(req.body.html));",
    "res.send('<h1>' + escapeHtml(req.query.n) + '</h1>');",
    "res.write(`<p>${escapeHtml(req.params.name)}</p>`);",
]


@pytest.mark.parametrize("code", ENCODED_JS)
def test_js017_is_quiet_when_an_encoder_wraps_the_value(tmp_path: Path, code: str) -> None:
    assert [i.rule_id for i in scan_one(tmp_path, "server.js", code) if i.rule_id == "JS017"] == []


@pytest.mark.parametrize("code", [
    "res.send(req.query.n);",
    "res.send('<h1>' + req.query.n);",
    "res.send(escapeHtml(title) + req.query.n);",
    "res.send(escapeHtml(req.query.a) + req.query.b);",
    "res.send(String(req.query.n));",
])
def test_js017_stays_high_without_an_encoder(tmp_path: Path, code: str) -> None:
    hits = [i for i in scan_one(tmp_path, "server.js", code) if i.rule_id == "JS017"]
    assert hits and hits[0].severity is Severity.HIGH


# ---------------------------------------------------------------------------
# 5. PHP005 with an encoder
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code", [
    "<?php echo htmlspecialchars($_GET['name'], ENT_QUOTES); ?>",
    "<?php echo htmlentities($_POST['comment']); ?>",
    "<?php echo intval($_GET['page']); ?>",
    "<?php echo (int)$_GET['id']; ?>",
    "<?php echo (int) $_REQUEST['id']; ?>",
    "<?php echo filter_var($_GET['email'], FILTER_SANITIZE_EMAIL); ?>",
    "<?php echo json_encode($_GET['q']); ?>",
    "<?php echo 'Hello ' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '!'; ?>",
])
def test_php005_is_quiet_when_an_encoder_wraps_the_value(tmp_path: Path, code: str) -> None:
    assert [i.rule_id for i in scan_one(tmp_path, "page.php", code) if i.rule_id == "PHP005"] == []


def test_php005_with_strip_tags_is_low(tmp_path: Path) -> None:
    hits = [i for i in scan_one(tmp_path, "page.php", "<?php echo strip_tags($_GET['name']); ?>")
            if i.rule_id == "PHP005"]
    assert [i.severity for i in hits] == [Severity.LOW]


@pytest.mark.parametrize("code", [
    "<?php echo $_GET['name']; ?>",
    "<?php echo 'Hi ' . $_GET['name']; ?>",
    "<?php echo htmlspecialchars($_GET['a']) . $_GET['b']; ?>",
    "<?php echo trim($_GET['name']); ?>",
])
def test_php005_stays_high_without_an_encoder(tmp_path: Path, code: str) -> None:
    hits = [i for i in scan_one(tmp_path, "page.php", code) if i.rule_id == "PHP005"]
    assert hits and hits[0].severity is Severity.HIGH


# ---------------------------------------------------------------------------
# 6. README: the limit of the redaction
# ---------------------------------------------------------------------------

def test_readme_states_what_redaction_does_not_catch() -> None:
    text = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    lower = text.lower()
    assert "secrets are removed before anything is sent." not in lower
    for phrase in ("bare variable name", "char arrays", "readme", "secret findings themselves are never sent"):
        assert phrase in lower, phrase


# ---------------------------------------------------------------------------
# 7. Honest startup console
# ---------------------------------------------------------------------------

def _state(**changes: Any) -> Any:
    from oranovix_guardian.gui.startup_report import StartupState
    values: Dict[str, Any] = dict(
        version="1.1.0", rules=12, osv_updated=None, osv_advisories=0,
        ai="off", live_defense=False, threat_feed=False, log_sentinel=False, language="English",
    )
    values.update(changes)
    return StartupState(**values)


def _lines(state: Any, lang: str = "en") -> List[str]:
    from oranovix_guardian.core.language_manager import LanguageManager
    from oranovix_guardian.gui.startup_report import startup_lines
    manager = LanguageManager()
    before = manager.current_lang
    manager.set_language(lang)
    try:
        return [text for text, _level in startup_lines(state)]
    finally:
        manager.set_language(before)


def test_the_console_shows_the_real_version_and_rule_count() -> None:
    from oranovix_guardian.core.version import APP_VERSION
    lines = _lines(_state(version=APP_VERSION, rules=37))
    assert APP_VERSION in lines[0]
    assert any("37" in line for line in lines)
    assert not any("license" in line.lower() for line in lines)


def test_the_console_says_when_the_vulnerability_database_is_missing_or_dated() -> None:
    from datetime import datetime
    missing = " ".join(_lines(_state()))
    present = " ".join(_lines(_state(osv_updated=datetime(2026, 11, 3, 8, 15), osv_advisories=4321)))
    assert "2026-11-03" in present and "4321" in present
    assert "2026-11-03" not in missing and missing != present


@pytest.mark.parametrize("ai", ["off", "offline", "online"])
def test_the_console_shows_each_ai_state_differently(ai: str) -> None:
    others = {state: " ".join(_lines(_state(ai=state))) for state in ("off", "offline", "online")}
    assert len(set(others.values())) == 3


def test_the_console_shows_which_monitors_are_on() -> None:
    all_off = _lines(_state())
    all_on = _lines(_state(live_defense=True, threat_feed=True, log_sentinel=True))
    assert all_off != all_on
    assert len(all_on) == len(all_off)


@pytest.mark.parametrize("lang", ["de", "ar"])
def test_the_console_is_translated(lang: str) -> None:
    english = _lines(_state(ai="online", live_defense=True))
    other = _lines(_state(ai="online", live_defense=True), lang)
    assert len(other) == len(english)
    assert sum(a != b for a, b in zip(english, other)) >= len(english) - 1


def test_collecting_the_state_needs_no_network_and_no_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.gui.startup_report import StartupState
    from oranovix_guardian.scanner_engine.gemini_config import GeminiConfig
    monkeypatch.setattr(GeminiConfig, "api_key", classmethod(lambda cls: ""))

    state = StartupState.collect()

    assert state.ai == "off"
    assert state.rules > 0
    from oranovix_guardian.core.version import APP_VERSION
    assert state.version == APP_VERSION


def test_the_ai_state_follows_key_and_consent(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.gui.startup_report import StartupState
    from oranovix_guardian.scanner_engine.gemini_config import GeminiConfig
    monkeypatch.setattr(GeminiConfig, "api_key", classmethod(lambda cls: "k" * 30))
    monkeypatch.setattr(GeminiConfig, "online_allowed", classmethod(lambda cls: False))
    assert StartupState.ai_state() == "offline"
    monkeypatch.setattr(GeminiConfig, "online_allowed", classmethod(lambda cls: True))
    assert StartupState.ai_state() == "online"
    monkeypatch.setattr(GeminiConfig, "api_key", classmethod(lambda cls: ""))
    assert StartupState.ai_state() == "off"


def test_the_scanner_page_has_no_fixed_boot_texts() -> None:
    source = (ROOT / "src" / "oranovix_guardian" / "gui" / "pages" / "scanner_page.py").read_text(encoding="utf-8")
    for fixed in ("v1.0 initializing", "Checking license", "Loading AI analyzer... ✓"):
        assert fixed not in source


# ---------------------------------------------------------------------------
# 8. Shutdown robustness
# ---------------------------------------------------------------------------

class _Monitor:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def shutdown(self, timeout=None) -> None:
        self.calls += 1
        if self.fail:
            raise RuntimeError("monitor thread did not stop")


class _Lock:
    def __init__(self) -> None:
        self.released = 0

    def release(self) -> None:
        self.released += 1


@pytest.mark.parametrize("failing", ["_live_defense", "_threat_hub", "_log_sentinel"])
def test_a_failing_monitor_shutdown_still_closes_the_window(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, failing: str
) -> None:
    import customtkinter as ctk
    from oranovix_guardian.gui.app import CodeGuardianApp

    closed: List[bool] = []
    monkeypatch.setattr(ctk.CTk, "destroy", lambda self: closed.append(True))
    app = CodeGuardianApp.__new__(CodeGuardianApp)      # no Tk window needed
    monitors = {name: _Monitor(fail=name == failing) for name in ("_live_defense", "_threat_hub", "_log_sentinel")}
    for name, monitor in monitors.items():
        setattr(app, name, monitor)
    lock = _Lock()
    setattr(app, "_instance", lock)

    callbacks = []
    app._closing = False
    app._pages = {}
    monkeypatch.setattr(type(app), "withdraw", lambda self: None)
    monkeypatch.setattr(type(app), "after", lambda self, delay, callback: callbacks.append(callback))
    with caplog.at_level(logging.ERROR):
        app._on_close()
        app._on_close()
        assert not closed and lock.released == 0
        deadline = time.monotonic() + 3
        while callbacks and time.monotonic() < deadline:
            callbacks.pop(0)()
            time.sleep(0.005)

    assert closed == [True]
    assert lock.released == 1
    assert all(monitor.calls == 1 for monitor in monitors.values())
    assert "monitor thread did not stop" in caplog.text


def test_destroy_handles_monitors_that_were_never_started(monkeypatch: pytest.MonkeyPatch) -> None:
    import customtkinter as ctk
    from oranovix_guardian.gui.app import CodeGuardianApp

    closed: List[bool] = []
    monkeypatch.setattr(ctk.CTk, "destroy", lambda self: closed.append(True))
    app = CodeGuardianApp.__new__(CodeGuardianApp)
    app._live_defense = app._threat_hub = app._log_sentinel = None

    app.destroy()

    assert closed == [True]


def test_ast_parses_this_file() -> None:
    ast.parse(Path(__file__).read_text(encoding="utf-8"))
