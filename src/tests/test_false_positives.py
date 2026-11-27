"""False positives found in the audit, and the true positives next to them.

Each case is scanned with the real engine (Bandit, AST, regex, merger).
"""
from __future__ import annotations

import importlib.util
import shutil
import textwrap
from pathlib import Path
from typing import List

import pytest

from oranovix_guardian.core.alarm_center import Alarm, AlarmCenter, AlarmChannel, AlarmLevel, SqliteSeenFindingStore
from oranovix_guardian.live_defense.base import ChangeType
from oranovix_guardian.live_defense.baseline import Baseline
from oranovix_guardian.live_defense.classifier import ChangeClassifier
from oranovix_guardian.live_defense.file_integrity import FileIntegrityMonitor
from oranovix_guardian.scanner_engine.ast_analyzer import ASTAnalyzer
from oranovix_guardian.scanner_engine.base import Issue, Severity
from oranovix_guardian.scanner_engine.categories import IssueCategory
from oranovix_guardian.scanner_engine.orchestrator import ScanOrchestrator


def scan_code(tmp_path: Path, code: str, name: str = "app.py") -> List[Issue]:
    target = tmp_path / "project" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(code), encoding="utf-8")
    return list(ScanOrchestrator().scan(str(target.parent)).issues)


def rule_ids(issues: List[Issue]) -> set:
    return {rule for issue in issues for rule in (issue.rule_id, *issue.also_detected_by)}


def ast_ids(code: str) -> List[str]:
    return [issue.rule_id for issue in ASTAnalyzer.analyze(textwrap.dedent(code), "x.py")]


# ---------------------------------------------------------------------------
# Dangerous call rule: only the builtins
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code", [
    "import re\npattern = re.compile(r'\\d+')\n",
    "model.eval()\n",
    "df.eval('a + b')\n",
    "pattern.exec('text')\n",
    "from re import compile as c\nc('x')\n",
    "from re import compile\ncompile('x')\n",
    "import regex\nregex.compile(user_pattern)\n",
    "def eval(x):\n    return x\neval(data)\n",
    "exec = runner.exec\nexec(job)\n",
    "class Model:\n    def eval(self):\n        return self\nModel().eval()\n",
], ids=[
    "re.compile", "model.eval", "df.eval", "pattern.exec", "compile-as-c", "compile-imported",
    "regex.compile", "eval-defined", "exec-assigned", "method-named-eval",
])
def test_methods_and_rebound_names_are_not_dangerous_calls(code: str) -> None:
    assert not [rule for rule in ast_ids(code) if rule in {"AST-EVA", "AST-EXE", "AST-COM"}]


@pytest.mark.parametrize("code, rule", [
    ("def view(request):\n    return eval(request.GET['x'])\n", "AST-EVA"),
    ("def run(user_code):\n    exec(user_code)\n", "AST-EXE"),
    ("def build(src):\n    return compile(src, 'f', 'exec')\n", "AST-COM"),
    ("import builtins\nbuiltins.eval(data)\n", "AST-EVA"),
    ("__builtins__.exec(data)\n", "AST-EXE"),
    ("from builtins import eval\neval(data)\n", "AST-EVA"),
    ("eval(f'1 + {x}')\n", "AST-EVA"),
])
def test_builtin_calls_with_dynamic_input_stay_critical(code: str, rule: str) -> None:
    issues = [i for i in ASTAnalyzer.analyze(code, "x.py") if i.rule_id == rule]

    assert len(issues) == 1
    assert issues[0].severity is Severity.CRITICAL


@pytest.mark.parametrize("code, rule", [
    ("eval('1 + 1')\n", "AST-EVA"),
    ("exec('import os')\n", "AST-EXE"),
    ("compile('x = 1', '<string>', 'exec')\n", "AST-COM"),
])
def test_builtin_calls_on_a_constant_string_are_medium(code: str, rule: str) -> None:
    issues = [i for i in ASTAnalyzer.analyze(code, "x.py") if i.rule_id == rule]

    assert len(issues) == 1
    assert issues[0].severity is Severity.MEDIUM


def test_eval_on_request_data_is_critical_through_the_whole_engine(tmp_path: Path) -> None:
    issues = scan_code(tmp_path, """
        def view(request):
            return eval(request.GET["x"])
    """)

    worst = [i for i in issues if i.category is IssueCategory.CODE_EXEC]
    assert worst and worst[0].severity is Severity.CRITICAL


def test_exec_on_user_code_is_critical_through_the_whole_engine(tmp_path: Path) -> None:
    issues = scan_code(tmp_path, """
        def run(user_code):
            exec(user_code)
    """)

    assert any(i.category is IssueCategory.CODE_EXEC and i.severity is Severity.CRITICAL for i in issues)


def test_eval_of_a_constant_is_not_critical_through_the_whole_engine(tmp_path: Path) -> None:
    issues = scan_code(tmp_path, "value = eval('1 + 1')\n")

    assert all(i.severity is not Severity.CRITICAL for i in issues)


# ---------------------------------------------------------------------------
# Hardcoded secrets: placeholders and non-secret names
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "test", "changeme", "CHANGE_ME_PLEASE", "xxxxxxxxxxxx", "example-secret-value", "dummy-password-1",
    "empty", "short7c", "https://example.org/reset", "/etc/app/password.txt", "./keys/dev.pem",
    "C:\\keys\\dev.pem", "<your-token-here>", "${DB_PASSWORD}", "{{ secret }}", "%(password)s",
    "your_api_key_here", "placeholder-value",
])
def test_placeholder_values_are_recognised(value: str) -> None:
    from oranovix_guardian.scanner_engine.secret_heuristics import SecretHeuristics
    assert SecretHeuristics.is_placeholder(value)


@pytest.mark.parametrize("value", ["SuperSecret123", "S3cr3tPr0dPassw0rd!", "AKIAQ5VXD2LPRN7MK4TB", "hunter2hunter2"])
def test_real_looking_values_are_not_placeholders(value: str) -> None:
    from oranovix_guardian.scanner_engine.secret_heuristics import SecretHeuristics
    assert not SecretHeuristics.is_placeholder(value)


@pytest.mark.parametrize("name", [
    "password_reset_url", "PASSWORD_FIELD", "token_header", "secret_name", "key_path", "password_label",
])
def test_names_that_hold_no_secret(name: str) -> None:
    from oranovix_guardian.scanner_engine.secret_heuristics import SecretHeuristics
    assert SecretHeuristics.is_non_secret_name(name)


def test_token_test_is_not_a_secret(tmp_path: Path) -> None:
    issues = scan_code(tmp_path, 'token = "test"\n')

    # Bandit may still list it at its own LOW severity; nothing promotes it.
    assert not [i for i in issues if i.category is IssueCategory.SECRET and i.severity is not Severity.LOW]
    assert "SEC001" not in rule_ids(issues) and "AST-SEC1" not in rule_ids(issues)


def test_placeholder_password_is_not_critical(tmp_path: Path) -> None:
    issues = scan_code(tmp_path, 'password = "changeme"\nsecret = "example-secret-value"\n')

    assert all(i.severity not in (Severity.CRITICAL, Severity.HIGH) for i in issues)


@pytest.mark.parametrize("code", [
    'password_reset_url = "/accounts/password/reset/"\n',
    'PASSWORD_FIELD = "password"\n',
    'PASSWORD_HEADER = "X-Password-Confirmation"\n',
    'def login(password_label="Your password please"):\n    return password_label\n',
    'connect(password_path="/run/secrets/db_password")\n',
])
def test_hardcoded_password_rules_skip_names_and_placeholders(tmp_path: Path, code: str) -> None:
    issues = scan_code(tmp_path, code)

    assert all(i.severity not in (Severity.CRITICAL, Severity.HIGH) for i in issues), [
        (i.rule_id, i.severity) for i in issues
    ]


def test_a_real_password_is_still_critical(tmp_path: Path) -> None:
    issues = scan_code(tmp_path, 'password = "S3cr3tPr0dPassw0rd!"\n')

    secrets = [i for i in issues if i.category is IssueCategory.SECRET]
    assert len(secrets) == 1
    assert secrets[0].severity is Severity.CRITICAL
    assert {"SEC001", "B105", "AST-SEC1"} <= rule_ids(secrets)


def test_a_real_password_argument_is_still_high(tmp_path: Path) -> None:
    issues = scan_code(tmp_path, 'connect(user="app", password="S3cr3tPr0dPassw0rd!")\n')

    reported = [i for i in issues if "B106" in (i.rule_id, *i.also_detected_by)]
    assert reported and reported[0].severity in (Severity.HIGH, Severity.CRITICAL)


# ---------------------------------------------------------------------------
# Weak hash: usedforsecurity=False
# ---------------------------------------------------------------------------

def test_md5_not_used_for_security_is_not_flagged() -> None:
    code = "import hashlib\ndigest = hashlib.md5(data, usedforsecurity=False).hexdigest()\n"

    assert "AST-CRY1" not in ast_ids(code)


def test_md5_for_security_is_still_flagged() -> None:
    assert "AST-CRY1" in ast_ids("import hashlib\ndigest = hashlib.md5(password).hexdigest()\n")


# ---------------------------------------------------------------------------
# Subprocess with a literal command list
# ---------------------------------------------------------------------------

def test_literal_command_list_is_not_promoted(tmp_path: Path) -> None:
    issues = scan_code(tmp_path, 'import subprocess\nsubprocess.run(["ls", "-l"])\n')

    assert all(i.severity not in (Severity.CRITICAL, Severity.HIGH) for i in issues), [
        (i.rule_id, i.severity) for i in issues
    ]


def test_dynamic_command_is_still_promoted(tmp_path: Path) -> None:
    issues = scan_code(tmp_path, 'import subprocess\ndef run(cmd):\n    subprocess.run([cmd, "-l"])\n')

    assert any(i.severity is Severity.HIGH and i.category is IssueCategory.COMMAND_EXEC for i in issues)


# ---------------------------------------------------------------------------
# Real packages: requests and urllib3
# ---------------------------------------------------------------------------

def _package_folder(name: str) -> Path:
    spec = importlib.util.find_spec(name)
    if spec is None or spec.origin is None:
        pytest.skip(f"{name} is not installed")
    return Path(spec.origin).parent


def test_requests_and_urllib3_have_no_critical_finding(tmp_path: Path) -> None:
    copy = tmp_path / "packages"
    for name in ("requests", "urllib3"):
        shutil.copytree(_package_folder(name), copy / name, ignore=shutil.ignore_patterns("__pycache__"))

    result = ScanOrchestrator().scan(str(copy))

    critical = [(Path(i.file_path).name, i.line_number, i.rule_id) for i in result.issues
                if i.severity is Severity.CRITICAL]
    assert result.files_scanned > 50
    assert critical == []


# ---------------------------------------------------------------------------
# Live Defense: a changed file rings CRITICAL only for real danger
# ---------------------------------------------------------------------------

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


@pytest.fixture
def site(tmp_path: Path) -> Path:
    root = tmp_path / "site"
    (root / "shop").mkdir(parents=True)
    (root / "shop" / "views.py").write_text("def index(request):\n    return None\n", encoding="utf-8")
    return root


def _monitor(site: Path, tmp_path: Path, channel: RecordingChannel, scanner=None) -> FileIntegrityMonitor:
    baseline = Baseline(str(site), str(tmp_path / "integrity.db"), MemoryKeyStore())
    baseline.create()
    center = AlarmCenter(SqliteSeenFindingStore(str(tmp_path / "alarms.db")), [channel])
    if scanner is None:
        return FileIntegrityMonitor(baseline, alarm_center=center)
    return FileIntegrityMonitor(baseline, alarm_center=center, file_scanner=scanner)


def _modify(path: Path, text: str) -> None:
    import os
    before = path.stat().st_mtime_ns
    path.write_text(text, encoding="utf-8")
    os.utime(path, ns=(before + 2_000_000_000, before + 2_000_000_000))


def test_views_gaining_re_compile_rings_no_critical_alarm(site: Path, tmp_path: Path) -> None:
    channel = RecordingChannel()
    monitor = _monitor(site, tmp_path, channel)
    _modify(site / "shop" / "views.py", (
        "import re\n\nSLUG = re.compile(r'^[a-z0-9-]+$')\n\n"
        "def index(request):\n    return SLUG.match(request.GET.get('s', ''))\n"
    ))

    events = monitor.check()

    assert len(events) == 1
    assert events[0].severity is not Severity.CRITICAL
    assert not [a for a in channel.alarms if a.level is AlarmLevel.CRITICAL]


def test_views_gaining_eval_on_request_data_rings_critical(site: Path, tmp_path: Path) -> None:
    channel = RecordingChannel()
    monitor = _monitor(site, tmp_path, channel)
    _modify(site / "shop" / "views.py", "def index(request):\n    return eval(request.GET['q'])\n")

    events = monitor.check()

    assert events[0].severity is Severity.CRITICAL
    assert [a for a in channel.alarms if a.level is AlarmLevel.CRITICAL]


def _finding(category: IssueCategory, severity: Severity = Severity.CRITICAL) -> Issue:
    return Issue(
        rule_id="X1", title="Finding", description="", severity=severity, file_path="app/x.py",
        line_number=3, category=category, confidence="HIGH",
    )


@pytest.mark.parametrize("category", [
    IssueCategory.SQL_INJECTION, IssueCategory.XSS, IssueCategory.WEAK_CRYPTO, IssueCategory.TLS,
    IssueCategory.DESERIALIZATION, IssueCategory.MISCONFIGURATION,
])
def test_other_findings_cap_a_modified_file_at_medium(category: IssueCategory) -> None:
    severity, _ = ChangeClassifier().classify(ChangeType.MODIFIED, "app/x.py", findings=[_finding(category)])

    assert severity is Severity.MEDIUM


def test_other_findings_in_a_new_file_never_make_it_critical() -> None:
    severity, _ = ChangeClassifier().classify(
        ChangeType.NEW, "app/x.py", findings=[_finding(IssueCategory.SQL_INJECTION)]
    )

    assert severity is Severity.HIGH


@pytest.mark.parametrize("category", [IssueCategory.SECRET, IssueCategory.CODE_EXEC])
def test_secrets_and_dynamic_code_execution_stay_critical(category: IssueCategory) -> None:
    severity, _ = ChangeClassifier().classify(ChangeType.MODIFIED, "app/x.py", findings=[_finding(category)])

    assert severity is Severity.CRITICAL


def test_capped_findings_do_not_ring_critical_on_their_own(site: Path, tmp_path: Path) -> None:
    channel = RecordingChannel()
    sql = _finding(IssueCategory.SQL_INJECTION)
    monitor = _monitor(site, tmp_path, channel, scanner=lambda path: [sql])
    _modify(site / "shop" / "views.py", "def index(request):\n    return 1\n")

    event = monitor.check()[0]

    assert event.severity is Severity.MEDIUM
    assert all(f.severity is Severity.MEDIUM for f in event.findings)
    assert not [a for a in channel.alarms if a.level is AlarmLevel.CRITICAL]
