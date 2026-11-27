"""One hostile file must not hide the findings of the others.

A Python file with a 100,000-term expression used to raise RecursionError
in the AST analyzer, which aborted the whole Python engine: Django rules
and the other files' AST checks were skipped for every file sorted after
it. Also: files above the size cap, links that leave the scan root,
custom regex rules that do not compile or backtrack for ever, and the
folders the scan skips.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import List

import pytest

from oranovix_guardian.scanner_engine.base import BaseScanner, Issue, ScanResult, ScanStatus
from oranovix_guardian.scanner_engine.js_scanner import JSScanner
from oranovix_guardian.scanner_engine.orchestrator import ScanOrchestrator
from oranovix_guardian.scanner_engine.python_scanner import PythonScanner
from oranovix_guardian.scanner_engine.rule_engine import Rule, RuleEngine

DEEP_EXPRESSION = "y = " + " + ".join(["1"] * 100_000) + "\n"

SETTINGS = 'DEBUG = False\nALLOWED_HOSTS = ["*"]\nSECRET_KEY = os.environ["KEY"]\nimport os\n'
VIEWS = (
    "from django.utils.safestring import mark_safe\n"
    "from django.shortcuts import render\n\n"
    "def banner(request):\n"
    '    text = mark_safe("<b>%s</b>" % request.GET["banner"])\n'
    '    return render(request, "banner.html", {"banner": text})\n'
)
SECRETS = 'password = "S3cr3tPr0dPassw0rd!"\n'


def rules(issues: List[Issue]) -> set:
    return {rule for issue in issues for rule in (issue.rule_id, *issue.also_detected_by)}


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "shop"
    root.mkdir()
    (root / "settings.py").write_text(SETTINGS, encoding="utf-8")
    (root / "views.py").write_text(VIEWS, encoding="utf-8")
    (root / "secrets_module.py").write_text(SECRETS, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Per-file isolation
# ---------------------------------------------------------------------------

def test_the_findings_are_there_without_the_hostile_file(project: Path) -> None:
    found = rules(ScanOrchestrator().scan(str(project)).issues)

    assert {"DJ005", "DS001", "SEC001"} <= found


def test_a_deep_expression_does_not_hide_other_findings(project: Path) -> None:
    (project / "aaa_data.py").write_text(DEEP_EXPRESSION, encoding="utf-8")

    result = ScanOrchestrator().scan(str(project))

    assert {"DJ005", "DS001", "SEC001"} <= rules(result.issues)
    assert any("aaa_data.py" in w and "not analysed" in w for w in result.engine_warnings), result.engine_warnings


def test_the_python_engine_reports_the_file_and_completes(project: Path) -> None:
    (project / "aaa_data.py").write_text(DEEP_EXPRESSION, encoding="utf-8")

    result = PythonScanner().scan(str(project))

    assert result.status is ScanStatus.COMPLETED, result.error_message
    assert {"DJ005", "DS001"} <= rules(result.issues)
    warning = next(w for w in result.engine_warnings if "aaa_data.py" in w and "not analysed" in w)
    assert "not analysed" in warning and "RecursionError" in warning


def test_an_analyzer_crash_is_isolated_per_analyzer(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.scanner_engine.django_rules import DjangoAnalyzer

    def broken(code: str, file_path: str = "") -> List[Issue]:
        raise MemoryError("simulated")

    monkeypatch.setattr(DjangoAnalyzer, "analyze", staticmethod(broken))
    result = PythonScanner().scan(str(project))

    assert "DS001" in rules(result.issues)          # settings rules still ran
    assert "AST-SEC1" in rules(result.issues)       # AST rules still ran
    assert any("views.py" in w and "MemoryError" in w for w in result.engine_warnings)


@pytest.mark.parametrize("scanner_name", ["js", "php", "java", "csharp", "template", "secrets"])
def test_a_crashing_file_does_not_stop_the_other_scanners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner_name: str
) -> None:
    from oranovix_guardian.scanner_engine.csharp_scanner import CSharpScanner
    from oranovix_guardian.scanner_engine.django_template_rules import DjangoTemplateScanner
    from oranovix_guardian.scanner_engine.java_scanner import JavaScanner
    from oranovix_guardian.scanner_engine.php_scanner import PHPScanner
    from oranovix_guardian.scanner_engine.secrets_detector import SecretsDetector

    # Credentials and weak hashes only: shell-shaped lines on disk get locked
    # by an antivirus, and the scanner would then read nothing.
    scanners = {
        "js": (JSScanner, ".js", "_scan_file", 'const password = "S3cr3tPr0dPassw0rd";\n'),
        "php": (PHPScanner, ".php", "_scan_file", "<?php $h = md5($password); ?>\n"),
        "java": (JavaScanner, ".java", "_scan_file", 'String password = "S3cr3tPr0dPassw0rd";\n'),
        "csharp": (CSharpScanner, ".cs", "_scan_file", 'string password = "S3cr3tPr0dPassw0rd";\n'),
        "template": (DjangoTemplateScanner, ".html", "scan_file", "{{ value|safe }}\n"),
        "secrets": (SecretsDetector, ".env", "_scan_file", 'password = "S3cr3tPr0dPassw0rd!"\n'),
    }
    klass, extension, method, content = scanners[scanner_name]
    (tmp_path / f"a_broken{extension}").write_text(content, encoding="utf-8")
    (tmp_path / f"b_good{extension}").write_text(content, encoding="utf-8")
    original = getattr(klass, method)

    def flaky(self, path: str):
        if "a_broken" in path:
            raise RecursionError("maximum recursion depth exceeded")
        return original(self, path)

    monkeypatch.setattr(klass, method, flaky)
    result = klass().scan(str(tmp_path))

    assert result.status is ScanStatus.COMPLETED, result.error_message
    assert any("b_good" in issue.file_path for issue in result.issues)
    assert any("a_broken" in w and "not analysed" in w for w in result.engine_warnings)


def test_the_rule_engine_loop_is_isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    engine = RuleEngine(str(tmp_path / "rules"))
    engine.add_rule(Rule(id="C1", name="todo", description="", pattern=r"TODO", severity="LOW", language="ALL"))
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("# TODO\n", encoding="utf-8")
    (tmp_path / "src" / "b.py").write_text("# TODO\n", encoding="utf-8")
    original = RuleEngine.scan_file

    def flaky(self: RuleEngine, path: str, language, **kwargs):
        if path.endswith("a.py"):
            raise RecursionError("boom")
        return original(self, path, language, **kwargs)

    monkeypatch.setattr(RuleEngine, "scan_file", flaky)
    result = ScanOrchestrator(rule_engine=engine).scan(str(tmp_path / "src"))

    assert any(i.rule_id == "C1" and i.file_path.endswith("b.py") for i in result.issues)
    assert any("a.py" in w and "not analysed" in w for w in result.engine_warnings)


# ---------------------------------------------------------------------------
# Size cap
# ---------------------------------------------------------------------------

def test_a_file_above_the_size_cap_is_reported_as_skipped(project: Path) -> None:
    big = project / "big.js"
    with open(big, "w", encoding="utf-8") as handle:
        handle.write('const password = "S3cr3tPr0dPassw0rd";\n')
        handle.write(("// filler line " + "x" * 80 + "\n") * (6 * 1024 * 1024 // 96))
    assert big.stat().st_size > 6_000_000

    result = ScanOrchestrator().scan(str(project))

    assert not [i for i in result.issues if i.file_path.endswith("big.js")]
    skipped = [w for w in result.engine_warnings if "big.js" in w]
    assert skipped and all("not analysed" in w and "5 MB" in w for w in skipped)
    assert len(skipped) == 1, skipped                    # reported once, not per engine
    assert {"DJ005", "DS001"} <= rules(result.issues)


def test_the_size_cap_value() -> None:
    assert BaseScanner.MAX_FILE_BYTES == 5 * 1024 * 1024


# ---------------------------------------------------------------------------
# Links that leave the scan root
# ---------------------------------------------------------------------------

def _symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs extra rights on this system")


def _junction(target: Path, link: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("directory junctions exist on Windows only")
    import _winapi
    _winapi.CreateJunction(str(target), str(link))  # type: ignore[attr-defined]


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    folder = tmp_path / "outside"
    folder.mkdir()
    (folder / "secret.py").write_text('password = "OutsideSecret-123456"\n', encoding="utf-8")
    return folder


def test_a_symlink_to_a_file_outside_the_root_is_skipped(project: Path, outside: Path) -> None:
    _symlink(outside / "secret.py", project / "linked.py")

    assert str(project / "linked.py") not in BaseScanner.collect_files(str(project), [".py"])
    result = ScanOrchestrator().scan(str(project))
    assert not [i for i in result.issues if "OutsideSecret" in (i.code_snippet or "") or i.file_path.endswith("linked.py")]


def test_a_junction_to_a_folder_outside_the_root_is_skipped(project: Path, outside: Path) -> None:
    _junction(outside, project / "vendor_link")

    files = BaseScanner.collect_files(str(project), [".py"])

    assert not [f for f in files if "vendor_link" in f]
    result = ScanOrchestrator().scan(str(project))
    assert not [i for i in result.issues if "vendor_link" in i.file_path]


def test_a_link_inside_the_root_is_still_scanned(project: Path) -> None:
    inner = project / "lib"
    inner.mkdir()
    (inner / "x.py").write_text("x = 1\n", encoding="utf-8")
    _junction(inner, project / "lib_link")

    assert any("lib_link" in f for f in BaseScanner.collect_files(str(project), [".py"]))


# ---------------------------------------------------------------------------
# Custom rules
# ---------------------------------------------------------------------------

def _rules_file(tmp_path: Path, *patterns: str) -> Path:
    path = tmp_path / "import.json"
    path.write_text(json.dumps({"rules": [
        {"id": f"IMP-{i}", "name": f"rule {i}", "pattern": pattern, "severity": "LOW", "language": "ALL"}
        for i, pattern in enumerate(patterns)
    ]}), encoding="utf-8")
    return path


def test_an_invalid_imported_regex_is_rejected_with_a_message(tmp_path: Path) -> None:
    engine = RuleEngine(str(tmp_path / "rules"))

    count = engine.import_rules(str(_rules_file(tmp_path, r"valid\(", r"broken[(")))

    assert count == 1
    assert len(engine.last_rejected) == 1
    assert "IMP-1" in engine.last_rejected[0] and "regular expression" in engine.last_rejected[0]
    assert "IMP-1" not in {rule.id for rule in engine.rules}


def test_a_catastrophic_imported_regex_is_rejected(tmp_path: Path) -> None:
    engine = RuleEngine(str(tmp_path / "rules"))

    assert engine.import_rules(str(_rules_file(tmp_path, r"(a+)+$", r"(\w*)*x", r"(?:a|aa)+b"))) == 0
    assert len(engine.last_rejected) == 3


def test_add_rule_refuses_an_invalid_pattern(tmp_path: Path) -> None:
    from oranovix_guardian.scanner_engine.rule_engine import RulePatternError
    engine = RuleEngine(str(tmp_path / "rules"))

    with pytest.raises(RulePatternError):
        engine.add_rule(Rule(id="X", name="x", description="", pattern="[", severity="LOW", language="ALL"))


def test_a_slow_pattern_already_on_disk_cannot_hang_a_scan(tmp_path: Path) -> None:
    """Saved by an older version, so never validated on import: checked on load."""
    from oranovix_guardian.scanner_engine.base import Language
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "custom_rules.json").write_text(json.dumps({"rules": [
        {"id": "OLD", "name": "old", "pattern": r"(a|aa)*c", "severity": "LOW", "language": "ALL"},
        {"id": "OK", "name": "ok", "pattern": r"a{3}", "severity": "LOW", "language": "ALL"},
    ]}), encoding="utf-8")
    engine = RuleEngine(str(rules_dir))
    code = ("a" * 100_000) + "\n"

    started = time.perf_counter()
    issues = engine.scan(code, Language.PYTHON, "x.py")

    assert time.perf_counter() - started < 5
    assert any("OLD" in message for message in engine.last_rejected)
    assert {i.rule_id for i in issues} == {"OK"}


def test_long_lines_are_cut_before_matching(tmp_path: Path) -> None:
    from oranovix_guardian.scanner_engine.base import Language
    engine = RuleEngine(str(tmp_path / "rules"))
    engine.add_rule(Rule(id="C1", name="x", description="", pattern=r"needle", severity="LOW", language="ALL"))

    near = "x" * 10 + "needle"
    far = "x" * (RuleEngine.MAX_LINE_LENGTH + 10) + "needle"

    assert [i.line_number for i in engine.scan(f"{near}\n{far}\n", Language.PYTHON, "x.py") if i.rule_id == "C1"] == [1]


def test_patterns_are_compiled_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import re as re_module
    from oranovix_guardian.scanner_engine import rule_engine as module
    engine = RuleEngine(str(tmp_path / "rules"))
    engine.add_rule(Rule(id="C1", name="x", description="", pattern=r"needle\d", severity="LOW", language="ALL"))
    calls: List[str] = []
    real_compile = re_module.compile

    def counting(pattern, flags=0):
        calls.append(pattern)
        return real_compile(pattern, flags)

    monkeypatch.setattr(module.re, "compile", counting)
    from oranovix_guardian.scanner_engine.base import Language
    for _ in range(20):
        engine.scan("needle1\nneedle2\n", Language.PYTHON, "x.py")

    assert calls.count(r"needle\d") <= 1


def test_custom_patterns_run_per_line(tmp_path: Path) -> None:
    from oranovix_guardian.scanner_engine.base import Language
    engine = RuleEngine(str(tmp_path / "rules"))
    engine.add_rule(Rule(id="C1", name="x", description="", pattern=r"api_key", severity="LOW", language="ALL"))

    issues = [i for i in engine.scan("a = 1\nb = api_key\n\napi_key()\n", Language.PYTHON, "x.py") if i.rule_id == "C1"]

    assert [i.line_number for i in issues] == [2, 4]


# ---------------------------------------------------------------------------
# Which folders are scanned
# ---------------------------------------------------------------------------

def test_migrations_are_scanned(tmp_path: Path) -> None:
    (tmp_path / "app" / "migrations").mkdir(parents=True)
    (tmp_path / "app" / "migrations" / "0002_raw.py").write_text("x = 1\n", encoding="utf-8")

    assert any("migrations" in f for f in BaseScanner.collect_files(str(tmp_path), [".py"]))


@pytest.mark.parametrize("name", ["env", "build"])
def test_env_and_build_are_scanned_when_they_hold_source(tmp_path: Path, name: str) -> None:
    (tmp_path / name).mkdir()
    (tmp_path / name / "tasks.py").write_text("x = 1\n", encoding="utf-8")

    assert any(name in Path(f).parts for f in BaseScanner.collect_files(str(tmp_path), [".py"]))


@pytest.mark.parametrize("name", ["env", "build", "myvenv"])
def test_a_virtual_environment_is_skipped_whatever_its_name(tmp_path: Path, name: str) -> None:
    (tmp_path / name / "Lib").mkdir(parents=True)
    (tmp_path / name / "pyvenv.cfg").write_text("home = C:\\Python\n", encoding="utf-8")
    (tmp_path / name / "Lib" / "x.py").write_text("x = 1\n", encoding="utf-8")

    assert BaseScanner.collect_files(str(tmp_path), [".py"]) == []


@pytest.mark.parametrize("marker", ["bdist.win-amd64", "lib.linux-x86_64-cpython-313"])
def test_a_generated_build_folder_is_skipped(tmp_path: Path, marker: str) -> None:
    (tmp_path / "build" / marker).mkdir(parents=True)
    (tmp_path / "build" / marker / "x.py").write_text("x = 1\n", encoding="utf-8")

    assert BaseScanner.collect_files(str(tmp_path), [".py"]) == []


def test_a_pyinstaller_build_folder_is_skipped(tmp_path: Path) -> None:
    work = tmp_path / "build" / "app"
    work.mkdir(parents=True)
    (work / "Analysis-00.toc").write_text("x", encoding="utf-8")
    (work / "x.py").write_text("x = 1\n", encoding="utf-8")

    assert BaseScanner.collect_files(str(tmp_path), [".py"]) == []


@pytest.mark.parametrize("name", ["venv", ".venv", "node_modules", ".git", "site-packages", "__pycache__", "dist"])
def test_the_usual_folders_stay_excluded(tmp_path: Path, name: str) -> None:
    (tmp_path / name).mkdir()
    (tmp_path / name / "x.py").write_text("x = 1\n", encoding="utf-8")

    assert BaseScanner.collect_files(str(tmp_path), [".py"]) == []


def test_scan_result_type_is_unchanged() -> None:
    assert isinstance(ScanResult(target_path="x", scan_id="1").engine_warnings, list)
