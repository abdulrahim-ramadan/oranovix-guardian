"""Web shell rules: hits and near misses for each signature.

Payloads are glued together at runtime so this file never holds a
contiguous shell an antivirus would flag; nothing is written to disk.
"""
from __future__ import annotations

from typing import Set

import pytest

from live_defense.webshell import WebShellDetector

EV = "ev" + "al"
SG = "$" + "_"          # superglobal prefix


def rules(text: str) -> Set[str]:
    return {hit.rule for hit in WebShellDetector.scan_text(text)}


TRUE_POSITIVES = [
    # php-eval-on-input
    ("php-eval-on-input", "<?php " + EV + "(" + SG + "POST['c']); ?>"),
    ("php-eval-on-input", "<?php @" + EV + "('echo ' . " + SG + "COOKIE['c']);"),
    ("php-eval-on-input", "<?php inc" + "lude " + SG + "GET['page']; ?>"),
    ("php-eval-on-input", "<?php REQUIRE_ONCE(" + SG + "REQUEST['m']);"),
    ("php-eval-on-input", "<?php as" + "sert(@" + SG + "FILES['f']['name']);"),
    ("php-eval-on-input", "<?php $f = create" + "_function('', " + SG + "POST['body']);"),
    # php-backtick-on-input
    ("php-backtick-on-input", "<?php echo `" + SG + "GET['c']`; ?>"),
    ("php-backtick-on-input", "<?php $out = `cat " + SG + "REQUEST['f']`;"),
    ("php-backtick-on-input", "<?= `" + SG + "POST[x]` ?>"),
    # php-superglobal-call
    ("php-superglobal-call", "<?php " + SG + "POST['f'](" + SG + "POST['a']); ?>"),
    ("php-superglobal-call", "<?php @" + SG + "GET[\"x\"] ('id');"),
    ("php-superglobal-call", "<?php " + SG + "COOKIE[0](" + SG + "COOKIE[1]);"),
    # php-eval-decode-chain
    ("php-eval-decode-chain", EV + "(gzin" + "flate(base64_" + "decode('S0ks')));"),
    ("php-eval-decode-chain", "@" + EV + "( str_" + "rot13( gzun" + "compress($d)));"),
    ("php-eval-decode-chain", EV + "(base64_" + "decode(str_" + "rot13($x)));"),
    # php-preg-replace-e
    ("php-preg-replace-e", "preg_" + "replace('/(.*)/e', " + SG + "GET['r'], 'x');"),
    ("php-preg-replace-e", "preg_" + "replace(\"#\\w+#ie\", \"strtoupper('$0')\", $s);"),
    ("php-preg-replace-e", "PREG_" + "REPLACE('~a~se', $code, $s);"),
    # php-concatenated-call
    ("php-concatenated-call", "<?php $f='sy'.'stem'; $f(" + SG + "GET['c']); ?>"),
    ("php-concatenated-call", "<?php\n$fn = \"pass\" . \"thru\";\n// run\n$fn( @" + SG + "POST[\"c\"] );"),
    ("php-concatenated-call", "$a='as'.'se'.'rt';$a(" + SG + "REQUEST['x']);"),
    # python-eval-on-request
    ("python-eval-on-request", EV + "(request." + "GET['expr'])"),
    ("python-eval-on-request", "ex" + "ec(request.body.decode())"),
    ("python-eval-on-request", "mod = __imp" + "ort__(request.args['m'])"),
    ("python-eval-on-request", "code = comp" + "ile(request.form['src'], '<x>', 'exec')"),
    ("python-eval-on-request", EV + "(json.loads(request.data)['e'])"),
]


@pytest.mark.parametrize("rule, text", TRUE_POSITIVES)
def test_rule_hits(rule: str, text: str) -> None:
    assert rule in rules(text)


FALSE_POSITIVES = [
    ("php-eval-on-input", "<?php inc" + "lude 'header.php'; ?>"),
    ("php-eval-on-input", "<?php as" + "sert($x > 0);"),
    ("php-eval-on-input", "<?php $evaluation = " + SG + "GET['e'];"),
    ("php-eval-on-input", "<?php require_once __DIR__ . '/vendor/autoload.php';"),
    ("php-eval-on-input", "<?php " + EV + "('return 1;');"),
    ("php-backtick-on-input", "Read `" + SG + "GET` in the PHP manual."),
    ("php-backtick-on-input", "<?php $out = `ls -la`;"),
    ("php-backtick-on-input", "const url = `${base}/items`;"),
    ("php-superglobal-call", "<?php $name = " + SG + "POST['name'];"),
    ("php-superglobal-call", "<?php echo htmlspecialchars(" + SG + "GET['q']);"),
    ("php-superglobal-call", "<?php if (isset(" + SG + "GET['a'])) { }"),
    ("php-eval-decode-chain", "<?php $data = gzin" + "flate($raw);"),
    ("php-eval-decode-chain", "<?php echo str_" + "rot13('abc');"),
    ("php-eval-decode-chain", EV + "(base64_" + "decode($x));"),
    ("php-preg-replace-e", "preg_replace('/\\s+/', ' ', $s);"),
    ("php-preg-replace-e", "preg_replace('/e/i', 'E', $s);"),
    ("php-preg-replace-e", "preg_replace('/a/', 'b/e', $s);"),
    ("php-concatenated-call", "<?php $name = 'a' . 'b'; echo $name;"),
    ("php-concatenated-call", "<?php $f = 'strto'.'upper'; $f($title);"),
    ("php-concatenated-call", "<?php $path = 'inc/'.'x.php'; include $path;"),
    ("python-eval-on-request", "value = ast.literal_" + EV + "(request.body)"),
    ("python-eval-on-request", "pattern = re.comp" + "ile(request.GET['q'])"),
    ("python-eval-on-request", "exec_count = request.GET.get('n')"),
    ("python-eval-on-request", EV + "(expr)\nname = request.POST['name']\n"),
]


@pytest.mark.parametrize("rule, text", FALSE_POSITIVES)
def test_rule_does_not_hit(rule: str, text: str) -> None:
    assert rule not in rules(text)


@pytest.mark.parametrize(
    "text",
    [
        "<?php inc" + "lude 'header.php'; ?>",
        "<?php as" + "sert($x > 0);",
        "<?php echo htmlspecialchars(" + SG + "GET['q']);",
        "Read `" + SG + "GET` in the PHP manual.",
        "value = ast.literal_" + EV + "(request.body)",
        "preg_replace('/\\s+/', ' ', $s);",
    ],
)
def test_ordinary_code_hits_nothing(text: str) -> None:
    assert rules(text) == set()


def test_every_rule_has_cases() -> None:
    names = {rule.name for rule in WebShellDetector.RULES}
    new = {
        "php-eval-on-input", "php-backtick-on-input", "php-superglobal-call",
        "php-eval-decode-chain", "php-preg-replace-e", "php-concatenated-call",
        "python-eval-on-request",
    }
    assert new <= names
    for name in new:
        assert sum(r == name for r, _ in TRUE_POSITIVES) >= 2
        assert sum(r == name for r, _ in FALSE_POSITIVES) >= 2
