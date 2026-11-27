"""Normalisation and single-request rules, measured on a true and a false positive corpus.

The payloads live as plain text lines in tests/fixtures/log_sentinel; the
encoded and mixed case variants are built here at runtime.
"""
from __future__ import annotations

import base64
import random
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import quote

import pytest

from oranovix_guardian.core.app_paths import AppPaths
from oranovix_guardian.log_sentinel.entry import AccessLogEntry
from oranovix_guardian.log_sentinel.normalize import NormalizedRequest, RequestNormalizer
from oranovix_guardian.log_sentinel.rules import (
    REQUEST_RULES,
    AttackCategory,
    RequestAnalyzer,
    ResponseJudge,
    SqlInjectionRule,
    raise_severity,
)
from oranovix_guardian.scanner_engine.base import Severity

CORPUS = Path(__file__).parent / "fixtures" / "log_sentinel"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/132.0"


@dataclass(frozen=True)
class Sample:
    rule: str
    target: str
    status: int
    agent: str
    variant: str = "as logged"


def read_corpus(name: str, with_rule: bool) -> List[Sample]:
    samples = []
    for line in (CORPUS / name).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        rule = fields.pop(0) if with_rule else ""
        target, status, agent = (fields + ["-", "-"])[:3]
        samples.append(Sample(rule, target, 404 if status == "-" else int(status),
                              BROWSER if agent == "-" else agent))
    return samples


def entry_for(sample: Sample, status: int = 0, size: int = 153) -> AccessLogEntry:
    path, _, query = sample.target.partition("?")
    return AccessLogEntry(None, "203.0.113.7", "GET", path, query, status or sample.status, size,
                          user_agent=sample.agent)


# ---------------------------------------------------------------------------
# Variants made at runtime
# ---------------------------------------------------------------------------

def double_encoded(target: str) -> str:
    """Every character outside the structure encoded twice: ' becomes %2527."""
    path, sep, query = target.partition("?")
    def twice(text: str, safe: str) -> str:
        return quote(quote(text, safe=safe), safe=safe)
    if not query:
        return twice(path, "/")
    params = "&".join(
        f"{key}={twice(value, '')}" if eq else twice(key, "")
        for key, eq, value in (part.partition("=") for part in query.split("&"))
    )
    return f"{path}{sep}{params}"


def mixed_case(text: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(text))


def variants(sample: Sample) -> List[Sample]:
    found = [sample]
    if sample.target != "/":
        found.append(Sample(sample.rule, double_encoded(sample.target), sample.status, sample.agent, "double encoded"))
        found.append(Sample(sample.rule, mixed_case(sample.target), sample.status, sample.agent, "mixed case"))
    else:
        found.append(Sample(sample.rule, sample.target, sample.status, mixed_case(sample.agent), "mixed case agent"))
    return found


TRUE_POSITIVES = [variant for sample in read_corpus("true_positives.txt", True) for variant in variants(sample)]


def benign_base64_image() -> str:
    """A long data URL in a query, as some image editors send it."""
    generator = random.Random(20261116)
    data = base64.b64encode(bytes(generator.randrange(256) for _ in range(6000))).decode()
    return "/editor/preview/?img=data:image/png;base64," + quote(data, safe="")


FALSE_POSITIVES = read_corpus("false_positives.txt", False) + [
    Sample("", benign_base64_image(), 200, BROWSER),
    Sample("", "/editor/preview/?img=data:image/png;base64," + base64.b64encode(b"\x89PNG" * 900).decode(), 200, BROWSER),
]


# ---------------------------------------------------------------------------
# Normaliser
# ---------------------------------------------------------------------------

def test_normaliser_undoes_encodings_and_tricks() -> None:
    normalizer = RequestNormalizer()
    request = normalizer.normalize("/item", "id=1%2527%2F**%2FUnIoN%2F**%2FSeLeCt%2B1%23%00")

    assert request.encoding_rounds == 2
    assert request.had_null_byte is True
    assert request.decoded == "/item?id=1'/**/union/**/select 1#"
    assert request.text == "/item?id=1' union select 1"
    assert request.params == (("id", "1'/**/union/**/select 1#"),)


def test_normaliser_full_width_and_overlong_forms() -> None:
    normalizer = RequestNormalizer()
    assert normalizer.normalize("/x", "q=%EF%BC%9Cscript%EF%BC%9E").decoded == "/x?q=<script>"
    assert normalizer.normalize("/..%c0%af..%c0%afetc/passwd").path == "/../../etc/passwd"
    assert normalizer.normalize("/%u002e%u002e/x").path == "/../x"


def test_normaliser_stops_after_three_rounds() -> None:
    four_times = "%25252527"          # ' encoded four times
    assert RequestNormalizer().normalize("/x", "q=" + four_times).query == "q=%27"


def test_plus_is_a_space_only_in_the_query() -> None:
    request = RequestNormalizer().normalize("/c++/guide", "q=c+guide")
    assert request.path == "/c++/guide" and request.query == "q=c guide"


# ---------------------------------------------------------------------------
# The corpora
# ---------------------------------------------------------------------------

def test_true_positive_corpus_has_eight_payloads_per_family() -> None:
    per_rule: Dict[str, int] = defaultdict(int)
    for sample in read_corpus("true_positives.txt", True):
        per_rule[sample.rule] += 1
    assert set(per_rule) == {rule.rule_id for rule in REQUEST_RULES}
    assert min(per_rule.values()) >= 8, dict(per_rule)


@pytest.mark.parametrize("sample", TRUE_POSITIVES, ids=lambda s: f"{s.rule}:{s.variant}:{s.target[:40]}")
def test_true_positive_is_found(sample: Sample) -> None:
    analyzer = RequestAnalyzer()
    fired = {d.rule_id for d in analyzer.analyze(entry_for(sample))}
    assert sample.rule in fired, f"{sample.variant}: {sample.target} {sample.agent}"


def test_no_rule_fires_on_the_false_positive_corpus() -> None:
    analyzer = RequestAnalyzer()
    noisy: List[Tuple[str, str, str]] = []
    for sample in FALSE_POSITIVES:
        for detection in analyzer.analyze(entry_for(sample)):
            noisy.append((detection.rule_id, sample.target[:80], detection.evidence))
    assert noisy == []


def normalized(sample: Sample) -> NormalizedRequest:
    entry = entry_for(sample)
    return RequestNormalizer().normalize(entry.path, entry.query, entry.user_agent)


def test_every_rule_is_measured_on_both_corpora() -> None:
    """Precision per rule: hits on the attacks, and none on the ordinary traffic."""
    hits: Dict[str, Set[str]] = defaultdict(set)
    false: Dict[str, int] = defaultdict(int)
    for rule in REQUEST_RULES:
        for sample in TRUE_POSITIVES:
            request = normalized(sample)
            if rule.rule_id == sample.rule and rule.find(request, entry_for(sample)):
                hits[rule.rule_id].add(sample.target + sample.agent)
        for sample in FALSE_POSITIVES:
            request = normalized(sample)
            if rule.find(request, entry_for(sample)):
                false[rule.rule_id] += 1
    expected = defaultdict(set)
    for sample in TRUE_POSITIVES:
        expected[sample.rule].add(sample.target + sample.agent)
    for rule in REQUEST_RULES:
        assert hits[rule.rule_id] == expected[rule.rule_id], rule.rule_id
        assert false[rule.rule_id] == 0, rule.rule_id


# ---------------------------------------------------------------------------
# Severity and the answer of the server
# ---------------------------------------------------------------------------

SQLI = Sample("LS101", "/item?id=1%27%20UNION%20SELECT%201,2,3--", 404, BROWSER)


@pytest.mark.parametrize("status", [400, 403, 404, 405, 444, 500, 301])
def test_refused_attack_keeps_its_base_severity(status: int) -> None:
    (detection,) = [d for d in RequestAnalyzer().analyze(entry_for(SQLI, status)) if d.rule_id == "LS101"]
    assert detection.severity is Severity.HIGH
    assert [r.key for r in detection.reasons] == ["ls_reason_pattern"]


def test_attack_answered_with_a_real_page_is_one_level_higher() -> None:
    analyzer = RequestAnalyzer()
    for _ in range(3):
        analyzer.analyze(entry_for(Sample("", "/nothing-here/", 404, BROWSER), 404, size=153))

    (detection,) = analyzer.analyze(entry_for(SQLI, 200, size=48211))

    assert detection.severity is Severity.CRITICAL
    assert detection.reasons[-1].key == "ls_reason_answered"
    assert detection.reasons[-1].kwargs() == {"status": "200"}


def test_200_with_the_size_of_the_error_page_is_not_raised() -> None:
    analyzer = RequestAnalyzer()
    for _ in range(3):
        analyzer.analyze(entry_for(Sample("", "/missing/", 404, BROWSER), 404, size=153))

    (detection,) = analyzer.analyze(entry_for(SQLI, 200, size=153))

    assert detection.severity is Severity.HIGH


def test_a_catch_all_page_stops_raising() -> None:
    analyzer = RequestAnalyzer()
    severities = [analyzer.analyze(entry_for(SQLI, 200, size=3999))[0].severity for _ in range(8)]
    assert severities[:4] == [Severity.CRITICAL] * 4
    assert severities[-1] is Severity.HIGH       # the same 200 page for every probe


def test_probe_rules_are_not_raised_and_a_present_panel_is_not_judged() -> None:
    analyzer = RequestAnalyzer()
    scanner = Sample("LS111", "/", 200, "sqlmap/1.7")
    assert [(d.rule_id, d.severity) for d in analyzer.analyze(entry_for(scanner, 200, 9000))] == [("LS111", Severity.MEDIUM)]
    assert analyzer.analyze(entry_for(Sample("", "/wp-login.php", 200, BROWSER), 200, 9000)) == []
    (panel,) = analyzer.analyze(entry_for(Sample("", "/wp-login.php", 404, BROWSER), 404))
    assert (panel.rule_id, panel.severity, panel.category) == ("LS110", Severity.LOW, AttackCategory.ADMIN_PROBE)


def test_judge_memory_is_bounded() -> None:
    judge = ResponseJudge()
    for size in range(10_000):
        judge.observe(AccessLogEntry(None, "x", "GET", "/", "", 404, size + 1))
    assert len(judge.error_sizes) <= ResponseJudge.MAX_SIZES


def test_raise_severity_stops_at_critical() -> None:
    assert raise_severity(Severity.LOW) is Severity.MEDIUM
    assert raise_severity(Severity.CRITICAL) is Severity.CRITICAL


def test_rule_texts_have_keys() -> None:
    rule = SqlInjectionRule()
    assert (rule.title_key, rule.explanation_key) == ("ls_rule_ls101", "ls_rule_ls101_explain")


@pytest.mark.parametrize("language", ["en", "de", "ar"])
def test_every_rule_has_a_title_and_an_explanation(language: str) -> None:
    import json as json_module

    texts = json_module.loads((AppPaths.resource("translations") / f"{language}.json").read_text("utf-8"))
    keys = [key for rule in REQUEST_RULES for key in (rule.title_key, rule.explanation_key)]
    keys += [f"ls_rule_{rule_id}{suffix}" for rule_id in ("ls201", "ls202", "ls203", "ls204", "ls301")
             for suffix in ("", "_explain")]
    keys += ["ls_reason_pattern", "ls_reason_answered"]
    assert [key for key in keys if not texts.get(key)] == []
