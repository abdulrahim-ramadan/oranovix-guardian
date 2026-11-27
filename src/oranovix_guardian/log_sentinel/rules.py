"""
Attack rules for single requests.

One class per rule. A rule looks at the normalised request and returns
the piece of text that gave it away, or nothing. The patterns ask for
the structure of an attack (a quote before ``OR 1=1``, a call after
``sleep``), not for words, so ``/blog/union-select-guide/`` or a search
for ``O'Brien`` stay quiet.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Pattern, Sequence, Tuple

from oranovix_guardian.scanner_engine.base import Severity

from .entry import AccessLogEntry
from .normalize import NormalizedRequest, RequestNormalizer


class AttackCategory(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    REMOTE_FILE_INCLUSION = "remote_file_inclusion"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    TEMPLATE_INJECTION = "template_injection"
    LOG4J = "log4j"
    SENSITIVE_FILE = "sensitive_file"
    ADMIN_PROBE = "admin_probe"
    SCANNER = "scanner"
    BRUTE_FORCE = "brute_force"
    PATH_SCAN = "path_scan"
    FLOOD = "flood"
    PLANTED_FILE = "planted_file"


SEVERITY_ORDER = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def raise_severity(severity: Severity) -> Severity:
    return SEVERITY_ORDER[min(SEVERITY_ORDER.index(severity) + 1, len(SEVERITY_ORDER) - 1)]


@dataclass(frozen=True)
class Reason:
    """A translatable sentence: a text key and its values."""

    key: str
    args: Tuple[Tuple[str, str], ...] = ()

    @classmethod
    def of(cls, key: str, **args: object) -> "Reason":
        return cls(key, tuple((name, str(value)) for name, value in args.items()))

    def kwargs(self) -> Dict[str, str]:
        return dict(self.args)


@dataclass(frozen=True)
class Detection:
    """A rule fired on a request (or, for behaviour rules, on a series of them)."""

    rule_id: str
    category: AttackCategory
    severity: Severity
    entry: AccessLogEntry
    evidence: str
    reasons: Tuple[Reason, ...] = ()
    normalized: str = ""

    @property
    def title_key(self) -> str:
        return f"ls_rule_{self.rule_id.lower()}"

    @property
    def explanation_key(self) -> str:
        return f"ls_rule_{self.rule_id.lower()}_explain"


class AttackRule(ABC):
    """One kind of attack in one request."""

    rule_id: str = ""
    category: AttackCategory = AttackCategory.SQL_INJECTION
    severity: Severity = Severity.MEDIUM
    # A payload that got a real 200 answer may have worked: one level higher.
    raise_on_success: bool = True

    @property
    def title_key(self) -> str:
        return f"ls_rule_{self.rule_id.lower()}"

    @property
    def explanation_key(self) -> str:
        return f"ls_rule_{self.rule_id.lower()}_explain"

    @abstractmethod
    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        """The evidence, or ``""`` when the rule does not apply."""

    @staticmethod
    def first(patterns: Iterable[Pattern[str]], *texts: str) -> str:
        for pattern in patterns:
            for text in texts:
                if not text:
                    continue
                match = pattern.search(text)
                if match:
                    return match.group(0)[:120]
        return ""


def _p(pattern: str) -> Pattern[str]:
    return re.compile(pattern)


def _any(*patterns: Pattern[str]) -> Tuple[Pattern[str]]:
    """One search instead of many: the alternatives of a rule as a single pattern.

    Only for patterns without back references, whose group numbers would shift.
    """
    return (re.compile("|".join(f"(?:{pattern.pattern})" for pattern in patterns)),)


# ---------------------------------------------------------------------------
# Injection
# ---------------------------------------------------------------------------

class SqlInjectionRule(AttackRule):
    rule_id = "LS101"
    category = AttackCategory.SQL_INJECTION
    severity = Severity.HIGH

    _ON_TEXT = (
        # 1=1 style tautology after a quote, bracket or number
        _p(r"(?:['\")]|\d) ?(?:or|and|xor|\|\||&&) ?\(? ?(['\"]?)([a-z0-9_]{1,20})\1 ?(?:=|<=>|like) ?(['\"]?)\2(?![a-z0-9_])"),
    ) + _any(
        # union select followed by something a query selects, not by prose
        _p(r"\bunion(?: all| distinct)? ?\(? ?select ?(?:\d|null\b|@@|char\(|concat|0x|'|\"|\(|\*|[a-z_][a-z0-9_.]{0,30} ?(?:,|from\b))"),
        _p(r"['\"] ?(?:or|and) ?['\"]?\d{1,10}['\"]? ?[<>]=? ?['\"]?\d"),
        _p(r"['\"] ?(?:or|and) ?(?:true|false)\b"),
        # time based
        _p(r"\b(?:sleep|pg_sleep) ?\( ?\d"),
        _p(r"\bbenchmark ?\( ?\d"),
        _p(r"\bwaitfor delay ?'"),
        _p(r"\bdbms_pipe\.receive_message"),
        # schema and system tables
        _p(r"\binformation_schema\b"),
        _p(r"\b(?:sqlite_master|pg_catalog|mysql\.user|sys\.(?:tables|objects|databases))\b"),
        # stacked queries
        _p(r"; ?(?:drop (?:table|database)|delete from|insert into|update [a-z_][a-z0-9_]{0,30} set|truncate table"
           r"|exec(?:ute)? (?:xp_|sp_|master\.)|declare @|shutdown\b|create (?:table|user|function))"),
        # error based and file access
        _p(r"\b(?:extractvalue|updatexml|load_file) ?\("),
        _p(r"\binto (?:out|dump)file\b"),
        _p(r"\bconvert ?\( ?int ?,"),
    )
    # The comment itself is the evidence: admin'-- and 1'#
    _ON_DECODED = _any(
        _p(r"['\"] ?\)? ?(?:--|#|/\*)"),
        _p(r"\b(?:or|and) \d{1,10}=\d{1,10} ?(?:--|#|/\*)"),
    )

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        return self.first(self._ON_TEXT, request.text) or self.first(self._ON_DECODED, request.decoded)


class XssRule(AttackRule):
    rule_id = "LS102"
    category = AttackCategory.XSS
    severity = Severity.MEDIUM

    _EVENTS = (
        r"on(?:error|load|mouseover|mouseenter|mouseout|focus|blur|click|dblclick|change|submit|input"
        r"|keydown|keyup|keypress|toggle|begin|end|animationstart|transitionend|pointerover|wheel)"
    )
    _PATTERNS = _any(
        _p(r"< ?/? ?script\b"),
        _p(r"<[a-z][a-z0-9]{0,15}\b[^>]{0,200}?\b" + _EVENTS + r" ?="),
        _p(r"['\"] ?/?\b" + _EVENTS + r" ?="),
        _p(r"< ?(?:svg|iframe|object|embed|math|details|marquee|isindex|base)\b"),
        _p(r"\b(?:javascript|vbscript|livescript) ?:[^ ]{0,60}[(`\[]"),
        _p(r"\bdata ?: ?text/html"),
        _p(r"\bdocument ?\. ?(?:cookie|domain|write)\b"),
        _p(r"(?<![a-z])(?:alert|prompt|confirm)(?:\(|`) ?['\"\d`]"),
        _p(r"\bstring\.fromcharcode ?\("),
        _p(r"<[a-z][a-z0-9]{0,15}\b[^>]{0,200}?\b(?:src|href|action|formaction) ?= ?['\"]? ?(?:javascript|data):"),
    )

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        return self.first(self._PATTERNS, request.decoded)


class PathTraversalRule(AttackRule):
    rule_id = "LS103"
    category = AttackCategory.PATH_TRAVERSAL
    severity = Severity.HIGH

    _PATTERNS = _any(
        _p(r"(?:\.\.;?[/\\]){2,}"),
        _p(r"/web-inf/(?:web|struts|applicationcontext)\.xml\b"),
        _p(r"(?:^|[=/\\])\.\.[/\\][^ ]{0,80}?(?:etc|windows|winnt|boot|proc|inetpub)\b"),
        _p(r"/etc/(?:passwd|shadow|group|hosts|issue|motd)\b"),
        _p(r"\b(?:boot|win|system)\.ini\b"),
        _p(r"(?:c:)?[/\\]windows[/\\]system32\b"),
        _p(r"/proc/self/(?:environ|cmdline|fd|maps|status)\b"),
        _p(r"\b(?:php|zip|phar|expect|glob|compress\.zlib) ?:// ?\w"),
        _p(r"\bfile ?: ?//"),
    )

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        evidence = self.first(self._PATTERNS, request.decoded)
        if not evidence and request.had_null_byte and "." in request.decoded:
            evidence = "%00"          # cuts off an appended extension
        return evidence


class RemoteFileInclusionRule(AttackRule):
    rule_id = "LS104"
    category = AttackCategory.REMOTE_FILE_INCLUSION
    severity = Severity.HIGH

    _INCLUDE_PARAMS = frozenset({
        "include", "inc", "page", "file", "path", "template", "tpl", "module", "mod", "require",
        "load", "doc", "document", "folder", "dir", "style", "pg", "cat", "show", "nav", "lang",
        "language", "conf", "config", "view", "content", "layout", "root", "pdf", "src_file",
    })
    _REMOTE = re.compile(r"^ ?(?:https?|ftps?|smb|data) ?:")
    _SCRIPT_URL = re.compile(
        r"^ ?(?:https?|ftps?)://[^ ]{1,200}?(?:\.(?:sh|pl|py|cgi|exe|bin)\??$|\?$)"
    )
    _UNC = re.compile(r"^ ?\\\\[a-z0-9.-]{1,100}\\")

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        for key, value in request.params:
            name = key.strip().strip("[]")
            if self._SCRIPT_URL.search(value) or self._UNC.search(value):
                return f"{name}={value}"[:120]
            if name in self._INCLUDE_PARAMS and self._REMOTE.search(value):
                return f"{name}={value}"[:120]
        return ""


class CommandInjectionRule(AttackRule):
    rule_id = "LS105"
    category = AttackCategory.COMMAND_INJECTION
    severity = Severity.HIGH

    _COMMANDS = (
        r"(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|netcat|bash|sh|zsh|python[23]?|perl|ruby|php"
        r"|ping|echo|nslookup|ifconfig|ipconfig|netstat|chmod|chown|rm|powershell|cmd|cmd\.exe|sleep"
        r"|busybox|tftp|telnet|base64|xterm|ps|kill|pwd|hostname|dir|type|net|certutil|bitsadmin)"
    )
    # The command must be followed by an argument, a separator or the end; ";id=2" stays quiet.
    _AFTER = r"(?= ?[-/.a-z0-9$'\"|;&`)]| ?$)"
    _ON_VALUES = _any(
        _p(r"(?:;|\|\|?|&&|\n) ?" + _COMMANDS + _AFTER),
        _p(r"`[^`]{0,40}?\b" + _COMMANDS + r"\b[^`]{0,80}`"),
        _p(r"\$\( ?" + _COMMANDS + r"\b"),
        _p(r"\$\{ifs\}"),
        _p(r"(?:^|[;|&]) ?(?:/bin/|/usr/bin/)(?:sh|bash|nc|cat|id|wget|curl)\b"),
    )

    # Shellshock (CVE-2014-6271): a bash function definition in a header that a
    # CGI script turns into an environment variable, followed by a command.
    _SHELLSHOCK = re.compile(r"\( ?\) ?\{[^}]{0,60}\} ?[;>]")

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        evidence = self.first(self._ON_VALUES, *request.values, request.path)
        if evidence:
            return evidence
        return self.first((self._SHELLSHOCK,), request.user_agent, entry.referer.casefold(), request.decoded)


class SsrfProbeRule(AttackRule):
    rule_id = "LS106"
    category = AttackCategory.SSRF
    severity = Severity.MEDIUM

    _PATTERNS = _any(
        _p(r"\b169\.254\.169\.254\b"),
        _p(r"\bmetadata\.google\.internal\b"),
        _p(r"\b100\.100\.100\.200\b"),
        _p(r"\bfd00:ec2::254\b"),
        _p(r"\b(?:gopher|dict|ldap|tftp|jar) ?://"),
    )
    _LOCAL = re.compile(
        r"^ ?(?:https?|ftp|file)?:?//(?:[^/@ ]{0,60}@)?(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|127\.1"
        r"|0\.0\.0\.0|0|\[::1?\]|\[0:0:0:0:0:0:0:1\]|2130706433|0x7f[0-9a-f]{0,6}|017700000001)(?=[:/? ]|$)"
    )

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        evidence = self.first(self._PATTERNS, request.query)
        if evidence:
            return evidence
        for key, value in request.params:
            if self._LOCAL.search(value):
                return f"{key}={value}"[:120]
        return ""


class TemplateInjectionRule(AttackRule):
    rule_id = "LS107"
    category = AttackCategory.TEMPLATE_INJECTION
    severity = Severity.MEDIUM

    _PATTERNS = _any(
        _p(r"\{\{ ?\d{1,6} ?[*+/-] ?['\"]?\d{1,6}['\"]? ?\}\}"),
        _p(r"\{\{[^}]{0,80}?(?:config|self|request|lipsum|cycler|joiner|namespace|__class__|__globals__"
           r"|__import__|__builtins__|_self\.env|getruntime)[^}]{0,120}\}\}"),
        _p(r"\$\{ ?\d{1,6} ?[*+/-] ?\d{1,6} ?\}"),
        _p(r"#\{ ?\d{1,6} ?\* ?\d{1,6} ?\}"),
        _p(r"<%= ?\d{1,6} ?\* ?\d{1,6} ?%>"),
        _p(r"\{% ?(?:import|include|set|for|if|debug)\b[^%]{0,120}%\}"),
        _p(r"__(?:class|mro|subclasses|globals|builtins)__"),
        _p(r"\$\{ ?(?:t\(|@java\.lang|new java\.|\"freemarker)"),
        # Struts / OGNL: ${#...}, %{...}, and its well-known context objects
        _p(r"[$%]\{ ?\(? ?#"),
        _p(r"%\{[^{}]{1,300}\}"),
        _p(r"#_memberaccess|@ognl\.ognlcontext|#context ?\[ ?'xwork\."),
    )

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        return self.first(self._PATTERNS, request.decoded)


class Log4ShellRule(AttackRule):
    rule_id = "LS108"
    category = AttackCategory.LOG4J
    severity = Severity.HIGH
    # The lookup works out of band (the server calls the attacker); a 200 says nothing.
    raise_on_success = False

    # ${lower:j}, ${upper:J}, ${::-j} and ${env:X:-j} all become j
    _LOOKUP = re.compile(r"\$\{(?:lower:|upper:|::-|(?:env|sys|date|main):[^:{}$]{0,20}:-)([^${}]{0,10})\}")
    _JNDI = re.compile(r"\$\{ ?jndi ?: ?(?:ldaps?|rmi|dns|iiop|corba|nis|nds|https?)?")

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        for text in (request.decoded, request.user_agent, entry.referer.casefold()):
            if "${" not in text:
                continue
            plain = text
            for _ in range(6):
                simpler = self._LOOKUP.sub(lambda m: m.group(1), plain)
                if simpler == plain:
                    break
                plain = simpler
            match = self._JNDI.search(plain)
            if match:
                return match.group(0)[:120]
        return ""


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

class SensitiveFileProbeRule(AttackRule):
    rule_id = "LS109"
    category = AttackCategory.SENSITIVE_FILE
    severity = Severity.MEDIUM

    _PATTERNS = _any(
        _p(r"/\.env(?:\.[a-z0-9_]{1,20})?(?:$|/|~)"),
        _p(r"/\.git/(?:config|head|index|logs|refs|objects)\b"),
        _p(r"/\.(?:svn|hg|bzr)/"),
        _p(r"/wp-config\.php(?:\.bak|\.old|\.save|\.orig|\.txt|~|\.swp)?$"),
        _p(r"/(?:\.ssh/)?id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$"),
        _p(r"/[a-z0-9_.-]{0,40}\.(?:sql|sql\.gz|sql\.zip|bak|old|swp|dump)$"),
        _p(r"/(?:backup|backups|dump|database|db)\.(?:zip|tar|tar\.gz|tgz|rar|7z)$"),
        _p(r"/phpinfo\.php$|/info\.php$"),
        _p(r"/server-(?:status|info)\b"),
        _p(r"/\.(?:htpasswd|htaccess|ds_store|npmrc|pypirc|netrc|bash_history|docker/config\.json)$"),
        _p(r"/\.aws/credentials$"),
        _p(r"/web\.config$"),
        _p(r"/actuator/(?:env|heapdump|configprops|mappings)\b"),
        _p(r"/(?:config|configuration|settings|local_settings)\.(?:php|py|ini|yml|yaml|json)\.(?:bak|old|save|orig|txt)$"),
    )

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        return self.first(self._PATTERNS, request.path)


class ForeignAdminPanelRule(AttackRule):
    """Probes for admin panels of software the site does not run.

    Only answers that say "not here" count (404, 403, 410, 444). A panel
    that answers 2xx or 3xx is the site's own and is not judged, and
    neither is a plain ``/admin``.
    """

    rule_id = "LS110"
    category = AttackCategory.ADMIN_PROBE
    severity = Severity.LOW
    raise_on_success = False

    NOT_HERE = frozenset({403, 404, 410, 444})
    _PATTERNS = _any(
        _p(r"^/wp-(?:login\.php|admin(?:/|$))"),
        _p(r"^/xmlrpc\.php$"),
        _p(r"^/(?:phpmyadmin|phpmyadmin\d?|pma|myadmin|mysqladmin|dbadmin|sqladmin)(?:/|$)"),
        _p(r"^/adminer(?:-[\d.]{1,10})?\.php$"),
        _p(r"^/administrator/(?:index\.php)?$"),
        _p(r"^/manager/html\b"),
        _p(r"^/(?:jenkins|hudson)/(?:login|script)\b"),
        _p(r"^/(?:vendor/phpunit/|boaform/|hnap1\b|cgi-bin/(?:luci|webproc))"),
        _p(r"^/solr/admin\b"),
        _p(r"^/(?:typo3|bitrix/admin|user/login\.php)\b"),
    )

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        if entry.status not in self.NOT_HERE:
            return ""
        return self.first(self._PATTERNS, request.path)


class ScannerUserAgentRule(AttackRule):
    rule_id = "LS111"
    category = AttackCategory.SCANNER
    severity = Severity.MEDIUM
    raise_on_success = False

    _PATTERN = re.compile(
        r"\b(?:sqlmap|nikto|nmap|masscan|zgrab|wpscan|acunetix|nuclei|dirbuster|gobuster|feroxbuster"
        r"|ffuf|wfuzz|openvas|nessus|w3af|arachni|netsparker|havij|zmeu|jorgee|whatweb|joomscan|commix"
        r"|xsstrike|dirsearch|skipfish|burpcollaborator|interactsh)\b"
    )

    def find(self, request: NormalizedRequest, entry: AccessLogEntry) -> str:
        match = self._PATTERN.search(request.user_agent)
        return match.group(0) if match else ""


REQUEST_RULES: Tuple[AttackRule, ...] = (
    SqlInjectionRule(), XssRule(), PathTraversalRule(), RemoteFileInclusionRule(),
    CommandInjectionRule(), SsrfProbeRule(), TemplateInjectionRule(), Log4ShellRule(),
    SensitiveFileProbeRule(), ForeignAdminPanelRule(), ScannerUserAgentRule(),
)


# ---------------------------------------------------------------------------
# Did the server answer the attack?
# ---------------------------------------------------------------------------

@dataclass
class ResponseJudge:
    """Learns what the site's error pages look like.

    An attack answered with 2xx and a body that is not the usual error
    page may have worked. Many sites answer every unknown path with the
    same 200 page; a size that comes back for many attacks is that page.
    """

    KEEP = frozenset({400, 403, 404, 405, 444})
    ERROR_STATUSES = frozenset({400, 403, 404, 405, 410, 444})
    MAX_SIZES = 200
    CATCH_ALL_AFTER = 5

    error_sizes: Counter = field(default_factory=Counter)
    attack_ok_sizes: Counter = field(default_factory=Counter)

    def observe(self, entry: AccessLogEntry) -> None:
        if entry.status in self.ERROR_STATUSES and entry.size:
            self._count(self.error_sizes, entry.size)

    def answered(self, entry: AccessLogEntry) -> bool:
        """True when the attack got a 2xx body that is not a known error page."""
        if not 200 <= entry.status < 300:
            return False
        self._count(self.attack_ok_sizes, entry.size)
        if entry.size == 0 or entry.size in self.usual_error_sizes():
            return False
        return self.attack_ok_sizes[entry.size] < self.CATCH_ALL_AFTER

    def usual_error_sizes(self) -> Tuple[int, ...]:
        return tuple(size for size, count in self.error_sizes.most_common(3) if count >= 2)

    def _count(self, counter: Counter, size: int) -> None:
        if size not in counter and len(counter) >= self.MAX_SIZES:
            for stale, _ in counter.most_common()[-self.MAX_SIZES // 2:]:
                del counter[stale]
        counter[size] += 1


class RequestAnalyzer:
    """Runs every request rule on an entry."""

    def __init__(
        self,
        rules: Sequence[AttackRule] = REQUEST_RULES,
        normalizer: Optional[RequestNormalizer] = None,
        judge: Optional[ResponseJudge] = None,
    ) -> None:
        self._rules = tuple(rules)
        self._normalizer = normalizer or RequestNormalizer()
        self._judge = judge or ResponseJudge()

    @property
    def rules(self) -> Tuple[AttackRule, ...]:
        return self._rules

    def normalize(self, entry: AccessLogEntry) -> NormalizedRequest:
        return self._normalizer.normalize(entry.path, entry.query, entry.user_agent)

    def analyze(self, entry: AccessLogEntry, request: Optional[NormalizedRequest] = None) -> List[Detection]:
        request = request or self.normalize(entry)
        self._judge.observe(entry)
        found: List[Detection] = []
        answered: Optional[bool] = None
        for rule in self._rules:
            evidence = rule.find(request, entry)
            if not evidence:
                continue
            severity = rule.severity
            reasons = [Reason.of("ls_reason_pattern", evidence=evidence)]
            if rule.raise_on_success:
                if answered is None:
                    answered = self._judge.answered(entry)
                if answered:
                    severity = raise_severity(severity)
                    reasons.append(Reason.of("ls_reason_answered", status=entry.status))
            found.append(Detection(
                rule_id=rule.rule_id, category=rule.category, severity=severity, entry=entry,
                evidence=evidence, reasons=tuple(reasons), normalized=request.text,
            ))
        return found
