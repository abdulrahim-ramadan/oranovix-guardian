"""
Vulnerability categories shared by every engine.

Different engines report the same weakness under different rule IDs
(Bandit ``B105``, regex ``SEC001``, AST ``AST-SEC1``...).  A common
category lets ``IssueMerger`` recognise them as one finding.
"""
from __future__ import annotations

from enum import Enum


class IssueCategory(str, Enum):
    """What kind of weakness an issue describes."""

    SECRET = "secret"
    SQL_INJECTION = "sql_injection"
    CODE_EXEC = "code_exec"
    COMMAND_EXEC = "command_exec"
    WEAK_CRYPTO = "weak_crypto"
    WEAK_RANDOM = "weak_random"
    INSECURE_IMPORT = "insecure_import"
    DESERIALIZATION = "deserialization"
    TLS = "tls"
    XSS = "xss"
    FILE_INCLUSION = "file_inclusion"
    OPEN_REDIRECT = "open_redirect"
    INFO_LEAK = "info_leak"
    DEBUG = "debug"
    MISCONFIGURATION = "misconfiguration"
    NETWORK = "network"
    CSRF = "csrf"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    ACCESS_CONTROL = "access_control"
    TOKEN_VERIFICATION = "token_verification"
    DATA_EXPOSURE = "data_exposure"
    HOST_VALIDATION = "host_validation"
    COOKIE_SECURITY = "cookie_security"
    CORS = "cors"
    DEPENDENCY = "dependency"
    OTHER = "other"

    @classmethod
    def parse(cls, value: str) -> "IssueCategory":
        """Convert a JSON string to a category; unknown values become OTHER."""
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.OTHER


_C = IssueCategory

# Categories for rules whose engines identify them only by rule ID.
RULE_CATEGORIES: dict[str, IssueCategory] = {
    # Bandit
    "B105": _C.SECRET, "B106": _C.SECRET, "B107": _C.SECRET,
    "B608": _C.SQL_INJECTION, "B610": _C.SQL_INJECTION, "B611": _C.SQL_INJECTION,
    "B102": _C.CODE_EXEC, "B307": _C.CODE_EXEC,
    "B601": _C.COMMAND_EXEC, "B602": _C.COMMAND_EXEC, "B603": _C.COMMAND_EXEC,
    "B604": _C.COMMAND_EXEC, "B605": _C.COMMAND_EXEC, "B606": _C.COMMAND_EXEC,
    "B607": _C.COMMAND_EXEC, "B609": _C.COMMAND_EXEC,
    "B303": _C.WEAK_CRYPTO, "B304": _C.WEAK_CRYPTO, "B305": _C.WEAK_CRYPTO,
    "B324": _C.WEAK_CRYPTO, "B413": _C.WEAK_CRYPTO, "B505": _C.WEAK_CRYPTO,
    "B311": _C.WEAK_RANDOM,
    "B401": _C.INSECURE_IMPORT, "B402": _C.INSECURE_IMPORT, "B403": _C.INSECURE_IMPORT,
    "B404": _C.INSECURE_IMPORT,
    "B301": _C.DESERIALIZATION, "B302": _C.DESERIALIZATION, "B506": _C.DESERIALIZATION,
    "B323": _C.TLS, "B501": _C.TLS, "B502": _C.TLS, "B503": _C.TLS,
    "B504": _C.TLS, "B507": _C.TLS,
    "B308": _C.XSS, "B701": _C.XSS, "B702": _C.XSS, "B703": _C.XSS,
    "B201": _C.DEBUG, "B202": _C.DEBUG,
    "B104": _C.NETWORK,
    "B310": _C.SSRF,
    # Python regex checks
    "SEC001": _C.SECRET,
    # JavaScript / TypeScript
    "JS001": _C.CODE_EXEC, "JS002": _C.CODE_EXEC, "JS003": _C.CODE_EXEC,
    "JS004": _C.SECRET,
    "JS005": _C.XSS, "JS006": _C.XSS, "JS007": _C.XSS,
    "JS008": _C.SQL_INJECTION,
    "JS009": _C.COMMAND_EXEC,
    "JS010": _C.OPEN_REDIRECT,
    "JS011": _C.INFO_LEAK, "JS012": _C.INFO_LEAK,
    "JS013": _C.WEAK_RANDOM,
    "JS014": _C.DEBUG,
    # PHP
    "PHP001": _C.CODE_EXEC,
    "PHP002": _C.COMMAND_EXEC, "PHP010": _C.COMMAND_EXEC,
    "PHP003": _C.FILE_INCLUSION,
    "PHP004": _C.SQL_INJECTION, "PHP008": _C.SQL_INJECTION, "PHP009": _C.SQL_INJECTION,
    "PHP005": _C.XSS, "PHP006": _C.XSS,
    "PHP007": _C.WEAK_CRYPTO,
    "PHP011": _C.MISCONFIGURATION, "PHP012": _C.MISCONFIGURATION,
    # Java
    "JAVA001": _C.COMMAND_EXEC, "JAVA002": _C.COMMAND_EXEC,
    "JAVA003": _C.SECRET,
    "JAVA004": _C.SQL_INJECTION, "JAVA005": _C.SQL_INJECTION,
    "JAVA006": _C.DESERIALIZATION, "JAVA007": _C.DESERIALIZATION,
    "JAVA008": _C.WEAK_RANDOM, "JAVA009": _C.WEAK_RANDOM,
    "JAVA010": _C.CODE_EXEC,
    "JAVA011": _C.INFO_LEAK, "JAVA012": _C.INFO_LEAK,
    # C#
    "CS001": _C.COMMAND_EXEC,
    "CS002": _C.SECRET, "CS003": _C.SECRET,
    "CS004": _C.SQL_INJECTION, "CS005": _C.SQL_INJECTION,
    "CS006": _C.XSS,
    "CS007": _C.DESERIALIZATION, "CS008": _C.DESERIALIZATION,
    "CS009": _C.DESERIALIZATION, "CS010": _C.DESERIALIZATION,
    "CS011": _C.DEBUG,
    "CS012": _C.INFO_LEAK, "CS013": _C.INFO_LEAK,
    # Django / DRF views
    "DJ001": _C.CSRF,
    "DJ002": _C.SSRF,
    "DJ003": _C.OPEN_REDIRECT,
    "DJ004": _C.PATH_TRAVERSAL,
    "DJ005": _C.XSS,
    "DJ006": _C.SQL_INJECTION,
    "DJ007": _C.TOKEN_VERIFICATION,
    "DJ008": _C.ACCESS_CONTROL, "DJ010": _C.ACCESS_CONTROL,
    "DJ009": _C.DATA_EXPOSURE,
    # Django settings
    "DS001": _C.HOST_VALIDATION,
    "DS002": _C.COOKIE_SECURITY,
    "DS003": _C.CSRF,
    "DS004": _C.MISCONFIGURATION,
    "DS005": _C.CORS,
    "DS006": _C.TLS,
    # Django templates
    "DT001": _C.XSS, "DT002": _C.XSS,
    # Dependencies
    "DEP001": _C.DEPENDENCY, "DEP002": _C.DEPENDENCY,
}


def category_for_rule(rule_id: str) -> IssueCategory:
    """Return the category registered for *rule_id*, or OTHER."""
    return RULE_CATEGORIES.get(rule_id, IssueCategory.OTHER)
