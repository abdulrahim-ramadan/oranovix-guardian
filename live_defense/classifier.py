"""
Change classifier: severity and reasons of one file change.

Kept apart from the monitor so the baseline can use the same rules to
refuse files that already look planted when it is created.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import ClassVar, FrozenSet, List, Optional, Sequence, Tuple

from scanner_engine.base import Issue, Severity

from .base import ChangeType
from .paths import PUBLIC_DIRS, LinkInfo, public_part, upload_part
from .webshell import SignatureHit


class ChangeClassifier:
    """Severity and reasons of one change."""

    EXECUTABLE: ClassVar[FrozenSet[str]] = frozenset({
        ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht", ".phps", ".phar",
        ".inc", ".asp", ".aspx", ".ashx", ".asmx", ".cshtml", ".jsp", ".jspx", ".jspf", ".cfm",
        ".cgi", ".pl", ".py", ".js", ".sh", ".bat", ".ps1", ".exe", ".dll",
    })
    CODE: ClassVar[FrozenSet[str]] = EXECUTABLE | frozenset({
        ".ts", ".tsx", ".jsx", ".mjs", ".java", ".cs", ".html", ".htm", ".rb", ".go",
        ".pl", ".cgi", ".asp", ".jspx", ".ps1", ".bat", ".cmd", ".vbs",
    })
    PUBLIC_DIRS: ClassVar[FrozenSet[str]] = PUBLIC_DIRS
    # Change how the server treats the folder (e.g. run .jpg as PHP).
    SERVER_CONTROL: ClassVar[FrozenSet[str]] = frozenset({".htaccess", ".user.ini", "web.config"})
    # Extensions an upload filter usually lets through.
    HARMLESS_LOOKING: ClassVar[FrozenSet[str]] = frozenset({
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg", ".tif", ".tiff",
        ".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".zip", ".mp3", ".mp4",
    })
    SENSITIVE_NAMES: ClassVar[FrozenSet[str]] = frozenset({
        "settings.py", "wsgi.py", "asgi.py", "urls.py", ".htaccess", ".user.ini", "web.config",
        "nginx.conf", "httpd.conf", "apache2.conf",
    })
    SERIOUS: ClassVar[FrozenSet[Severity]] = frozenset({Severity.HIGH, Severity.CRITICAL})
    LISTED_FINDINGS: ClassVar[int] = 3
    SERVER_CONF_DIRS: ClassVar[FrozenSet[str]] = frozenset({
        "nginx", "apache", "apache2", "httpd", "conf.d", "sites-available", "sites-enabled",
    })

    def classify(
        self,
        change: ChangeType,
        relative: str,
        hits: Sequence[SignatureHit] = (),
        findings: Sequence[Issue] = (),
        root_name: str = "",
        link: Optional[LinkInfo] = None,
        too_large: bool = False,
    ) -> Tuple[Severity, Tuple[str, ...]]:
        """*root_name* is the monitored folder's own name: monitoring ``uploads`` directly is still public."""
        path = self.normalized(relative)
        suffix = path.suffix.lower()
        rated: List[Tuple[Severity, str]] = []
        if path.name != PurePosixPath(relative).name:
            rated.append((Severity.LOW, f"Name ends with a dot or space; Windows serves it as {path.name}"))

        if change in (ChangeType.NEW, ChangeType.MODIFIED):
            for hit in hits:
                rated.append((Severity.CRITICAL, f"Web shell signature: {hit.description} (line {hit.line})"))
            hidden = self._hidden_extension(path)
            if hidden:
                rated.append((Severity.CRITICAL, f"Executable extension {hidden} hidden behind {suffix}"))

        public = public_part((root_name, *path.parts[:-1]))
        sensitive = self._is_sensitive(path)
        if public and path.name.lower() in self.SERVER_CONTROL:
            verb = {ChangeType.NEW: "New", ChangeType.MODIFIED: "Changed", ChangeType.DELETED: "Deleted"}
            rated.append((
                Severity.CRITICAL,
                f"{verb.get(change, 'Changed')} server configuration file {path.name} in the {public}/ folder",
            ))
        if link is not None and change in (ChangeType.NEW, ChangeType.MODIFIED):
            rated.append(self._link_risk("New link" if change is ChangeType.NEW else "Changed link", link, public))
        if too_large and change in (ChangeType.NEW, ChangeType.MODIFIED):
            rated.append((Severity.MEDIUM, "File too large to scan fully"))
        if change is ChangeType.NEW:
            if suffix in self.EXECUTABLE and public:
                rated.append((Severity.CRITICAL, f"New executable file in the {public}/ folder"))
            elif sensitive:
                rated.append((Severity.HIGH, "New sensitive configuration file"))
            elif suffix in self.CODE:
                rated.append((Severity.MEDIUM, "New code file"))
            else:
                rated.append((Severity.LOW, "New file"))
        elif change is ChangeType.MODIFIED:
            if sensitive:
                rated.append((Severity.HIGH, "Sensitive configuration file changed"))
            elif suffix in self.CODE:
                rated.append((Severity.MEDIUM, "Source file changed"))
            else:
                rated.append((Severity.LOW, "File changed"))
        elif change is ChangeType.DELETED:
            if sensitive:
                rated.append((Severity.HIGH, "Sensitive configuration file deleted"))
            else:
                rated.append((Severity.MEDIUM, "File deleted"))

        # Serious findings set the event severity, so the list matches the alarm.
        serious = sorted(
            (f for f in findings if f.severity in self.SERIOUS and str(f.confidence).upper() != "LOW"),
            key=lambda issue: (-issue.severity.weight, issue.line_number),
        )
        for issue in serious[: self.LISTED_FINDINGS]:
            rated.append((issue.severity, f"Code scan: {issue.title} (line {issue.line_number})"))
        if len(findings) > len(serious[: self.LISTED_FINDINGS]):
            worst = max(findings, key=lambda issue: issue.severity.weight).severity
            rated.append((Severity.LOW, f"Code scan: {len(findings)} finding(s), worst {worst.value}"))

        rated.sort(key=lambda item: -item[0].weight)
        return rated[0][0], tuple(reason for _, reason in rated)

    def present_risks(
        self,
        relative: str,
        hits: Sequence[SignatureHit] = (),
        root_name: str = "",
        link: Optional[LinkInfo] = None,
    ) -> Tuple[str, ...]:
        """Why a file that merely exists already looks planted; empty when it does not.

        Used when a baseline is created, so a compromised folder is not
        recorded as good. Code in web roots (static/, public_html/...) is
        normal there, so "executable in a public folder" only counts in
        upload-type folders.
        """
        path = self.normalized(relative)
        parents = (root_name, *path.parts[:-1])
        reasons = [f"Web shell signature: {hit.description} (line {hit.line})" for hit in hits]
        hidden = self._hidden_extension(path)
        if hidden:
            reasons.append(f"Executable extension {hidden} hidden behind {path.suffix.lower()}")
        upload = upload_part(parents)
        if upload and path.suffix.lower() in self.EXECUTABLE:
            reasons.append(f"Executable file in the {upload}/ folder")
        public = public_part(parents)
        if link is not None and public:
            reasons.append(self._link_risk("Link", link, public)[1])
        return tuple(reasons)

    @staticmethod
    def _link_risk(what: str, link: LinkInfo, public: str) -> Tuple[Severity, str]:
        if public and link.outside_root:
            return Severity.CRITICAL, (
                f"{what} in the {public}/ folder points outside the monitored folder: {link.target}"
            )
        if public:
            return Severity.HIGH, f"{what} in the {public}/ folder points to {link.target}"
        return Severity.MEDIUM, f"{what} points to {link.target}"

    def is_code(self, relative: str) -> bool:
        return self.normalized(relative).suffix.lower() in self.CODE

    @staticmethod
    def normalized(relative: str) -> PurePosixPath:
        """Trailing dots and spaces dropped from every part: Windows ignores them."""
        parts = [part.rstrip(". ") or part for part in PurePosixPath(relative).parts]
        return PurePosixPath(*parts) if parts else PurePosixPath(relative)

    def _hidden_extension(self, path: PurePosixPath) -> str:
        """``shell.php.jpg`` -> ``.php``: an executable extension before a harmless one."""
        suffixes = [s.lower() for s in path.suffixes]
        if len(suffixes) < 2 or suffixes[-1] not in self.HARMLESS_LOOKING:
            return ""
        return next((s for s in suffixes[:-1] if s in self.EXECUTABLE), "")

    def _is_sensitive(self, path: PurePosixPath) -> bool:
        name = path.name.lower()
        parents = {p.lower() for p in path.parts[:-1]}
        if name in self.SENSITIVE_NAMES:
            return True
        if name == ".env" or name.startswith(".env."):
            return True
        if name == "dockerfile" or name.startswith("dockerfile."):
            return True
        if name.endswith(".conf") and parents & self.SERVER_CONF_DIRS:
            return True
        if "sites-enabled" in parents or "sites-available" in parents:
            return True
        return "settings" in parents and name.endswith(".py")
