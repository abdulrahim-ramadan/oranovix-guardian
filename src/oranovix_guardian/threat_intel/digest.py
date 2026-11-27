"""
Digest of what is new in the feed, as plain text and as simple HTML.

``DigestBuilder.build`` is a pure function: the same items, projects and
"since" always give the same digest, and nothing is read or sent. The
GUI shows its headline today; a mail or a chat message can carry the
same text later.
"""
from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional, Sequence

from .exposure import ExposureReport
from .models import ProjectMatch, Relevance, StoredItem
from .projects import Project
from .sanitize import SafeUrl


@dataclass(frozen=True)
class DigestTexts:
    """The wording of a digest. English by default; the GUI passes translations."""

    headline: str = "Since your last visit: {new} new"
    exposed: str = "{count} of your projects are exposed"
    exposed_one: str = "1 of your projects is exposed"
    exposed_none: str = "none of your projects is exposed"
    accepted: str = "{count} accepted"
    nothing_new: str = "Nothing new since your last visit."
    affecting: str = "Affects your projects"
    possible: str = "Possible matches, verify"
    other: str = "Other news"
    more: str = "and {count} more"
    exploited: str = "exploited in the wild"
    fix: str = "fixed in {version}"
    no_fix: str = "no fixed version known"
    projects: str = "Your projects"
    project_line: str = "{name}: {count} item(s) affect it"
    project_clear: str = "{name}: nothing affects it"

    KEYS = (
        "headline", "exposed", "exposed_one", "exposed_none", "accepted", "nothing_new", "affecting", "possible", "other", "more",
        "exploited", "fix", "no_fix", "projects", "project_line", "project_clear",
    )

    @classmethod
    def translated(cls, translate: Callable[[str], str]) -> "DigestTexts":
        """Texts from translation keys ``digest_<name>``; missing keys stay English."""
        values: Dict[str, str] = {}
        for name in cls.KEYS:
            key = f"digest_{name}"
            text = translate(key)
            if text and text != key:
                values[name] = text
        return cls(**values)


@dataclass(frozen=True)
class Digest:
    new_count: int
    affecting_count: int
    possible_count: int
    headline: str
    text: str
    html: str
    checked: bool = True        # False: the headline says why nothing was checked
    exposed_count: int = 0      # projects with an open confirmed item, read or not


class DigestBuilder:
    """Builds the digest. No state, no I/O."""

    MAX_OTHER = 10
    SEPARATOR = "  \u00b7  "

    @classmethod
    def build(
        cls,
        items: Sequence[StoredItem],
        projects: Sequence[Project],
        since: Optional[datetime],
        texts: DigestTexts = DigestTexts(),
        not_checked: str = "",
        exposure: Optional[ExposureReport] = None,
    ) -> Digest:
        """Digest of the items first seen after *since* (all of them when ``None``).

        Background items are not news, unless they affect a project.
        *not_checked* is the reason why the projects could not be checked
        (feed off, no database, ...). It replaces the "new" part, and no
        project is then called clear.

        The headline has two parts that do not depend on each other: what
        is new since the visit, and how many projects are exposed. The
        second one counts every open item, read or not. *exposure* carries
        the accepted risks; without it, it is built from the items.
        """
        new = [
            item for item in items
            if item.counts_as_new and (since is None or item.first_seen > since)
        ]
        new.sort(key=cls._order)
        affecting = [item for item in new if item.relevance is Relevance.AFFECTS_YOU]
        possible = [item for item in new if item.relevance is Relevance.POSSIBLE]
        other = [item for item in new if item.relevance is Relevance.GENERAL]

        if exposure is None:
            exposure = ExposureReport.build(items, projects)
        checked = not not_checked
        exposed = len(exposure.exposed)
        if not_checked:
            headline = not_checked
        elif new:
            # "affecting" is still passed for wordings written for the old headline.
            headline = texts.headline.format(new=len(new), affecting=len(affecting))
        else:
            headline = texts.nothing_new
        if exposed == 1:
            headline += cls.SEPARATOR + texts.exposed_one
        elif exposed:
            headline += cls.SEPARATOR + texts.exposed.format(count=exposed)
        elif checked and projects:
            headline += cls.SEPARATOR + texts.exposed_none
        return Digest(
            new_count=len(new),
            affecting_count=len(affecting),
            possible_count=len(possible),
            headline=headline,
            text=cls._text(headline, affecting, possible, other, exposure, texts, checked),
            html=cls._html(headline, affecting, possible, other, exposure, texts, checked),
            checked=checked,
            exposed_count=exposed,
        )

    @staticmethod
    def _order(item: StoredItem) -> tuple:
        moment = item.item.published or item.first_seen
        return (item.relevance.rank, -moment.timestamp(), item.id)

    # ------------------------------------------------------------------
    # Plain text
    # ------------------------------------------------------------------

    @classmethod
    def _text(
        cls, headline: str, affecting: Sequence[StoredItem], possible: Sequence[StoredItem],
        other: Sequence[StoredItem], exposure: ExposureReport, texts: DigestTexts,
        checked: bool = True,
    ) -> str:
        lines: List[str] = [headline]
        for title, group in ((texts.affecting, affecting), (texts.possible, possible)):
            if not group:
                continue
            lines += ["", f"{title} ({len(group)})"]
            for item in group:
                lines.append(f"- {cls._line(item, texts)}")
                lines.append(f"  {item.item.url}")
                lines += [f"  {cls._match_line(match, texts)}" for match in item.matches]
        if other:
            lines += ["", f"{texts.other} ({len(other)})"]
            lines += [f"- {cls._line(item, texts)}" for item in other[: cls.MAX_OTHER]]
            if len(other) > cls.MAX_OTHER:
                lines.append(f"  {texts.more.format(count=len(other) - cls.MAX_OTHER)}")
        project_lines = cls._project_lines(exposure, texts, checked)
        if project_lines:
            lines += ["", texts.projects] + [f"- {line}" for line in project_lines]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _line(item: StoredItem, texts: DigestTexts) -> str:
        date = item.item.published.strftime("%Y-%m-%d") if item.item.published else ""
        parts = [item.item.title, f"[{item.item.source}{', ' + date if date else ''}]"]
        if item.item.is_known_exploited:
            parts.append(f"({texts.exploited})")
        return " ".join(parts)

    @staticmethod
    def _match_line(match: ProjectMatch, texts: DigestTexts) -> str:
        line = f"{match.project}: {match.package} {match.version}".rstrip()
        if match.advisory_id:
            line += f" ({match.advisory_id})"
        if match.fixed_version:
            line += f", {texts.fix.format(version=match.fixed_version)}"
        elif match.confirmed:
            line += f", {texts.no_fix}"
        return line

    @staticmethod
    def _project_lines(exposure: ExposureReport, texts: DigestTexts, checked: bool = True) -> List[str]:
        """One line per project: what it is exposed to, whatever was read."""
        lines = []
        for entry in exposure.projects:
            count, accepted = len(entry.open), len(entry.accepted)
            if not count and not accepted and not checked:
                continue        # not checked is not the same as clear
            if accepted and not count:
                lines.append(f"{entry.project.name}: {texts.accepted.format(count=accepted)}")
                continue
            template = texts.project_line if count else texts.project_clear
            line = template.format(name=entry.project.name, count=count)
            if accepted:
                line += f", {texts.accepted.format(count=accepted)}"
            lines.append(line)
        return lines

    # ------------------------------------------------------------------
    # HTML (every value is escaped; links only when they are web links)
    # ------------------------------------------------------------------

    @classmethod
    def _html(
        cls, headline: str, affecting: Sequence[StoredItem], possible: Sequence[StoredItem],
        other: Sequence[StoredItem], exposure: ExposureReport, texts: DigestTexts,
        checked: bool = True,
    ) -> str:
        esc = html.escape
        parts: List[str] = [f"<h2>{esc(headline)}</h2>"]
        for title, group in ((texts.affecting, affecting), (texts.possible, possible)):
            if not group:
                continue
            parts.append(f"<h3>{esc(title)} ({len(group)})</h3>")
            parts.append("<ul>")
            for item in group:
                matches = "".join(
                    f"<br><small>{esc(cls._match_line(match, texts))}</small>"
                    for match in item.matches
                )
                parts.append(f"<li>{cls._link(item, texts)}{matches}</li>")
            parts.append("</ul>")
        if other:
            parts.append(f"<h3>{esc(texts.other)} ({len(other)})</h3>")
            parts.append("<ul>")
            parts += [f"<li>{cls._link(item, texts)}</li>" for item in other[: cls.MAX_OTHER]]
            parts.append("</ul>")
            if len(other) > cls.MAX_OTHER:
                parts.append(f"<p>{esc(texts.more.format(count=len(other) - cls.MAX_OTHER))}</p>")
        project_lines = cls._project_lines(exposure, texts, checked)
        if project_lines:
            parts.append(f"<h3>{esc(texts.projects)}</h3>")
            parts.append("<ul>" + "".join(f"<li>{esc(line)}</li>" for line in project_lines) + "</ul>")
        return "\n".join(parts) + "\n"

    @classmethod
    def _link(cls, item: StoredItem, texts: DigestTexts) -> str:
        label = html.escape(cls._line(item, texts))
        url = SafeUrl.clean(item.item.url)
        if not url:
            return label
        return f'<a href="{html.escape(url, quote=True)}">{label}</a>'
