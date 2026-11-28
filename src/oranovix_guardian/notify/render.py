"""
The report as plain text, Telegram HTML and an email HTML part.

All three come from one list of lines, so they always say the same.
Every dynamic value goes through ``html.escape`` in the HTML forms.
Telegram gets only ``<b>``, ``<i>``, ``<code>`` and ``<a>``, and no tag
spans two lines (the message may be split between lines). The email
part is right-to-left for Arabic. Texts follow the UI language.
"""
from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Mapping, Sequence, Tuple

from oranovix_guardian.core.language_manager import LanguageManager

from .models import OutboundMessage
from .report import SEVERITIES, DailyReport

Translate = Callable[..., str]


@dataclass(frozen=True)
class Seg:
    text: str
    style: str = ""         # "", "b", "i" or "code"
    href: str = ""          # only for web links (already cleaned)


@dataclass(frozen=True)
class Line:
    kind: str               # "title", "section", "item", "text" or "blank"
    segs: Tuple[Seg, ...] = ()

    @property
    def plain(self) -> str:
        return "".join(seg.text for seg in self.segs)


def local(moment: datetime) -> datetime:
    return moment.astimezone() if moment.tzinfo else moment


class Blocks:
    """Turns lines into the three outputs."""

    @staticmethod
    def text(lines: Sequence[Line]) -> str:
        out: List[str] = []
        for line in lines:
            if line.kind == "blank":
                out.append("")
            elif line.kind == "item":
                out.append("• " + line.plain)
            elif line.kind == "section":
                out.append(line.plain.upper() if line.plain.isascii() else line.plain)
            else:
                out.append(line.plain)
        return "\n".join(out).strip() + "\n"

    @staticmethod
    def _inline(segs: Sequence[Seg]) -> str:
        parts = []
        for seg in segs:
            text = html.escape(seg.text, quote=False)
            if seg.href:
                text = f'<a href="{html.escape(seg.href, quote=True)}">{text}</a>'
            if seg.style in ("b", "i", "code"):
                text = f"<{seg.style}>{text}</{seg.style}>"
            parts.append(text)
        return "".join(parts)

    @classmethod
    def telegram(cls, lines: Sequence[Line]) -> str:
        out: List[str] = []
        for line in lines:
            if line.kind == "blank":
                out.append("")
            elif line.kind in ("title", "section"):
                out.append(f"<b>{html.escape(line.plain, quote=False)}</b>")
            elif line.kind == "item":
                out.append("• " + cls._inline(line.segs))
            else:
                out.append(cls._inline(line.segs))
        return "\n".join(out).strip() + "\n"

    @classmethod
    def email(cls, lines: Sequence[Line], rtl: bool, lang: str) -> str:
        direction = ' dir="rtl"' if rtl else ""
        align = "right" if rtl else "left"
        out = [f'<!DOCTYPE html><html lang="{html.escape(lang)}"{direction}><head><meta charset="utf-8"></head>',
               f'<body{direction} style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222;'
               f'text-align:{align}">']
        in_list = False
        for line in lines:
            if line.kind == "item":
                if not in_list:
                    out.append("<ul>")
                    in_list = True
                out.append(f"<li>{cls._inline(line.segs)}</li>")
                continue
            if in_list:
                out.append("</ul>")
                in_list = False
            if line.kind == "title":
                out.append(f'<h2 style="color:#b00020">{html.escape(line.plain)}</h2>')
            elif line.kind == "section":
                out.append(f"<h3>{html.escape(line.plain)}</h3>")
            elif line.kind == "text":
                out.append(f"<p>{cls._inline(line.segs)}</p>")
        if in_list:
            out.append("</ul>")
        out.append("</body></html>")
        return "\n".join(out) + "\n"


class ReportRenderer:
    DATE = "%d.%m.%Y"
    TIME = "%d.%m.%Y %H:%M"

    def __init__(self, translate: Translate, rtl: bool = False, lang: str = "en") -> None:
        self._t = translate
        self._rtl = rtl
        self._lang = lang

    @classmethod
    def for_current_language(cls) -> "ReportRenderer":
        lm = LanguageManager()
        return cls(lm.t, rtl=lm.is_rtl, lang=lm.current_lang)

    # ------------------------------------------------------------------

    def subject(self, report: DailyReport) -> str:
        return self._t("nt_subject", date=local(report.now).strftime(self.DATE)).replace("\r", " ").replace("\n", " ")

    def text(self, report: DailyReport) -> str:
        return Blocks.text(self.lines(report))

    def telegram_html(self, report: DailyReport) -> str:
        return Blocks.telegram(self.lines(report))

    def email_html(self, report: DailyReport) -> str:
        return Blocks.email(self.lines(report), self._rtl, self._lang)

    def message(self, report: DailyReport, message_id: str = "", kind: str = "daily") -> OutboundMessage:
        lines = self.lines(report)
        return OutboundMessage(
            id=message_id, kind=kind, subject=self.subject(report), text=Blocks.text(lines),
            telegram_html=Blocks.telegram(lines), email_html=Blocks.email(lines, self._rtl, self._lang),
            created_at=report.now,
        )

    def simple(self, message_id: str, kind: str, subject: str, body: Sequence[str], now: datetime) -> OutboundMessage:
        """A short message (test, alarm, fold-up) in the same three forms."""
        lines = [Line("title", (Seg(subject),))] + [Line("text", (Seg(text),)) for text in body]
        return OutboundMessage(
            id=message_id, kind=kind, subject=subject.replace("\r", " ").replace("\n", " "),
            text=Blocks.text(lines), telegram_html=Blocks.telegram(lines),
            email_html=Blocks.email(lines, self._rtl, self._lang), created_at=now,
        )

    # ------------------------------------------------------------------

    def _severity(self, name: str) -> str:
        key = name.lower()
        text = self._t(key)
        return name if text == key else text

    def _counts(self, counts: Mapping[str, int]) -> str:
        return "  ·  ".join(f"{self._severity(s)} {counts[s]}" for s in SEVERITIES if counts.get(s))

    def _rule(self, rule_id: str) -> str:
        key = f"ls_rule_{rule_id.lower()}"
        text = self._t(key)
        return rule_id if text == key else text

    def lines(self, report: DailyReport) -> List[Line]:
        t = self._t
        lines: List[Line] = [
            Line("title", (Seg(t("nt_report_title", date=local(report.now).strftime(self.DATE))),)),
            Line("text", (Seg(t("nt_report_period", since=local(report.since).strftime(self.TIME)), "i"),)),
        ]

        def section(key: str) -> None:
            lines.append(Line("blank"))
            lines.append(Line("section", (Seg(t(key)),)))

        if report.quiet:
            lines.append(Line("blank"))
            lines.append(Line("text", (Seg(t("nt_report_quiet")),)))

        section("nt_sec_feed")
        if not report.feed_checked:
            lines.append(Line("text", (Seg(t("nt_feed_not_checked")),)))
        else:
            lines.append(Line("text", (Seg(t("nt_feed_counts", new=report.feed_new, exposed=report.feed_exposed)),)))
        for hit in report.feed_hits:
            segs = [Seg(hit.title, "b", hit.url)]
            if hit.cve_ids:
                segs.append(Seg(" "))
                segs.append(Seg(", ".join(hit.cve_ids), "code"))
            if hit.projects:
                segs.append(Seg(" " + t("nt_feed_affects", projects=", ".join(hit.projects))))
            if hit.exploited:
                segs.append(Seg(" " + t("nt_feed_exploited"), "i"))
            lines.append(Line("item", tuple(segs)))

        if report.sites:
            section("nt_sec_uptime")
            for site in report.sites:
                label = f"{site.project} ({site.host})" if site.host else site.project
                if site.down_since is not None and site.back_up_at is None:
                    text = t("nt_site_down", site=label, time=local(site.down_since).strftime(self.TIME))
                else:
                    moment = site.back_up_at or report.now
                    text = t("nt_site_up", site=label, time=local(moment).strftime(self.TIME))
                lines.append(Line("item", (Seg(text),)))

        section("nt_sec_sentinel")
        if report.sentinel_by_severity:
            lines.append(Line("text", (Seg(t("nt_sentinel_counts", counts=self._counts(report.sentinel_by_severity))),)))
            for rule_id, hits in report.sentinel_top_rules:
                lines.append(Line("item", (Seg(self._rule(rule_id), "b"), Seg(f": {hits}"))))
            if report.sentinel_networks:
                lines.append(Line("text", (Seg(t("nt_sentinel_networks")),)))
                for network, hits in report.sentinel_networks:
                    lines.append(Line("item", (Seg(network, "code"), Seg(f": {hits}"))))
        else:
            lines.append(Line("text", (Seg(t("nt_none")),)))

        section("nt_sec_live")
        if report.integrity_by_severity:
            lines.append(Line("text", (Seg(t("nt_live_counts", counts=self._counts(report.integrity_by_severity))),)))
            for severity, path in report.integrity_paths:
                lines.append(Line("item", (Seg(self._severity(severity) + " "), Seg(path, "code"))))
        else:
            lines.append(Line("text", (Seg(t("nt_none")),)))

        section("nt_sec_scan")
        scan = report.last_scan
        if scan is None:
            lines.append(Line("text", (Seg(t("nt_scan_none")),)))
        else:
            lines.append(Line("text", (Seg(t("nt_scan_line", date=local(scan.date).strftime(self.DATE),
                                              project=scan.project, counts=self._counts(scan.counts) or "0")),)))

        lines.append(Line("blank"))
        lines.append(Line("text", (Seg(t("nt_report_footer"), "i"),)))
        return lines
