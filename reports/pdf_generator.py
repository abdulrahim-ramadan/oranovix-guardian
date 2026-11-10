"""
Professional, multilingual PDF report generator for Oranovix Guardian scan results.

This module converts a ``ScanResult`` object into a fully formatted, multi-page
PDF document using the ReportLab Platypus layout engine.  It supports both
left-to-right (LTR) and right-to-left (RTL) languages; Arabic text is reshaped
and reordered at render time using the ``arabic-reshaper`` and
``python-bidi`` libraries when they are available.

Architecture:
  - ``_Palette``           — centralised brand-colour constants (red/black theme).
  - ``FontRegistry``       — singleton that discovers and registers a TTF font
                             capable of rendering Arabic glyphs with ReportLab.
  - ``StyleBuilder``       — builds a named dict of ``ParagraphStyle`` objects
                             adapted to the active language direction.
  - ``PDFReportConfig``    — user-tunable generation options (output directory,
                             company name, confidentiality label).
  - ``PDFReportGenerator`` — orchestrates the full document build: cover page,
                             executive summary, detailed findings, and footer note.

Version: 1.1.0
"""
from __future__ import annotations

import os
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import KeepTogether
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.language_manager import LanguageManager
from scanner_engine.base import Issue, ScanResult, Severity


# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

class _Palette:
    # Oranovix Guardian — red/black brand palette
    DARK_BG    = colors.HexColor("#0a0a0a")
    PRIMARY    = colors.HexColor("#cc0000")
    CRITICAL   = colors.HexColor("#ff0000")
    HIGH       = colors.HexColor("#cc0000")
    MEDIUM     = colors.HexColor("#ff8800")
    LOW        = colors.HexColor("#00ff41")
    SAFE       = colors.HexColor("#00ff41")
    WHITE      = colors.white
    LIGHT_GRAY = colors.HexColor("#f8f9fa")
    MID_GRAY   = colors.HexColor("#dee2e6")
    TEXT_DARK  = colors.HexColor("#212529")
    TEXT_MID   = colors.HexColor("#6c757d")


def _severity_color(severity: Severity) -> colors.Color:
    """Map a ``Severity`` enum value to its corresponding brand colour.

    Args:
        severity: One of the four ``Severity`` levels defined in
                  ``scanner_engine.base``.

    Returns:
        A ReportLab ``Color`` object from the ``_Palette`` constants.

    Raises:
        KeyError: If an unrecognised ``Severity`` value is passed.
    """
    return {
        Severity.LOW:      _Palette.LOW,
        Severity.MEDIUM:   _Palette.MEDIUM,
        Severity.HIGH:     _Palette.HIGH,
        Severity.CRITICAL: _Palette.CRITICAL,
    }[severity]


# ---------------------------------------------------------------------------
# FontRegistry — Singleton that handles TTF registration
# ---------------------------------------------------------------------------

class FontRegistry:
    """Singleton registry that discovers and registers an Arabic-capable TTF font.

    ReportLab requires TTF fonts to be registered with ``pdfmetrics`` before
    they can be referenced in ``ParagraphStyle`` definitions.  This class walks
    a prioritised list of Windows system font paths and registers the first one
    that exists and can be loaded successfully.  If none are found, it falls
    back to the built-in Helvetica (which covers Latin characters but not Arabic).

    All access is via class methods; the class should never be instantiated.

    Class attributes:
        _arabic_font:      Name of the registered regular-weight font (or fallback).
        _arabic_font_bold: Name of the registered bold-weight font (or fallback).
        _registered:       Guard flag to prevent duplicate ``pdfmetrics`` calls.
        _CANDIDATES:       Ordered list of ``(ttf_path, logical_name, bold_ttf_path)``
                           tuples tried at registration time.
    """

    _arabic_font:      str  = "Helvetica"
    _arabic_font_bold: str  = "Helvetica-Bold"
    _registered:       bool = False

    # Windows system-font candidates (path, regular-name, bold-path-or-None).
    # Tried in order; the first successfully loaded font wins.
    _CANDIDATES: List[Tuple[str, str, Optional[str]]] = [
        ("C:/Windows/Fonts/arial.ttf",    "CG_Arial",    "C:/Windows/Fonts/arialbd.ttf"),
        ("C:/Windows/Fonts/calibri.ttf",  "CG_Calibri",  "C:/Windows/Fonts/calibrib.ttf"),
        ("C:/Windows/Fonts/tahoma.ttf",   "CG_Tahoma",   None),
    ]

    @classmethod
    def get_arabic_font(cls) -> str:
        """Return the logical name of the registered regular-weight font.

        Triggers font discovery and registration on the first call.

        Returns:
            The ReportLab font name string (e.g. ``"CG_Arial"`` or the fallback
            ``"Helvetica"``).
        """
        cls._ensure_registered()
        return cls._arabic_font

    @classmethod
    def get_arabic_bold(cls) -> str:
        """Return the logical name of the registered bold-weight font.

        Triggers font discovery and registration on the first call.

        Returns:
            The ReportLab bold font name string (e.g. ``"CG_Arial-Bold"``).
            Falls back to the regular font name if no separate bold file was found.
        """
        cls._ensure_registered()
        return cls._arabic_font_bold

    @classmethod
    def _ensure_registered(cls) -> None:
        """Register a TTF font with ReportLab if not already done.

        Iterates ``_CANDIDATES`` in order and stops at the first font that both
        exists on disk and loads without error.  Sets ``_registered = True``
        immediately to prevent re-entry even if all candidates fail.
        """
        if cls._registered:
            return
        # Mark as registered early to prevent recursive or repeated calls.
        cls._registered = True
        for reg_path, name, bold_path in cls._CANDIDATES:
            if not os.path.exists(reg_path):
                continue
            try:
                pdfmetrics.registerFont(TTFont(name, reg_path))
                cls._arabic_font = name

                if bold_path and os.path.exists(bold_path):
                    bold_name = name + "-Bold"
                    pdfmetrics.registerFont(TTFont(bold_name, bold_path))
                    cls._arabic_font_bold = bold_name
                else:
                    # No separate bold file available; reuse the regular weight.
                    cls._arabic_font_bold = name

                return
            except Exception:
                # This candidate failed (corrupt file, permission error, etc.);
                # try the next one.
                continue
        # If all candidates fail, Helvetica remains as the safe fallback.
        # Arabic glyphs will not render correctly, but the PDF will not crash.


# ---------------------------------------------------------------------------
# StyleBuilder — builds ReportLab ParagraphStyles per language
# ---------------------------------------------------------------------------

class StyleBuilder:
    """Factory that produces a named dict of ``ParagraphStyle`` objects for a document.

    The styles are adapted to the active language direction: LTR documents use
    Helvetica with left-aligned body text; RTL (Arabic) documents use the
    registered Arabic-capable font with right-aligned body text.  Code blocks
    are always rendered LTR using Courier regardless of language.

    Args:
        is_rtl: When ``True``, RTL-appropriate fonts and text alignment are used.
    """

    def __init__(self, is_rtl: bool = False) -> None:
        """Prepare font and alignment selections based on the text direction.

        Args:
            is_rtl: ``True`` for right-to-left (Arabic) documents,
                    ``False`` for left-to-right documents.
        """
        self._rtl  = is_rtl
        # Select the appropriate font family for body text.
        self._body_font      = FontRegistry.get_arabic_font() if is_rtl else "Helvetica"
        self._body_font_bold = FontRegistry.get_arabic_bold() if is_rtl else "Helvetica-Bold"
        # RTL body text is right-aligned; headings always use centred alignment.
        self._align_body  = TA_RIGHT  if is_rtl else TA_LEFT
        self._align_center = TA_CENTER

    def build(self) -> dict:
        """Build and return the complete named-style dictionary.

        Returns:
            A ``dict`` mapping style names (``"title"``, ``"body"``, ``"code"``,
            etc.) to configured ``ParagraphStyle`` instances ready for use in a
            ReportLab Platypus story.
        """
        f  = self._body_font
        fb = self._body_font_bold
        ac = self._align_center
        ab = self._align_body

        return {
            "title": ParagraphStyle(
                "cg_title",
                fontName=fb,
                fontSize=28,
                textColor=_Palette.WHITE,
                alignment=ac,
                spaceAfter=6,
            ),
            "subtitle": ParagraphStyle(
                "cg_subtitle",
                fontName=f,
                fontSize=12,
                textColor=colors.HexColor("#adb5bd"),
                alignment=ac,
                spaceAfter=4,
            ),
            "section_header": ParagraphStyle(
                "cg_section_header",
                fontName=fb,
                fontSize=14,
                textColor=_Palette.PRIMARY,
                spaceBefore=12,
                spaceAfter=6,
                alignment=ab,
            ),
            "body": ParagraphStyle(
                "cg_body",
                fontName=f,
                fontSize=9,
                textColor=_Palette.TEXT_DARK,
                spaceAfter=4,
                leading=14,
                alignment=ab,
            ),
            "body_bold": ParagraphStyle(
                "cg_body_bold",
                fontName=fb,
                fontSize=9,
                textColor=_Palette.TEXT_DARK,
                alignment=ab,
            ),
            "small": ParagraphStyle(
                "cg_small",
                fontName=f,
                fontSize=8,
                textColor=_Palette.TEXT_MID,
                alignment=ab,
            ),
            "code": ParagraphStyle(
                "cg_code",
                fontName="Courier",
                fontSize=8,
                textColor=colors.HexColor("#e83e8c"),
                backColor=colors.HexColor("#f8f9fa"),
                spaceAfter=2,
                leading=12,
                alignment=TA_LEFT,  # code is always LTR
            ),
            "risk_label": ParagraphStyle(
                "cg_risk_label",
                fontName=fb,
                fontSize=22,
                textColor=_Palette.WHITE,
                alignment=ac,
            ),
        }


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

@dataclass
class PDFReportConfig:
    """User-tunable generation options for the PDF report.

    Attributes:
        output_dir:      Directory where generated PDF files are written.
                         Relative paths are resolved against the project root.
        company_name:    Branding string shown in the report title banner.
        confidentiality: Classification label printed on the cover page
                         (e.g. ``"CONFIDENTIAL"`` or ``"INTERNAL USE ONLY"``).
    """

    output_dir:      str = "reports/output"
    company_name:    str = "Oranovix Guardian"
    confidentiality: str = "CONFIDENTIAL"


# ---------------------------------------------------------------------------
# PDFReportGenerator
# ---------------------------------------------------------------------------

class PDFReportGenerator:
    """Converts a ``ScanResult`` into a professional, multi-page PDF security report.

    The generator follows a linear story-building approach: each section method
    appends ReportLab Platypus flowable objects to a ``story`` list which is
    then handed to ``BaseDocTemplate.build``.  Language and text direction are
    driven by the ``LanguageManager`` singleton, enabling the same code path to
    produce both LTR (English) and RTL (Arabic) documents.

    Section layout (in order):
      1. Cover page  — branding, risk score badge, scan metadata.
      2. Executive summary — severity grid, findings overview, top categories,
                             issues-by-file table.
      3. Detailed findings — one accordion-style block per issue, sorted by severity.
      4. Footer disclaimer note.
    """

    def __init__(self, config: Optional[PDFReportConfig] = None) -> None:
        """Initialise the generator with optional configuration overrides.

        Args:
            config: A ``PDFReportConfig`` instance.  Defaults to the standard
                    configuration when omitted.
        """
        self._config = config or PDFReportConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        scan_result: ScanResult,
        output_path: Optional[str] = None,
    ) -> str:
        """Build the PDF report from a scan result and write it to disk.

        Orchestrates all section builders, constructs the ReportLab document
        with the correct page template (header/footer), and calls ``build``
        to render and write the file.

        Args:
            scan_result:  The completed ``ScanResult`` to document.
            output_path:  Absolute or relative path for the output ``.pdf`` file.
                          When omitted, a timestamped filename is generated inside
                          the configured output directory.

        Returns:
            The absolute path of the generated PDF file as a string.
        """
        lm       = LanguageManager()
        is_rtl   = lm.is_rtl
        # Build the style dictionary adapted to the current language direction.
        styles   = StyleBuilder(is_rtl).build()
        # Create a translation callable that also handles Arabic reshaping when needed.
        t        = self._make_translator(lm, is_rtl)

        path = output_path or self._default_path(scan_result)
        # Ensure the output directory exists before ReportLab tries to open the file.
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

        doc = BaseDocTemplate(
            path,
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=25 * mm,
        )
        doc.addPageTemplates([self._make_page_template(doc, t, lm)])

        # Build the ordered list of Platypus flowables that make up the document.
        story: list = []
        self._add_cover(story, scan_result, styles, t)
        story.append(PageBreak())
        self._add_executive_summary(story, scan_result, styles, t)
        story.append(PageBreak())
        self._add_issue_details(story, scan_result, styles, t)
        self._add_footer_note(story, styles, t)

        doc.build(story)
        return os.path.abspath(path)

    # ------------------------------------------------------------------
    # Translation helper
    # ------------------------------------------------------------------

    @staticmethod
    def _make_translator(lm: LanguageManager, is_rtl: bool):
        """Create a translation callable that optionally reshapes Arabic text.

        ReportLab cannot render Arabic glyphs in their correct visual form
        without pre-processing; the ``arabic-reshaper`` and ``python-bidi``
        libraries handle this transformation.  This factory returns the
        appropriate closure based on whether RTL mode is active and the
        required libraries are available.

        Args:
            lm:     The active ``LanguageManager`` singleton.
            is_rtl: Whether the current language is right-to-left.

        Returns:
            A callable ``t(key, **kwargs) -> str`` that translates a string key
            (and optional format arguments) into the active display language,
            with Arabic reshaping applied when applicable.
        """
        if is_rtl and lm.arabic_libs_available():
            # Reshape and reorder Arabic text so ReportLab renders it correctly.
            def _t(key: str, **kwargs) -> str:
                return lm.process_arabic_for_pdf(lm.t(key, **kwargs))
        else:
            def _t(key: str, **kwargs) -> str:
                return lm.t(key, **kwargs)
        return _t

    # ------------------------------------------------------------------
    # Page template (header / footer)
    # ------------------------------------------------------------------

    @staticmethod
    def _make_page_template(
        doc: BaseDocTemplate,
        t,
        lm: LanguageManager,
    ) -> PageTemplate:
        """Construct the ReportLab ``PageTemplate`` that draws the page footer.

        The template defines a single content ``Frame`` that fills the printable
        area and an ``onPage`` callback that draws the dark footer bar with the
        translated page-number string on every page.

        Args:
            doc: The ``BaseDocTemplate`` whose margin properties define the frame.
            t:   The translation callable returned by ``_make_translator``.
            lm:  The active ``LanguageManager`` (used to detect RTL for font selection).

        Returns:
            A configured ``PageTemplate`` instance with id ``"main"``.
        """
        frame = Frame(
            doc.leftMargin,
            doc.bottomMargin,
            doc.width,
            doc.height,
            id="main",
        )

        def _on_page(canvas, doc):  # noqa: ANN001
            """Draw the footer bar and page-number text on each rendered page."""
            canvas.saveState()
            # Fill the bottom strip with the brand dark background colour.
            canvas.setFillColor(_Palette.DARK_BG)
            canvas.rect(0, 0, A4[0], 18 * mm, fill=1, stroke=0)

            footer_text = t("pdf_footer", page=doc.page)
            # Use the Arabic-capable font when rendering an RTL document.
            font_name = FontRegistry.get_arabic_font() if lm.is_rtl else "Helvetica"
            canvas.setFont(font_name, 8)
            canvas.setFillColor(_Palette.WHITE)
            canvas.drawCentredString(A4[0] / 2, 7 * mm, footer_text)
            canvas.restoreState()

        return PageTemplate(id="main", frames=[frame], onPage=_on_page)

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------

    def _add_cover(
        self, story: list, result: ScanResult, S: dict, t
    ) -> None:
        """Append the cover-page flowables to the document story.

        The cover page contains three visual groups:
          1. Title banner — dark background with the company name.
          2. Risk score badge — coloured cell showing the numeric score and label.
          3. Scan metadata table — target path, scanner name, file count, duration,
             and scan status.

        Args:
            story:  The Platypus flowable list to append to (mutated in place).
            result: The ``ScanResult`` supplying the metadata and risk score.
            S:      Named style dictionary from ``StyleBuilder.build``.
            t:      Translation callable for localising label strings.
        """
        # Title banner
        story.append(
            Table(
                [[Paragraph(self._config.company_name, S["title"])]],
                colWidths=["100%"],
                style=TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), _Palette.DARK_BG),
                    ("TOPPADDING",    (0, 0), (-1, -1), 20),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ]),
            )
        )
        story.append(Spacer(1, 6))
        story.append(Paragraph(t("pdf_title"), S["subtitle"]))
        story.append(Spacer(1, 4))
        story.append(
            Paragraph(
                f"{t('pdf_generated')} {datetime.now().strftime('%B %d, %Y  %H:%M')}",
                S["small"],
            )
        )
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=2, color=_Palette.PRIMARY))
        story.append(Spacer(1, 10))

        # Risk score badge
        risk_color = self._risk_color(result.risk_score)
        story.append(
            Table(
                [[
                    Paragraph(str(result.risk_score), S["risk_label"]),
                    Paragraph(f"/100\n{result.risk_label}", S["subtitle"]),
                ]],
                colWidths=[40 * mm, 80 * mm],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (0, 0), risk_color),
                    ("BACKGROUND", (1, 0), (1, 0), _Palette.DARK_BG),
                    ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING",    (0, 0), (-1, -1), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 12),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
                ]),
            )
        )
        story.append(Spacer(1, 12))

        # Scan metadata table
        meta = [
            [t("pdf_target"),        str(result.target_path)],
            [t("pdf_scanner"),       result.scanner_name],
            [t("pdf_files_scanned"), str(result.files_scanned)],
            [t("pdf_duration"),      f"{result.duration_seconds:.1f}s"],
            [t("pdf_status"),        self._status_text(result, t)],
        ]
        story.append(
            Table(
                meta,
                colWidths=[50 * mm, None],
                style=TableStyle([
                    ("FONTNAME",       (0, 0), (0, -1), FontRegistry.get_arabic_bold()),
                    ("FONTNAME",       (1, 0), (1, -1), FontRegistry.get_arabic_font()),
                    ("FONTSIZE",       (0, 0), (-1, -1), 9),
                    ("TEXTCOLOR",      (0, 0), (0, -1), _Palette.TEXT_MID),
                    ("TEXTCOLOR",      (1, 0), (1, -1), _Palette.TEXT_DARK),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_Palette.LIGHT_GRAY, _Palette.WHITE]),
                    ("TOPPADDING",     (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
                    ("LEFTPADDING",    (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
                ]),
            )
        )

        self._add_engine_warnings(story, result, S, t)

    @staticmethod
    def _status_text(result: ScanResult, t) -> str:
        if result.engine_warnings:
            return f"{result.status.value} ({t('status_with_warnings')})"
        return result.status.value

    @staticmethod
    def _add_engine_warnings(story: list, result: ScanResult, S: dict, t) -> None:
        """List engines that could not run so the report never looks complete when it is not."""
        if not result.engine_warnings:
            return
        story.append(Spacer(1, 10))
        story.append(Paragraph(t("engine_warnings_title"), S["body_bold"]))
        story.append(Spacer(1, 3))
        for warning in result.engine_warnings:
            story.append(Paragraph(f"! {escape(warning)}", S["body"]))

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def _add_executive_summary(
        self, story: list, result: ScanResult, S: dict, t
    ) -> None:
        """Append the executive summary section to the document story.

        This section contains:
          - A four-cell severity grid (Critical / High / Medium / Low counts).
          - A findings-overview paragraph with scan statistics.
          - The top-5 most common rule IDs with occurrence counts.
          - An issues-by-file breakdown table sorted by descending issue count.

        Args:
            story:  The Platypus flowable list to append to (mutated in place).
            result: The ``ScanResult`` providing counts and issue data.
            S:      Named style dictionary from ``StyleBuilder.build``.
            t:      Translation callable for localising label strings.
        """
        story.append(Paragraph(t("pdf_exec_summary"), S["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=_Palette.MID_GRAY))
        story.append(Spacer(1, 6))

        # Severity grid
        stats = [
            (t("pdf_critical"), result.critical_count, _Palette.CRITICAL),
            (t("pdf_high"),     result.high_count,     _Palette.HIGH),
            (t("pdf_medium"),   result.medium_count,   _Palette.MEDIUM),
            (t("pdf_low"),      result.low_count,      _Palette.LOW),
        ]
        cells = []
        for label, count, color in stats:
            cells.append(
                Table(
                    [[Paragraph(str(count), S["risk_label"])],
                     [Paragraph(label,      S["subtitle"])]],
                    style=TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), color),
                        ("TOPPADDING",    (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
                    ]),
                )
            )
        story.append(
            Table(
                [cells],
                colWidths=[None, None, None, None],
                style=TableStyle([
                    ("LEFTPADDING",  (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ]),
            )
        )
        story.append(Spacer(1, 10))

        # Findings overview paragraph
        story.append(Paragraph(t("pdf_findings_overview"), S["body_bold"]))
        story.append(Spacer(1, 4))
        story.append(
            Paragraph(
                t(
                    "pdf_findings_text",
                    filename=os.path.basename(result.target_path),
                    duration=f"{result.duration_seconds:.1f}",
                    files=result.files_scanned,
                    total=result.total_issues,
                    score=result.risk_score,
                    risk_label=result.risk_label,
                ),
                S["body"],
            )
        )

        # Top categories: count issues by rule_id and list the 5 most frequent.
        if result.issues:
            story.append(Spacer(1, 6))
            story.append(Paragraph(t("pdf_most_common"), S["body_bold"]))
            story.append(Spacer(1, 4))
            top = Counter(i.rule_id for i in result.issues).most_common(5)
            for rule_id, cnt in top:
                # Resolve the human-readable title from the first matching issue.
                title = next(
                    (i.title for i in result.issues if i.rule_id == rule_id),
                    rule_id,  # fall back to the rule ID itself if no title is found
                )
                # Use the singular form when exactly one occurrence is found.
                occ = t("occurrences") if cnt > 1 else t("occurrence")
                story.append(
                    Paragraph(f"• <b>{rule_id}</b> – {title} ({cnt} {occ})", S["body"])
                )

        story.append(Spacer(1, 10))

        # Issues by file table: group issues by filename and sort descending by count.
        if result.issues:
            story.append(Paragraph(t("pdf_issues_by_file"), S["body_bold"]))
            story.append(Spacer(1, 4))
            by_file = result.issues_by_file()
            file_data = [[t("pdf_file_header"), t("pdf_issues_header")]]
            # Sort files so the most-affected files appear at the top of the table.
            for fp, file_issues in sorted(
                by_file.items(), key=lambda x: -len(x[1])
            ):
                file_data.append([
                    Paragraph(os.path.basename(fp), S["small"]),
                    str(len(file_issues)),
                ])
            story.append(
                Table(
                    file_data,
                    colWidths=[None, 25 * mm],
                    style=TableStyle([
                        ("FONTNAME",       (0, 0), (-1, 0), FontRegistry.get_arabic_bold()),
                        ("BACKGROUND",     (0, 0), (-1, 0), _Palette.PRIMARY),
                        ("TEXTCOLOR",      (0, 0), (-1, 0), _Palette.WHITE),
                        ("FONTSIZE",       (0, 0), (-1, -1), 8),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_Palette.WHITE, _Palette.LIGHT_GRAY]),
                        ("ALIGN",          (1, 0), (1, -1), "CENTER"),
                        ("TOPPADDING",     (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
                        ("LEFTPADDING",    (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING",   (0, 0), (-1, -1), 6),
                        ("GRID",           (0, 0), (-1, -1), 0.25, _Palette.MID_GRAY),
                    ]),
                )
            )

    # ------------------------------------------------------------------
    # Detailed findings
    # ------------------------------------------------------------------

    def _add_issue_details(
        self, story: list, result: ScanResult, S: dict, t
    ) -> None:
        """Append the detailed findings section to the document story.

        Each issue is rendered as a ``KeepTogether`` block containing a coloured
        header bar with the title and severity badge, a metadata grid (rule ID,
        confidence, file location, CWE), and optional description, code snippet,
        and recommendation paragraphs.  Issues are sorted by descending severity
        weight so the most critical findings appear first.

        Args:
            story:  The Platypus flowable list to append to (mutated in place).
            result: The ``ScanResult`` whose ``issues`` list is rendered.
            S:      Named style dictionary from ``StyleBuilder.build``.
            t:      Translation callable for localising label strings.
        """
        story.append(Paragraph(t("pdf_detailed_findings"), S["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=_Palette.MID_GRAY))
        story.append(Spacer(1, 6))

        if not result.issues:
            story.append(Paragraph(t("pdf_no_issues_detail"), S["body"]))
            return

        # Sort highest-severity issues first using the numeric weight attribute.
        sorted_issues = sorted(result.issues, key=lambda i: -i.severity.weight)

        for idx, issue in enumerate(sorted_issues, 1):
            sev_color = _severity_color(issue.severity)
            block = [
                Table(
                    [[
                        Paragraph(f"#{idx}  {issue.title}", S["body_bold"]),
                        Paragraph(issue.severity.value,     S["body_bold"]),
                    ]],
                    colWidths=[None, 24 * mm],
                    style=TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), sev_color),
                        ("TEXTCOLOR",     (0, 0), (-1, -1), _Palette.WHITE),
                        ("FONTSIZE",      (0, 0), (-1, -1), 9),
                        ("TOPPADDING",    (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                        ("ALIGN",         (1, 0), (1, 0), "CENTER"),
                    ]),
                ),
                Spacer(1, 2),
                Table(
                    [
                        [Paragraph(t("pdf_rule_id"),   S["small"]),
                         Paragraph(issue.rule_ids_label, S["body"]),
                         Paragraph(t("pdf_confidence"), S["small"]),
                         Paragraph(issue.confidence,   S["body"])],
                        [Paragraph(t("pdf_file_label"), S["small"]),
                         Paragraph(f"{issue.filename}:{issue.line_number}", S["body"]),
                         Paragraph(t("pdf_cwe"),        S["small"]),
                         Paragraph(issue.cwe or "—",   S["body"])],
                    ],
                    colWidths=[22 * mm, None, 25 * mm, 35 * mm],
                    style=TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), _Palette.LIGHT_GRAY),
                        ("FONTSIZE",      (0, 0), (-1, -1), 8),
                        ("TOPPADDING",    (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                        ("GRID",          (0, 0), (-1, -1), 0.25, _Palette.MID_GRAY),
                    ]),
                ),
            ]

            if issue.description:
                block += [
                    Spacer(1, 3),
                    Paragraph(t("pdf_description"), S["small"]),
                    Paragraph(issue.description, S["body"]),
                ]

            if issue.code_snippet:
                # HTML-escape the snippet so XML special characters do not break
                # ReportLab's markup parser when embedded in a Paragraph.
                safe = (
                    issue.code_snippet
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                )
                block += [
                    Spacer(1, 3),
                    Paragraph(t("pdf_code_snippet"), S["small"]),
                    Paragraph(
                        f"<font name='Courier' size='8'>{safe[:300]}</font>",
                        S["code"],
                    ),
                ]

            if issue.recommendation:
                block += [
                    Spacer(1, 3),
                    Paragraph(t("pdf_recommendation"), S["small"]),
                    Paragraph(issue.recommendation, S["body"]),
                ]

            block.append(Spacer(1, 10))
            story.append(KeepTogether(block))

    # ------------------------------------------------------------------
    # Footer disclaimer
    # ------------------------------------------------------------------

    def _add_footer_note(self, story: list, S: dict, t) -> None:
        """Append the closing disclaimer paragraph to the document story.

        Args:
            story: The Platypus flowable list to append to (mutated in place).
            S:     Named style dictionary from ``StyleBuilder.build``.
            t:     Translation callable for localising the disclaimer text.
        """
        story.append(HRFlowable(width="100%", thickness=1, color=_Palette.MID_GRAY))
        story.append(Spacer(1, 4))
        story.append(Paragraph(t("pdf_footer_note"), S["small"]))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _default_path(self, result: ScanResult) -> str:
        """Generate a default timestamped output file path.

        Relative ``output_dir`` values are resolved against the project root
        directory.  When running as a PyInstaller frozen executable, the base
        path is the directory containing the executable rather than the
        source tree.

        Args:
            result: The ``ScanResult`` whose target basename is incorporated
                    into the filename for easy identification.

        Returns:
            An absolute path string for the output PDF file, e.g.
            ``"/project/reports/output/oranovix_report_myapp_20260331_120000.pdf"``.
        """
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = os.path.basename(result.target_path) or "scan"
        out_dir = self._config.output_dir
        # Resolve relative paths against the project root (or executable directory).
        if not os.path.isabs(out_dir):
            if getattr(sys, "frozen", False):
                # PyInstaller sets sys.frozen; use the executable's directory.
                base = os.path.dirname(sys.executable)
            else:
                # Normal execution: go up one level from the reports/ package.
                base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            out_dir = os.path.join(base, out_dir)
        os.makedirs(out_dir, exist_ok=True)
        return os.path.join(out_dir, f"oranovix_report_{name}_{ts}.pdf")

    @staticmethod
    def _risk_color(score: int) -> colors.Color:
        """Map a numeric risk score to a brand colour for the score badge.

        The thresholds mirror the risk-level definitions used in the scanner engine:
          0        → safe (green)
          1 – 20   → low (green)
          21 – 50  → medium (orange)
          51 – 80  → high (red)
          81 – 100 → critical (bright red)

        Args:
            score: Integer risk score in the range 0–100.

        Returns:
            A ReportLab ``Color`` object from the ``_Palette`` constants.
        """
        if score == 0:   return _Palette.SAFE
        if score <= 20:  return _Palette.LOW
        if score <= 50:  return _Palette.MEDIUM
        if score <= 80:  return _Palette.HIGH
        return _Palette.CRITICAL
