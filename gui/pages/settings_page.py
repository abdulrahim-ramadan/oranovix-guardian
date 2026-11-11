"""
User-preferences page for Oranovix Guardian, covering appearance, language, sound, and AI settings.

This module provides two classes.  :class:`_Section` is a private helper
that renders a card-style labeled group box used to visually separate
settings categories.  :class:`SettingsPage` is the public scrollable page
widget that exposes every user-configurable preference:

- **Appearance** — toggle between dark and light themes.
- **Language** — switch the active locale via a drop-down (delegates to
  :class:`~core.language_manager.LanguageManager`).
- **Sound Alerts** — enable / disable audio feedback, adjust volume with a
  slider, and test each of the three named tones via
  :class:`~core.sound_manager.SoundManager`.
- **AI Analysis** — enter an optional Google Gemini API key for AI-powered
  code analysis.
- **About** — static product information.

The page is built once per application run (or UI rebuild) by
:meth:`~gui.app.CodeGuardianApp._build_pages`.

Version: 1.1.0
"""
from __future__ import annotations

from typing import Literal

import os
from tkinter import filedialog

import customtkinter as ctk

from gui.theme_manager        import ThemeManager
from core.language_manager    import LanguageManager
from core.sound_manager       import SoundManager
from scanner_engine.rule_engine import RuleEngine, Rule, RuleLanguage


class _Section(ctk.CTkFrame):
    """A labeled card that groups related settings visually.

    Renders a rounded, bordered frame with a bold title label and a thin
    horizontal divider beneath it.  Child widgets should be packed into
    this frame after construction.

    Args:
        master: The parent widget (typically the scrollable settings body).
        title:  The section heading text, including any leading emoji.
        **kwargs: Additional keyword arguments forwarded to
            :class:`ctk.CTkFrame`.
    """

    def __init__(self, master, title: str, **kwargs) -> None:
        tm = ThemeManager()
        super().__init__(
            master,
            fg_color=tm.c("card"),
            corner_radius=10,
            border_width=1,
            border_color=tm.c("border"),
            **kwargs,
        )
        # Section heading label, left-aligned with consistent padding
        ctk.CTkLabel(
            self,
            text=title,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=tm.c("text"),
            fg_color="transparent",
            anchor="w",
        ).pack(anchor="w", padx=16, pady=(12, 6))
        # 1-pixel divider separates the heading from the section body
        ctk.CTkFrame(self, height=1, fg_color=tm.c("border"),
                     corner_radius=0).pack(fill="x")


class SettingsPage(ctk.CTkFrame):
    """Scrollable settings page containing all user-configurable preferences.

    Displays grouped preference sections (Appearance, Language, Sound
    Alerts, AI Analysis, About) inside a
    :class:`ctk.CTkScrollableFrame`.  Sound-related controls read their
    initial state from the :class:`~core.sound_manager.SoundManager`
    singleton and write changes back to it immediately (which in turn
    persists them to ``settings.json``).

    Args:
        master:          The parent widget (the content area frame).
        on_theme_toggle: Zero-argument callable that triggers a theme flip
                         in :class:`~gui.app.CodeGuardianApp`.
        on_lang_change:  Single-argument callable that receives a display
                         name string (e.g. ``"Deutsch"``) and delegates to
                         :class:`~core.language_manager.LanguageManager`.
        **kwargs:        Additional keyword arguments forwarded to
                         :class:`ctk.CTkFrame`.
    """

    def __init__(self, master, on_theme_toggle, on_lang_change, **kwargs) -> None:
        tm = ThemeManager()
        super().__init__(master, fg_color=tm.c("bg"), corner_radius=0, **kwargs)
        self._on_theme = on_theme_toggle
        self._on_lang  = on_lang_change
        # Obtain the singleton SoundManager to read and update sound settings
        self._sm       = SoundManager()
        self._build()

    def _build(self) -> None:
        """Construct all settings widgets and pack them into the page.

        Builds a fixed-height header bar and a scrollable body that
        contains one :class:`_Section` card per settings category.
        References to interactive widgets (``_snd_switch``,
        ``_vol_slider``, ``_vol_lbl``, ``_api_entry``) are stored as
        instance attributes so the event handlers can access them.
        """
        tm = ThemeManager()
        lm = LanguageManager()

        # ── Fixed-height page header ──────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=tm.c("bg2"), corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr,
            text="  ⚙️  Settings",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=tm.c("text"),
            fg_color="transparent",
            anchor="w",
        ).pack(side="left", padx=16, fill="y")

        # Scrollable container for all section cards
        scroll = ctk.CTkScrollableFrame(self, fg_color=tm.c("bg"), corner_radius=0)
        scroll.pack(fill="both", expand=True, padx=20, pady=12)

        # ── Appearance ────────────────────────────────────────────────
        app_sec = _Section(scroll, "🎨  Appearance")
        app_sec.pack(fill="x", pady=(0, 12))

        row = ctk.CTkFrame(app_sec, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=10)
        ctk.CTkLabel(
            row,
            text=f"{tm.toggle_icon}  Theme Mode",
            font=ctk.CTkFont(size=12),
            text_color=tm.c("text"),
            fg_color="transparent",
        ).pack(side="left")
        # Button label dynamically reflects the *target* theme (opposite of current)
        ctk.CTkButton(
            row,
            text=f"Switch to {'Light ☀️' if tm.is_dark else 'Dark 🌙'}",
            width=160, height=30, corner_radius=6,
            fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
            text_color="#ffffff", font=ctk.CTkFont(size=11),
            command=self._on_theme,
        ).pack(side="right")

        # ── Language ──────────────────────────────────────────────────
        lang_sec = _Section(scroll, "🌐  Language")
        lang_sec.pack(fill="x", pady=(0, 12))

        row2 = ctk.CTkFrame(lang_sec, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=10)
        ctk.CTkLabel(
            row2, text=lm.t("language"),
            font=ctk.CTkFont(size=12), text_color=tm.c("text"),
            fg_color="transparent",
        ).pack(side="left")
        # StringVar initialised to the currently active language display name
        lang_var = ctk.StringVar(value=lm.current_display_name)
        ctk.CTkOptionMenu(
            row2, values=lm.display_names, variable=lang_var,
            command=self._on_lang,   # called with the selected display name
            width=160, height=30,
            fg_color=tm.c("bg3"), button_color=tm.c("accent"),
            button_hover_color=tm.c("accent_h"), text_color=tm.c("text"),
            font=ctk.CTkFont(size=11),
        ).pack(side="right")

        # ── Sound Alerts ──────────────────────────────────────────────
        snd_sec = _Section(scroll, "🔔  Sound Alerts")
        snd_sec.pack(fill="x", pady=(0, 12))

        # Enable / disable toggle row
        row3 = ctk.CTkFrame(snd_sec, fg_color="transparent")
        row3.pack(fill="x", padx=16, pady=(10, 4))
        ctk.CTkLabel(
            row3, text="Enable sound alerts",
            font=ctk.CTkFont(size=12), text_color=tm.c("text"),
            fg_color="transparent",
        ).pack(side="left")
        self._snd_switch = ctk.CTkSwitch(
            row3, text="",
            onvalue=True, offvalue=False,
            fg_color=tm.c("border"), progress_color=tm.c("accent"),
            command=self._toggle_sound,
        )
        self._snd_switch.pack(side="right")
        # Sync the switch visual state with the persisted SoundManager setting
        if self._sm.enabled:
            self._snd_switch.select()
        else:
            self._snd_switch.deselect()

        # Volume slider row
        row4 = ctk.CTkFrame(snd_sec, fg_color="transparent")
        row4.pack(fill="x", padx=16, pady=(4, 4))
        ctk.CTkLabel(
            row4, text="Volume",
            font=ctk.CTkFont(size=11), text_color=tm.c("text2"),
            fg_color="transparent", width=60,
        ).pack(side="left")
        # Percentage label updated live as the slider moves
        self._vol_lbl = ctk.CTkLabel(
            row4, text=f"{int(self._sm.volume * 100)}%",
            font=ctk.CTkFont(size=11), text_color=tm.c("accent"),
            fg_color="transparent", width=40,
        )
        self._vol_lbl.pack(side="right")
        self._vol_slider = ctk.CTkSlider(
            row4,
            from_=0, to=100, number_of_steps=20,   # 5% increments
            progress_color=tm.c("accent"), fg_color=tm.c("border"),
            button_color=tm.c("accent"), button_hover_color=tm.c("accent_h"),
            command=self._on_volume_change,
        )
        # Initialise slider position from the persisted volume (convert 0–1 → 0–100)
        self._vol_slider.set(self._sm.volume * 100)
        self._vol_slider.pack(side="right", fill="x", expand=True, padx=(0, 8))

        # Tone test buttons row (one button per named tone)
        row5 = ctk.CTkFrame(snd_sec, fg_color="transparent")
        row5.pack(fill="x", padx=16, pady=(4, 12))
        ctk.CTkLabel(
            row5, text="Test tones:",
            font=ctk.CTkFont(size=10), text_color=tm.c("text3"),
            fg_color="transparent",
        ).pack(side="left", padx=(0, 8))
        # Default argument binding (t=tone) captures the loop variable correctly
        for tone, label in [("complete", "✓ Complete"), ("critical", "⚠ Critical"),
                             ("error", "✗ Error")]:
            ctk.CTkButton(
                row5, text=label, width=90, height=24, corner_radius=6,
                fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
                text_color=tm.c("text2"), font=ctk.CTkFont(size=9),
                command=lambda t=tone: self._sm.play(t),
            ).pack(side="left", padx=2)

        # ── AI Analysis ───────────────────────────────────────────────
        ai_sec = _Section(scroll, "🤖  AI Analysis (Gemini)")
        ai_sec.pack(fill="x", pady=(0, 12))

        ai_body = ctk.CTkFrame(ai_sec, fg_color="transparent")
        ai_body.pack(fill="x", padx=16, pady=10)
        ctk.CTkLabel(
            ai_body, text=lm.t("api_key"),
            font=ctk.CTkFont(size=11), text_color=tm.c("text2"),
            fg_color="transparent",
        ).pack(anchor="w", pady=(0, 4))
        # API key field uses bullet masking (show="•") for basic privacy
        self._api_entry = ctk.CTkEntry(
            ai_body, placeholder_text="AIza…", show="•",
            fg_color=tm.c("input_bg"), border_color=tm.c("border"),
            text_color=tm.c("text"), height=32,
        )
        self._api_entry.pack(fill="x")
        ctk.CTkLabel(
            ai_body, text="Optional — get a free key at aistudio.google.com",
            font=ctk.CTkFont(size=9), text_color=tm.c("text3"),
            fg_color="transparent",
        ).pack(anchor="w", pady=(4, 0))

        # ── Rules Manager ─────────────────────────────────────────────
        rules_sec = _Section(scroll, f"\U0001f4cb  {lm.t('rules_manager')}")
        rules_sec.pack(fill="x", pady=(0, 12))
        self._rules_sec = rules_sec
        self._build_rules_section(rules_sec, tm, lm)

        # ── About ─────────────────────────────────────────────────────
        about_sec = _Section(scroll, "ℹ️  About")
        about_sec.pack(fill="x", pady=(0, 20))

        # Each tuple: (text, font_size, weight, theme_color_key)
        about_lines: list[tuple[str, int, Literal["normal", "bold"], str]] = [
            ("Oranovix Guardian", 14, "bold", "text"),
            ("Professional Security Scanner  •  v1.0.0", 11, "normal", "text2"),
            ("100% free — powered by Bandit, Gemini & ReportLab", 10, "normal", "text3"),
        ]
        for line in about_lines:
            ctk.CTkLabel(
                about_sec, text=line[0],
                font=ctk.CTkFont(size=line[1], weight=line[2]),
                text_color=tm.c(line[3]), fg_color="transparent",
            ).pack(anchor="w", padx=16, pady=2)
        # Spacer at the bottom of the About card
        ctk.CTkFrame(about_sec, height=8, fg_color="transparent").pack()

    # ------------------------------------------------------------------
    # Sound handlers
    # ------------------------------------------------------------------

    def _toggle_sound(self) -> None:
        """Write the switch state back to SoundManager and persist it.

        ``CTkSwitch.get()`` returns the ``onvalue`` or ``offvalue`` passed
        at construction; casting to ``bool`` normalises both to a clean
        Python boolean before assignment.
        """
        self._sm.enabled = bool(self._snd_switch.get())

    def _on_volume_change(self, value: float) -> None:
        """Update SoundManager volume and refresh the percentage label.

        Args:
            value: Slider value in the range 0–100 (floats from CTkSlider).
                   Divided by 100 before storing so SoundManager receives
                   a normalised 0.0–1.0 float.
        """
        self._sm.volume = value / 100      # normalise to 0.0–1.0
        self._vol_lbl.configure(text=f"{int(value)}%")

    def refresh_theme(self) -> None:
        """Re-apply the background colour after a theme change."""
        tm = ThemeManager()
        self.configure(fg_color=tm.c("bg"))

    # ------------------------------------------------------------------
    # Rules Manager section builder
    # ------------------------------------------------------------------

    def _build_rules_section(self, parent, tm, lm) -> None:
        """Build the Rules Manager UI inside the given section frame."""
        self._engine = RuleEngine()

        # Action buttons row
        btn_row = ctk.CTkFrame(parent, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(10, 6))

        ctk.CTkButton(
            btn_row, text=f"+ {lm.t('add_rule')}",
            width=110, height=28, corner_radius=6,
            fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
            text_color="#ffffff", font=ctk.CTkFont(size=10),
            command=self._open_add_rule_dialog,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_row, text=f"\u2b06 {lm.t('import_rules')}",
            width=110, height=28, corner_radius=6,
            fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
            text_color=tm.c("text2"), font=ctk.CTkFont(size=10),
            command=self._import_rules,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_row, text=f"\u2b07 {lm.t('export_rules')}",
            width=110, height=28, corner_radius=6,
            fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
            text_color=tm.c("text2"), font=ctk.CTkFont(size=10),
            command=self._export_rules,
        ).pack(side="left")

        # Rule count label
        self._rule_count_lbl = ctk.CTkLabel(
            btn_row,
            text=self._rules_count_text(lm),
            font=ctk.CTkFont(size=9), text_color=tm.c("text3"),
            fg_color="transparent",
        )
        self._rule_count_lbl.pack(side="right")

        # Scrollable rule list
        self._rules_list_frame = ctk.CTkScrollableFrame(
            parent, fg_color=tm.c("bg2"), corner_radius=6, height=180,
        )
        self._rules_list_frame.pack(fill="x", padx=16, pady=(0, 12))
        self._refresh_rules_list()

    def _rules_count_text(self, lm=None) -> str:
        if lm is None:
            lm = LanguageManager()
        total   = len(self._engine.rules)
        enabled = sum(1 for r in self._engine.rules if r.enabled)
        return f"{enabled}/{total} {lm.t('rules_active')}"

    def _refresh_rules_list(self) -> None:
        """Repopulate the rules list frame from the current engine state."""
        tm = ThemeManager()
        lm = LanguageManager()

        # Clear existing widgets
        for child in self._rules_list_frame.winfo_children():
            child.destroy()

        if not self._engine.rules:
            ctk.CTkLabel(
                self._rules_list_frame,
                text=lm.t("no_rules"),
                font=ctk.CTkFont(size=11), text_color=tm.c("text3"),
                fg_color="transparent",
            ).pack(pady=12)
            return

        for rule in self._engine.rules:
            self._build_rule_row(self._rules_list_frame, rule, tm, lm)

        # Update count label if it exists
        if hasattr(self, "_rule_count_lbl"):
            self._rule_count_lbl.configure(text=self._rules_count_text(lm))

    def _build_rule_row(self, parent, rule: Rule, tm, lm) -> None:
        """Build a single rule row with toggle, name, and delete button."""
        row = ctk.CTkFrame(parent, fg_color=tm.c("card"), corner_radius=6)
        row.pack(fill="x", pady=2)

        # Toggle switch
        sw_var = ctk.BooleanVar(value=rule.enabled)
        sw = ctk.CTkSwitch(
            row, text="", variable=sw_var,
            onvalue=True, offvalue=False,
            fg_color=tm.c("border"), progress_color=tm.c("accent"),
            width=40,
            command=lambda r=rule, v=sw_var: self._toggle_rule(r.id, v.get()),
        )
        sw.pack(side="left", padx=(8, 4))

        # Severity badge
        sev_colors = {
            "CRITICAL": tm.c("critical"), "HIGH": tm.c("high"),
            "MEDIUM": tm.c("medium"),     "LOW": tm.c("low"),
        }
        badge_color = sev_colors.get(rule.severity.upper(), tm.c("text3"))
        ctk.CTkLabel(
            row, text=f" {rule.severity[:3]} ",
            fg_color=badge_color, corner_radius=3,
            font=ctk.CTkFont(size=8, weight="bold"),
            text_color="#ffffff", width=30,
        ).pack(side="left", padx=(0, 6))

        # Rule name and language
        ctk.CTkLabel(
            row, text=rule.name,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=tm.c("text") if rule.enabled else tm.c("text3"),
            fg_color="transparent", anchor="w",
        ).pack(side="left", fill="x", expand=True)

        lang_tag = rule.language if rule.language != "ALL" else "ALL"
        ctk.CTkLabel(
            row, text=lang_tag,
            font=ctk.CTkFont(size=8), text_color=tm.c("text3"),
            fg_color="transparent", width=70,
        ).pack(side="left")

        # Built-in indicator or Delete button
        if rule.is_builtin:
            ctk.CTkLabel(
                row, text="built-in",
                font=ctk.CTkFont(size=8), text_color=tm.c("text3"),
                fg_color="transparent", width=50,
            ).pack(side="right", padx=(0, 8))
        else:
            ctk.CTkButton(
                row, text="✕", width=24, height=22, corner_radius=4,
                fg_color=tm.c("bg3"), hover_color=tm.c("error"),
                text_color=tm.c("text2"), font=ctk.CTkFont(size=9),
                command=lambda r_id=rule.id: self._delete_rule(r_id),
            ).pack(side="right", padx=(0, 6))

    def _toggle_rule(self, rule_id: str, enabled: bool) -> None:
        if enabled:
            self._engine.enable_rule(rule_id)
        else:
            self._engine.disable_rule(rule_id)
        lm = LanguageManager()
        if hasattr(self, "_rule_count_lbl"):
            self._rule_count_lbl.configure(text=self._rules_count_text(lm))

    def _delete_rule(self, rule_id: str) -> None:
        self._engine.delete_rule(rule_id)
        self._refresh_rules_list()

    def _import_rules(self) -> None:
        lm = LanguageManager()
        path = filedialog.askopenfilename(
            title=lm.t("import_rules"),
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        count = self._engine.import_rules(path)
        self._refresh_rules_list()

    def _export_rules(self) -> None:
        lm = LanguageManager()
        path = filedialog.asksaveasfilename(
            title=lm.t("export_rules"),
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        try:
            self._engine.export_rules(path, include_builtin=False)
        except Exception:
            pass

    def _open_add_rule_dialog(self) -> None:
        """Open a dialog to create a new custom rule."""
        tm = ThemeManager()
        lm = LanguageManager()

        dlg = ctk.CTkToplevel(self)
        dlg.title(lm.t("add_rule"))
        dlg.geometry("520x560")
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.configure(fg_color=tm.c("bg"))

        ctk.CTkLabel(
            dlg, text=f"+ {lm.t('add_rule')}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=tm.c("text"), fg_color="transparent",
        ).pack(anchor="w", padx=20, pady=(16, 4))
        ctk.CTkFrame(dlg, height=1, fg_color=tm.c("border"),
                     corner_radius=0).pack(fill="x")

        body = ctk.CTkScrollableFrame(dlg, fg_color=tm.c("bg"), corner_radius=0)
        body.pack(fill="both", expand=True, padx=20, pady=10)

        def _field(label: str, placeholder: str = "", show: str = "") -> ctk.CTkEntry:
            ctk.CTkLabel(body, text=label, font=ctk.CTkFont(size=10),
                         text_color=tm.c("text2"), fg_color="transparent",
                         anchor="w").pack(anchor="w", pady=(8, 2))
            e = ctk.CTkEntry(
                body, placeholder_text=placeholder, show=show,
                fg_color=tm.c("input_bg"), border_color=tm.c("border"),
                text_color=tm.c("text"), height=30,
            )
            e.pack(fill="x")
            return e

        e_id   = _field(lm.t("rule_id"),      "CUST-001")
        e_name = _field(lm.t("rule_name"),     "My Custom Rule")
        e_desc = _field(lm.t("rule_description"), "What this rule detects")
        e_pat  = _field(lm.t("rule_pattern"),  r"(?i)your_regex_here")

        # Severity dropdown
        ctk.CTkLabel(body, text=lm.t("rule_severity"),
                     font=ctk.CTkFont(size=10), text_color=tm.c("text2"),
                     fg_color="transparent", anchor="w").pack(anchor="w", pady=(8, 2))
        sev_var = ctk.StringVar(value="MEDIUM")
        ctk.CTkOptionMenu(
            body, values=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            variable=sev_var, width=160, height=30,
            fg_color=tm.c("bg3"), button_color=tm.c("accent"),
            button_hover_color=tm.c("accent_h"), text_color=tm.c("text"),
            font=ctk.CTkFont(size=10),
        ).pack(anchor="w")

        # Language dropdown
        ctk.CTkLabel(body, text=lm.t("rule_language"),
                     font=ctk.CTkFont(size=10), text_color=tm.c("text2"),
                     fg_color="transparent", anchor="w").pack(anchor="w", pady=(8, 2))
        lang_var = ctk.StringVar(value="ALL")
        ctk.CTkOptionMenu(
            body,
            values=["ALL", "Python", "JavaScript", "PHP", "Java", "C#"],
            variable=lang_var, width=160, height=30,
            fg_color=tm.c("bg3"), button_color=tm.c("accent"),
            button_hover_color=tm.c("accent_h"), text_color=tm.c("text"),
            font=ctk.CTkFont(size=10),
        ).pack(anchor="w")

        e_fix = _field(lm.t("rule_fix"), "Suggested fix for this issue")

        # Test area
        ctk.CTkLabel(body, text=lm.t("test_rule"),
                     font=ctk.CTkFont(size=10), text_color=tm.c("text2"),
                     fg_color="transparent", anchor="w").pack(anchor="w", pady=(8, 2))
        test_box = ctk.CTkTextbox(body, height=60, fg_color=tm.c("log_bg"),
                                   text_color=tm.c("text"),
                                   font=ctk.CTkFont(family="Consolas", size=9))
        test_box.pack(fill="x")
        test_result_lbl = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont(size=9),
            text_color=tm.c("text3"), fg_color="transparent", anchor="w",
        )
        test_result_lbl.pack(anchor="w")

        def _test() -> None:
            sample = test_box.get("1.0", "end").strip()
            if not sample or not e_pat.get():
                return
            tmp_rule = Rule(
                id=e_id.get() or "TEST",
                name=e_name.get() or "Test Rule",
                description="", pattern=e_pat.get(),
                severity=sev_var.get(), language=lang_var.get(),
            )
            try:
                issues = self._engine.test_rule(tmp_rule, sample)
                if issues:
                    test_result_lbl.configure(
                        text=f"\u2713 {len(issues)} match(es) found",
                        text_color=tm.c("warning"),
                    )
                else:
                    test_result_lbl.configure(
                        text="\u2713 No matches (pattern may be incorrect)",
                        text_color=tm.c("success"),
                    )
            except Exception as exc:
                test_result_lbl.configure(
                    text=f"\u26a0 Error: {exc}", text_color=tm.c("error")
                )

        # Bottom buttons
        btn_f = ctk.CTkFrame(dlg, fg_color=tm.c("bg2"), corner_radius=0, height=50)
        btn_f.pack(fill="x", side="bottom")
        btn_f.pack_propagate(False)

        ctk.CTkButton(
            btn_f, text=lm.t("test_rule"),
            width=100, height=30, corner_radius=6,
            fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
            text_color=tm.c("text2"), font=ctk.CTkFont(size=10),
            command=_test,
        ).pack(side="left", padx=(16, 6), pady=10)

        def _save() -> None:
            rule_id = e_id.get().strip()
            name    = e_name.get().strip()
            pattern = e_pat.get().strip()
            if not all([rule_id, name, pattern]):
                return
            rule = Rule(
                id=rule_id, name=name,
                description=e_desc.get().strip(),
                pattern=pattern,
                severity=sev_var.get(),
                language=lang_var.get(),
                enabled=True,
                fix_suggestion=e_fix.get().strip(),
                is_builtin=False,
            )
            self._engine.add_rule(rule)
            self._refresh_rules_list()
            dlg.destroy()

        ctk.CTkButton(
            btn_f, text=lm.t("save_rule"),
            width=100, height=30, corner_radius=6,
            fg_color=tm.c("accent"), hover_color=tm.c("accent_h"),
            text_color="#ffffff", font=ctk.CTkFont(size=10),
            command=_save,
        ).pack(side="right", padx=(6, 16), pady=10)

        ctk.CTkButton(
            btn_f, text=lm.t("cancel"),
            width=80, height=30, corner_radius=6,
            fg_color=tm.c("bg3"), hover_color=tm.c("hover"),
            text_color=tm.c("text2"), font=ctk.CTkFont(size=10),
            command=dlg.destroy,
        ).pack(side="right", padx=(0, 4), pady=10)
