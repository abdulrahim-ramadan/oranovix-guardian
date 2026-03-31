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

import customtkinter as ctk

from gui.theme_manager     import ThemeManager
from core.language_manager import LanguageManager
from core.sound_manager    import SoundManager


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

        # ── About ─────────────────────────────────────────────────────
        about_sec = _Section(scroll, "ℹ️  About")
        about_sec.pack(fill="x", pady=(0, 20))

        # Each tuple: (text, font_size, weight, theme_color_key)
        for line in [
            ("Oranovix Guardian", 14, "bold", "text"),
            ("Professional Security Scanner  •  v1.0.0", 11, "normal", "text2"),
            ("100% free — powered by Bandit, Gemini & ReportLab", 10, "normal", "text3"),
        ]:
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
        """Re-apply the background colour after a theme change.

        Called by the app when a lightweight theme refresh is needed
        without a full UI rebuild.
        """
        tm = ThemeManager()
        self.configure(fg_color=tm.c("bg"))
