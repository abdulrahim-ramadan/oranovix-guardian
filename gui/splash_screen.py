"""
SplashScreen — 3-second animated startup.
Bug 4 fix: loads assets/icon.png as the logo (120x120) with glow ring.
Falls back to canvas shield if PIL/image not available.
"""
from __future__ import annotations

import os
import sys
import tkinter as tk
from typing import Callable

import customtkinter as ctk

from gui.animation_manager import AnimationManager
from gui.asset_helper      import get_asset_path


class SplashScreen(ctk.CTkToplevel):
    """Full-screen dark splash shown while the main window initialises."""

    W, H       = 620, 360
    BG         = "#050505"
    ACCENT     = "#cc0000"
    ACCENT_H   = "#ff0000"
    GLOW_START = "#1a0000"
    TEXT_DIM   = "#555555"
    TEXT_FULL  = "#ffffff"

    def __init__(self, parent, on_done: Callable[[], None]) -> None:
        super().__init__(parent)
        self._on_done = on_done

        self.overrideredirect(True)
        self.configure(fg_color=self.BG)
        self.attributes("-topmost", True)

        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{self.W}x{self.H}+{(sw-self.W)//2}+{(sh-self.H)//2}")

        self._build()
        self._start_sequence()

    # ------------------------------------------------------------------
    # UI build
    # ------------------------------------------------------------------

    def _build(self) -> None:
        self._logo_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._logo_frame.pack(pady=(30, 0))

        icon_path = get_asset_path("icon.png")
        loaded    = False

        if os.path.exists(icon_path):
            try:
                from PIL import Image
                pil_img = Image.open(icon_path)
                pil_img.thumbnail((150, 150), Image.Resampling.LANCZOS)
                self.logo_image = ctk.CTkImage(
                    light_image=pil_img,
                    dark_image=pil_img,
                    size=(pil_img.width, pil_img.height),
                )
                self._logo_lbl = ctk.CTkLabel(
                    self._logo_frame, image=self.logo_image, text="",
                    fg_color="transparent",
                )
                self._logo_lbl.pack()
                loaded = True
            except Exception:
                pass

        if not loaded:
            # Fallback: canvas shield
            self._canvas = tk.Canvas(
                self._logo_frame, width=140, height=140,
                bg=self.BG, highlightthickness=0,
            )
            self._canvas.pack()
            self._glow_id = self._canvas.create_oval(
                8, 8, 132, 132, outline=self.GLOW_START, width=3,
            )
            pts = [70, 12, 128, 35, 128, 90, 70, 132, 12, 90, 12, 35]
            self._shield_id = self._canvas.create_polygon(
                pts, fill=self.GLOW_START, outline=""
            )
            self._cg_id = self._canvas.create_text(
                70, 74, text="OG",
                font=("Segoe UI", 28, "bold"), fill=self.BG,
            )
            self._use_canvas = True
        else:
            self._use_canvas = False

        # Glow ring around the logo image (canvas overlay)
        if loaded:
            self._ring_canvas = tk.Canvas(
                self._logo_frame, width=140, height=140,
                bg=self.BG, highlightthickness=0,
            )
            # DON'T pack ring over image — place it as decoration below logo
            self._glow_oval = None   # animated separately

        # Typing label
        self._title_var = tk.StringVar(value="")
        ctk.CTkLabel(
            self, textvariable=self._title_var,
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=self.TEXT_FULL, fg_color="transparent",
        ).pack(pady=(10, 2))

        # Subtitle
        self._sub_var = tk.StringVar(value="")
        ctk.CTkLabel(
            self, textvariable=self._sub_var,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=self.TEXT_DIM, fg_color="transparent",
        ).pack(pady=(0, 16))

        # Progress bar
        self._bar = ctk.CTkProgressBar(
            self, width=380, height=4,
            progress_color=self.ACCENT,
            fg_color="#1a0000", corner_radius=2,
        )
        self._bar.set(0)
        self._bar.pack(pady=(0, 14))

        # Version
        ctk.CTkLabel(
            self, text="v1.0.0  •  Professional Edition",
            font=ctk.CTkFont(size=9),
            text_color="#333333", fg_color="transparent",
        ).pack()

    # ------------------------------------------------------------------
    # Animation sequence
    # ------------------------------------------------------------------

    def _start_sequence(self) -> None:
        if getattr(self, "_use_canvas", False):
            # Animate canvas shield colours
            AnimationManager.fade_color(
                self, self._canvas, self._shield_id,
                self.GLOW_START, self.ACCENT, duration_ms=700,
            )
            AnimationManager.fade_color(
                self, self._canvas, self._glow_id,
                self.GLOW_START, self.ACCENT_H, duration_ms=700,
            )
            AnimationManager.fade_color(
                self, self._canvas, self._cg_id,
                self.BG, "#ffffff", duration_ms=700,
            )

        # Type title text
        self.after(
            400,
            lambda: AnimationManager.type_text(
                self, "Oranovix Guardian",
                lambda t: self._title_var.set(t),
                char_delay=55,
                on_done=self._on_typing_done,
            ),
        )

        # Progress bar
        self.after(
            500,
            lambda: AnimationManager.run_splash_progress(
                self, self._bar,
                duration_ms=2000,
                on_done=self._finish,
            ),
        )

    def _on_typing_done(self) -> None:
        AnimationManager.type_text(
            self, "Professional Security Scanner",
            lambda t: self._sub_var.set(t),
            char_delay=28,
        )

    def _finish(self) -> None:
        self.after(300, self._close)

    def _close(self) -> None:
        try:
            self.destroy()
        except Exception:
            pass
        self._on_done()
