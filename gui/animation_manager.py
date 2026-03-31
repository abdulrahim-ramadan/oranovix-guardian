"""
AnimationManager — Static utility class for all UI animations.
Every animation schedules work via widget.after() to stay off the UI thread.

P2 additions:
  particle_bg   — 30 red dots with connecting lines on a canvas
  radar_pulse   — rotating radar sweep line
  shake         — horizontal shake for toast window
  reveal_cards  — now slides in from right
"""
from __future__ import annotations

import math
import random
import threading
from typing import Callable, List, Optional


class AnimationManager:
    """
    Pure-static animation toolkit.  Never instantiate directly.
    All methods accept a *root* widget for scheduling `after()` calls.
    """

    # ── Typewriter ────────────────────────────────────────────────────────

    @staticmethod
    def type_text(
        root,
        text: str,
        set_fn: Callable[[str], None],
        char_delay: int = 55,
        on_done: Optional[Callable] = None,
    ) -> None:
        """
        Reveal *text* one character at a time via *set_fn* (e.g. label.configure).
        Calls *on_done* when the full string has been typed.
        """
        def _step(idx: int) -> None:
            set_fn(text[:idx])
            if idx < len(text):
                root.after(char_delay, _step, idx + 1)
            elif on_done:
                on_done()
        root.after(0, _step, 0)

    # ── Counting number ───────────────────────────────────────────────────

    @staticmethod
    def count_up(
        root,
        set_fn: Callable[[str], None],
        target: int,
        duration_ms: int = 900,
        suffix: str = "",
        on_done: Optional[Callable] = None,
    ) -> None:
        """
        Animate a numeric counter from 0 → *target*.
        *set_fn* receives the string to display (e.g. "42%").
        """
        steps  = max(1, min(target, 60))
        delay  = max(1, duration_ms // steps)
        step_v = target / steps

        def _step(current_step: int) -> None:
            val = int(current_step * step_v)
            set_fn(f"{val}{suffix}")
            if current_step < steps:
                root.after(delay, _step, current_step + 1)
            else:
                set_fn(f"{target}{suffix}")
                if on_done:
                    on_done()
        root.after(0, _step, 0)

    # ── Canvas arc (score circle) ─────────────────────────────────────────

    @staticmethod
    def animate_arc(
        root,
        canvas,
        arc_id: int,
        target_score: int,        # 0-100
        duration_ms: int = 900,
    ) -> None:
        """
        Animate a canvas arc from extent=0 to extent corresponding to score/100.
        Arc drawn from 12 o'clock (start=90) going clockwise (negative extent).
        """
        target_extent = -(target_score / 100) * 359.9   # never full 360 (closed arc)
        steps  = 60
        delay  = max(1, duration_ms // steps)

        def _step(i: int) -> None:
            extent = target_extent * (i / steps)
            canvas.itemconfig(arc_id, extent=extent)
            if i < steps:
                root.after(delay, _step, i + 1)
        root.after(0, _step, 1)

    # ── Pulse button (while scanning) ────────────────────────────────────

    @staticmethod
    def pulse_button(
        root,
        button,
        color_a: str,
        color_b: str,
        interval_ms: int = 550,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        """
        Oscillate button fg_color between color_a and color_b.
        Stops when *stop_event* is set.
        """
        _state = {"on_a": True}

        def _toggle() -> None:
            if stop_event and stop_event.is_set():
                try:
                    button.configure(fg_color=color_a)
                except Exception:
                    pass
                return
            try:
                btn_color = color_a if _state["on_a"] else color_b
                button.configure(fg_color=btn_color)
                _state["on_a"] = not _state["on_a"]
                root.after(interval_ms, _toggle)
            except Exception:
                pass

        root.after(0, _toggle)

    # ── Progress bar smooth fill ──────────────────────────────────────────

    @staticmethod
    def animate_progress(
        root,
        bar,
        target: float,            # 0.0 – 1.0
        duration_ms: int = 400,
        on_done: Optional[Callable] = None,
    ) -> None:
        """Smoothly advance a CTkProgressBar from its current value to *target*."""
        steps = 30
        delay = max(1, duration_ms // steps)
        try:
            current = bar.get() if hasattr(bar, 'get') else 0.0
        except Exception:
            current = 0.0
        delta = (target - current) / steps

        def _step(i: int, val: float) -> None:
            new_val = min(target, val + delta) if delta > 0 else max(target, val + delta)
            try:
                bar.set(new_val)
            except Exception:
                return
            if i < steps:
                root.after(delay, _step, i + 1, new_val)
            elif on_done:
                on_done()
        root.after(0, _step, 0, current)

    # ── Hover color transition ─────────────────────────────────────────────

    @staticmethod
    def hover_transition(
        root,
        widget,
        from_color: str,
        to_color: str,
        steps: int = 6,
        delay: int = 18,
    ) -> None:
        """Smoothly blend fg_color of *widget* from *from_color* to *to_color*."""
        from gui.theme_manager import ThemeManager

        def _step(i: int) -> None:
            t = i / steps
            color = ThemeManager.blend(from_color, to_color, t)
            try:
                widget.configure(fg_color=color)
            except Exception:
                return
            if i < steps:
                root.after(delay, _step, i + 1)
        root.after(0, _step, 1)

    # ── Cards sequential reveal (slide from right) ───────────────────────

    @staticmethod
    def reveal_cards(
        root,
        cards: list,
        delay_between: int = 80,
        fade_steps: int = 8,
    ) -> None:
        """
        Make each card in *cards* appear sequentially with a slide-from-right feel.
        Cards must be initially hidden (pack_forget already called).
        """
        def _show(idx: int) -> None:
            if idx >= len(cards):
                return
            widget = cards[idx]
            try:
                widget.pack(fill="x", padx=0, pady=4)
            except Exception:
                try:
                    widget.grid()
                except Exception:
                    pass
            root.after(delay_between, _show, idx + 1)
        root.after(0, _show, 0)

    # ── Toast notification with shake ─────────────────────────────────────

    @staticmethod
    def show_toast(
        root,
        message: str,
        color:      str = "#007acc",
        duration_ms: int = 3000,
    ) -> None:
        """
        Slide a toast notification in from the top-right corner,
        shake it briefly to draw attention, hold, then slide out.
        """
        import customtkinter as ctk
        from gui.theme_manager import ThemeManager
        tm = ThemeManager()

        toast = ctk.CTkToplevel(root)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        toast.configure(fg_color=color)

        ctk.CTkLabel(
            toast,
            text=f"  {message}  ",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#ffffff",
            fg_color="transparent",
        ).pack(padx=12, pady=10)

        toast.update_idletasks()
        w, h = toast.winfo_reqwidth(), toast.winfo_reqheight()
        sw   = root.winfo_screenwidth()

        x_show = sw - w - 20
        y_show = 60
        y_hide = -h - 10

        def _shake_toast() -> None:
            """Horizontal shake after slide-in."""
            offsets = [6, -6, 4, -4, 2, -2, 0]
            def _s(i: int) -> None:
                if i >= len(offsets):
                    return
                try:
                    toast.geometry(f"{w}x{h}+{x_show + offsets[i]}+{y_show}")
                except Exception:
                    return
                root.after(40, _s, i + 1)
            root.after(0, _s, 0)

        def _move(target_y: int, step: int, total: int, next_fn) -> None:
            progress = step / total
            dy = int(y_hide + (target_y - y_hide) * progress)
            try:
                toast.geometry(f"{w}x{h}+{x_show}+{dy}")
            except Exception:
                return
            if step < total:
                root.after(16, _move, target_y, step + 1, total, next_fn)
            else:
                next_fn()

        def _slide_in() -> None:
            _move(y_show, 0, 15, lambda: (
                _shake_toast(),
                root.after(duration_ms, _slide_out),
            ))

        def _slide_out() -> None:
            try:
                _move(y_hide, 0, 15, lambda: toast.destroy())
            except Exception:
                try:
                    toast.destroy()
                except Exception:
                    pass

        toast.geometry(f"{w}x{h}+{x_show}+{y_hide}")
        toast.after(10, _slide_in)

    # ── Loading bar (splash) ──────────────────────────────────────────────

    @staticmethod
    def run_splash_progress(
        root,
        bar,
        duration_ms: int = 2200,
        on_done: Optional[Callable] = None,
    ) -> None:
        """Fill *bar* from 0→1 over *duration_ms*, then call *on_done*."""
        steps = 50
        delay = max(1, duration_ms // steps)
        val   = [0.0]

        def _step() -> None:
            val[0] = min(1.0, val[0] + 1 / steps)
            try:
                bar.set(val[0])
            except Exception:
                return
            if val[0] < 1.0:
                root.after(delay, _step)
            elif on_done:
                root.after(200, on_done)

        root.after(delay, _step)

    # ── Dashed-border animation (drop zone) ───────────────────────────────

    @staticmethod
    def animate_dash(root, canvas, item_id: int, interval: int = 60) -> threading.Event:
        """
        Advance the dash offset on a canvas item every *interval* ms,
        creating a 'marching ants' animated border.
        Returns a stop Event; set it to stop the animation.
        """
        stop = threading.Event()
        _offset = [0]

        def _tick() -> None:
            if stop.is_set():
                return
            _offset[0] = (_offset[0] + 1) % 16
            try:
                canvas.itemconfig(item_id, dashoffset=_offset[0])
            except Exception:
                return
            root.after(interval, _tick)

        root.after(0, _tick)
        return stop

    # ── Color fade-in (splash logo glow) ─────────────────────────────────

    @staticmethod
    def fade_color(
        root,
        canvas,
        item_id: int,
        from_color: str,
        to_color: str,
        duration_ms: int = 800,
    ) -> None:
        """
        Interpolate a canvas item's fill from *from_color* → *to_color*.
        """
        from gui.theme_manager import ThemeManager
        steps = 40
        delay = max(1, duration_ms // steps)

        def _step(i: int) -> None:
            color = ThemeManager.blend(from_color, to_color, i / steps)
            try:
                canvas.itemconfig(item_id, fill=color)
            except Exception:
                return
            if i < steps:
                root.after(delay, _step, i + 1)
        root.after(0, _step, 1)

    # ── P2: Particle background ───────────────────────────────────────────

    @staticmethod
    def particle_bg(
        root,
        canvas,
        dot_count: int = 30,
        stop_event: Optional[threading.Event] = None,
    ) -> threading.Event:
        """
        Animate *dot_count* red particles on *canvas* with connecting lines.
        Returns a stop Event; set it to halt animation.
        """
        if stop_event is None:
            stop_event = threading.Event()

        particles: list = []
        line_ids:  list = []

        def _init() -> None:
            try:
                cw = canvas.winfo_width() or 800
                ch = canvas.winfo_height() or 150
            except Exception:
                return
            for _ in range(dot_count):
                pid = canvas.create_oval(0, 0, 4, 4, fill="#cc0000", outline="")
                particles.append({
                    "x":  random.uniform(0, cw),
                    "y":  random.uniform(0, ch),
                    "vx": random.uniform(-0.7, 0.7),
                    "vy": random.uniform(-0.5, 0.5),
                    "id": pid,
                })
            _tick()

        def _tick() -> None:
            nonlocal line_ids
            if stop_event.is_set():
                return
            try:
                cw = canvas.winfo_width() or 800
                ch = canvas.winfo_height() or 150
            except Exception:
                return

            # Remove old connecting lines
            for lid in line_ids:
                try:
                    canvas.delete(lid)
                except Exception:
                    pass
            line_ids = []

            # Move every particle (wrap at edges)
            for p in particles:
                p["x"] = (p["x"] + p["vx"]) % cw
                p["y"] = (p["y"] + p["vy"]) % ch
                try:
                    x, y = p["x"], p["y"]
                    canvas.coords(p["id"], x - 2, y - 2, x + 2, y + 2)
                except Exception:
                    pass

            # Draw lines between close particles
            for i, a in enumerate(particles):
                for b in particles[i + 1:]:
                    dist = math.hypot(a["x"] - b["x"], a["y"] - b["y"])
                    if dist < 75:
                        r = int((1 - dist / 75) * 160)
                        color = f"#{r:02x}0000"
                        try:
                            lid = canvas.create_line(
                                a["x"], a["y"], b["x"], b["y"],
                                fill=color, width=1,
                            )
                            line_ids.append(lid)
                        except Exception:
                            pass

            try:
                root.after(50, _tick)
            except Exception:
                pass

        root.after(80, _init)
        return stop_event

    # ── P2: Radar sweep ───────────────────────────────────────────────────

    @staticmethod
    def radar_pulse(
        root,
        canvas,
        cx: int,
        cy: int,
        radius: int,
        stop_event: Optional[threading.Event] = None,
    ) -> threading.Event:
        """
        Draw a rotating radar sweep line on *canvas*.
        Returns a stop Event; set it to remove the animation.
        """
        if stop_event is None:
            stop_event = threading.Event()

        angle = [0.0]
        try:
            circle_id = canvas.create_oval(
                cx - radius, cy - radius, cx + radius, cy + radius,
                outline="#cc0000", width=1, dash=(4, 4),
            )
            line_id = canvas.create_line(cx, cy, cx + radius, cy,
                                          fill="#cc0000", width=2)
            # Faint fill to create sweep trail
            arc_id = canvas.create_arc(
                cx - radius, cy - radius, cx + radius, cy + radius,
                start=0, extent=30,
                fill="#1a0000", outline="", style="pie",
            )
        except Exception:
            return stop_event

        def _tick() -> None:
            if stop_event.is_set():
                for oid in (circle_id, line_id, arc_id):
                    try:
                        canvas.delete(oid)
                    except Exception:
                        pass
                return
            angle[0] = (angle[0] + 5) % 360
            rad = math.radians(angle[0])
            ex  = cx + radius * math.cos(rad)
            ey  = cy - radius * math.sin(rad)
            try:
                canvas.coords(line_id, cx, cy, ex, ey)
                canvas.itemconfig(arc_id, start=angle[0] - 30, extent=30)
            except Exception:
                return
            try:
                root.after(30, _tick)
            except Exception:
                pass

        root.after(0, _tick)
        return stop_event

    # ── P2: Shake window ──────────────────────────────────────────────────

    @staticmethod
    def shake_window(
        root,
        window,
        intensity: int = 5,
        cycles: int = 3,
    ) -> None:
        """Shake a Toplevel window horizontally (for error alerts)."""
        try:
            wx = window.winfo_x()
            wy = window.winfo_y()
            ww = window.winfo_width()
            wh = window.winfo_height()
        except Exception:
            return

        offsets = []
        for _ in range(cycles):
            offsets += [intensity, -intensity, intensity // 2, -(intensity // 2)]
        offsets.append(0)

        def _step(idx: int) -> None:
            if idx >= len(offsets):
                return
            try:
                window.geometry(f"{ww}x{wh}+{wx + offsets[idx]}+{wy}")
            except Exception:
                return
            root.after(35, _step, idx + 1)

        root.after(0, _step, 0)
