"""The main window uses the native frame, and the app icon is square and sharp.

Bug 1: a borderless main window (``overrideredirect``) had no taskbar
button and minimized to a title box in the corner of the desktop.
Bug 2: the 1536x1024 logo was resized to a square, so every icon was
squashed, and the small sizes were noise.
"""
from __future__ import annotations

import io
import re
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple, cast

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "assets"


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _ico_entries(path: Path) -> List[Tuple[int, int, bytes]]:
    data = path.read_bytes()
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    assert (reserved, kind) == (0, 1)
    entries = []
    for i in range(count):
        w, h, _colors, _res, _planes, bpp, size, offset = struct.unpack_from("<BBBBHHII", data, 6 + i * 16)
        assert bpp == 32
        entries.append((w or 256, h or 256, data[offset:offset + size]))
    return entries


def _rgba(img: Image.Image, xy: Tuple[int, int]) -> Tuple[int, int, int, int]:
    return cast(Tuple[int, int, int, int], img.getpixel(xy))


def _ico_images() -> Dict[int, Image.Image]:
    images = {}
    for w, h, blob in _ico_entries(ASSETS / "icon.ico"):
        assert blob[:8] == b"\x89PNG\r\n\x1a\n", "every entry is a PNG"
        img = Image.open(io.BytesIO(blob))
        img.load()
        assert img.size == (w, h)
        images[w] = img.convert("RGBA")
    return images


# ----------------------------------------------------------------------
# Bug 1: native frame
# ----------------------------------------------------------------------

def test_no_borderless_main_window_in_the_source() -> None:
    for name in ("gui/app.py", "gui/title_bar.py"):
        source = (ROOT / "src" / "oranovix_guardian" / name).read_text(encoding="utf-8")
        assert not re.search(r"overrideredirect\(\s*True\s*\)", source), name
        assert "_restore_taskbar_entry" not in source, name
        assert "SW_MINIMIZE" not in source, name


class _FakeInstance:
    def __init__(self) -> None:
        self.released = 0

    def release(self) -> None:
        self.released += 1


class _FakeController:
    def __init__(self) -> None:
        self.shut_down = 0

    def shutdown(self, timeout=None) -> None:
        self.shut_down += 1


@pytest.fixture(scope="module")
def app() -> Any:
    """One main window for the module.

    Creating Tk interpreters again and again in one process sometimes
    fails to load Tk's own scripts (Microsoft Store Python), so the GUI
    tests share this window; the close test runs last and closes it.
    """
    import oranovix_guardian.gui.app as app_module

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(app_module.CodeGuardianApp, "_show_main", lambda self: None)
        instance = _FakeInstance()
        try:
            window = app_module.CodeGuardianApp(instance=instance)
        except Exception as exc:  # no display
            pytest.skip(f"no display: {exc}")
        setattr(window, "_test_instance", instance)
        yield window
        try:
            window.destroy()
        except Exception:
            pass


def test_the_main_window_has_the_native_frame(app: Any) -> None:
    assert not app.overrideredirect()


def test_the_title_bar_has_no_window_buttons(app: Any) -> None:
    import customtkinter as ctk
    from oranovix_guardian.gui.title_bar import CustomTitleBar

    bar = None
    try:
        bar = CustomTitleBar(app, window=app, on_theme_toggle=lambda: None, on_lang_change=lambda _: None)
        texts = []
        stack = list(bar.winfo_children())
        while stack:
            widget = stack.pop()
            stack.extend(widget.winfo_children())
            if isinstance(widget, ctk.CTkButton):
                texts.append(widget.cget("text"))
        for symbol in ("─", "□", "❐", "✕"):
            assert symbol not in texts
        for name in ("_minimize", "_maximize", "_close", "_on_drag"):
            assert not hasattr(bar, name)
    finally:
        if bar is not None:
            bar.destroy()


def test_window_close_runs_the_clean_shutdown(app: Any) -> None:
    command = app.tk.call("wm", "protocol", app._w, "WM_DELETE_WINDOW")
    assert str(command).endswith("_on_close")

    live, hub, sentinel = _FakeController(), _FakeController(), _FakeController()
    app._live_defense, app._threat_hub, app._log_sentinel = live, hub, sentinel
    instance = app._test_instance
    app.after(0, app._on_close)
    app.mainloop()
    assert (live.shut_down, hub.shut_down, sentinel.shut_down) == (1, 1, 1)
    assert instance.released == 1


def test_dwm_helper_is_a_no_op_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.gui import window_frame

    calls: list = []
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(window_frame, "_dwm_set", lambda *a: calls.append(a) or 0)
    window_frame.apply_frame_theme(object(), dark=True, caption="#111111", text="#ffffff")
    assert calls == []


def test_dwm_helper_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.gui import window_frame

    class Broken:
        def wm_frame(self) -> str:
            raise RuntimeError("no window")

    monkeypatch.setattr(sys, "platform", "win32")
    window_frame.apply_frame_theme(Broken(), dark=False, caption="#ffffff", text="#000000")
    window_frame.apply_frame_theme(None, dark=True, caption="bad", text="bad")

    def explode(*args: Any) -> int:
        raise OSError("dwmapi missing")

    class Window:
        def wm_frame(self) -> str:
            return "0x1234"

    monkeypatch.setattr(window_frame, "_dwm_set", explode)
    window_frame.apply_frame_theme(Window(), dark=True, caption="#111111", text="#ffffff")


def test_dwm_helper_sets_dark_mode_and_windows_11_colors(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.gui import window_frame

    class Window:
        def wm_frame(self) -> str:
            return "0x1a2b"

    calls: list = []
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(window_frame, "_windows_build", lambda: 22631)
    monkeypatch.setattr(window_frame, "_dwm_set", lambda hwnd, attr, value: calls.append((hwnd, attr, value)) or 0)
    window_frame.apply_frame_theme(Window(), dark=True, caption="#112233", text="#ffffff")
    assert (0x1A2B, 20, 1) in calls
    assert (0x1A2B, 35, 0x332211) in calls          # COLORREF is 0x00BBGGRR
    assert (0x1A2B, 36, 0xFFFFFF) in calls

    calls.clear()
    monkeypatch.setattr(window_frame, "_windows_build", lambda: 19045)   # Windows 10
    window_frame.apply_frame_theme(Window(), dark=False, caption="#f0f0f0", text="#1e1e1e")
    assert calls == [(0x1A2B, 20, 0)]


def test_dwm_helper_falls_back_to_attribute_19(monkeypatch: pytest.MonkeyPatch) -> None:
    from oranovix_guardian.gui import window_frame

    class Window:
        def wm_frame(self) -> str:
            return "0x10"

    calls: list = []

    def fake(hwnd: int, attr: int, value: int) -> int:
        calls.append(attr)
        return 0 if attr == 19 else -2147024809   # E_INVALIDARG for 20 on old builds

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(window_frame, "_windows_build", lambda: 17763)
    monkeypatch.setattr(window_frame, "_dwm_set", fake)
    window_frame.apply_frame_theme(Window(), dark=True, caption="#000000", text="#ffffff")
    assert calls == [20, 19]


def test_main_sets_the_app_user_model_id_first() -> None:
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    assert 'SetCurrentProcessExplicitAppUserModelID("Oranovix.Guardian")' in source
    assert source.index("SetCurrentProcessExplicitAppUserModelID") < source.index("from oranovix_guardian.gui.app import")


# ----------------------------------------------------------------------
# Bug 2: icon
# ----------------------------------------------------------------------

def test_ico_has_exactly_the_eight_square_sizes() -> None:
    entries = _ico_entries(ASSETS / "icon.ico")
    assert sorted(w for w, _, _ in entries) == [16, 20, 24, 32, 48, 64, 128, 256]
    assert all(w == h for w, h, _ in entries)
    for size, img in _ico_images().items():
        assert img.size == (size, size)


def test_the_256_entry_is_not_squashed() -> None:
    img = _ico_images()[256]
    alpha = img.getchannel("A").point([255 if a > 16 else 0 for a in range(256)])
    bbox = alpha.getbbox()
    assert bbox is not None
    left, top, right, bottom = bbox
    ratio = (right - left) / (bottom - top)
    assert 0.95 <= ratio <= 1.05, ratio


def test_the_256_entry_has_transparent_corners() -> None:
    img = _ico_images()[256]
    for xy in ((0, 0), (255, 0), (0, 255), (255, 255)):
        assert _rgba(img, xy)[3] == 0, xy


def test_the_32_entry_keeps_the_green_code_sign() -> None:
    img = _ico_images()[32]
    green = 0
    for x in range(6, 26):
        for y in range(6, 26):
            r, g, _b, a = _rgba(img, (x, y))
            if a > 128 and g > 150 and r < 120:
                green += 1
    assert green >= 3, green


def test_square_asset_is_committed_and_square() -> None:
    img = Image.open(ASSETS / "icon_square.png")
    assert img.width == img.height
    assert img.mode == "RGBA"
    assert _rgba(img, (0, 0))[3] == 0


@pytest.mark.parametrize("size", [16, 20, 26, 150])
def test_logo_loader_keeps_the_source_aspect_ratio(size: int) -> None:
    from oranovix_guardian.gui.asset_helper import load_logo

    img = load_logo(size)
    assert img is not None
    source = Image.open(ASSETS / ("icon_shield.png" if size <= 20 else "icon_square.png"))
    assert max(img.size) == size
    assert abs(img.width / img.height - source.width / source.height) < 0.02


@pytest.mark.parametrize("name", ["gui/title_bar.py", "gui/pages/scanner_page.py", "gui/splash_screen.py"])
def test_ui_never_squares_the_rectangular_logo(name: str) -> None:
    source = (ROOT / "src" / "oranovix_guardian" / name).read_text(encoding="utf-8")
    assert '"icon.png"' not in source
    assert "load_logo" in source
