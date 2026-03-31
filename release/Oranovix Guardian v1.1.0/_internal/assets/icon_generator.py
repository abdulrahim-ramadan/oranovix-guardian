"""
Icon generator for Oranovix Guardian.
- If assets/icon.png exists, converts it to icon.ico (multi-size).
- Otherwise generates a red/black shield icon programmatically.
Run: python assets/icon_generator.py
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from PIL import Image, ImageDraw, ImageFont

ASSETS_DIR = Path(__file__).parent


def convert_png_to_ico() -> bool:
    """
    Convert assets/icon.png -> assets/icon.ico with all standard sizes.
    Writes the ICO manually via struct to work around Pillow's broken
    append_images ICO support.
    """
    import io, struct
    png_path = ASSETS_DIR / "icon.png"
    ico_path = ASSETS_DIR / "icon.ico"
    if not png_path.exists():
        return False
    try:
        base   = Image.open(str(png_path)).convert("RGBA")
        sizes  = [16, 32, 48, 64, 128, 256]

        # Render each size to in-memory PNG bytes
        blobs: list[bytes] = []
        for s in sizes:
            buf = io.BytesIO()
            base.resize((s, s), Image.LANCZOS).save(buf, format="PNG")
            blobs.append(buf.getvalue())

        # Build ICO: header + directory + image data
        count  = len(sizes)
        out    = io.BytesIO()
        out.write(struct.pack("<HHH", 0, 1, count))   # ICO header
        offset = 6 + count * 16
        for s, blob in zip(sizes, blobs):
            w = 0 if s == 256 else s   # 0 == 256 per ICO spec
            h = 0 if s == 256 else s
            out.write(struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(blob), offset))
            offset += len(blob)
        for blob in blobs:
            out.write(blob)

        ico_path.write_bytes(out.getvalue())
        print(f"Converted {png_path.name} -> {ico_path.name} "
              f"({ico_path.stat().st_size:,} bytes, {count} sizes)")
        return True
    except Exception as exc:
        print(f"PNG->ICO conversion failed: {exc}")
        return False


def _draw_shield(size: int = 256) -> Image.Image:
    """Red/black shield with 'OG' text."""
    ACCENT = (204, 0, 0, 255)
    DARK   = (20, 0, 0, 255)
    WHITE  = (255, 255, 255, 255)

    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    m  = size * 0.08
    cx = size / 2

    # Outer shield
    pts = [
        (m,         m * 1.5),
        (size - m,  m * 1.5),
        (size - m,  size * 0.60),
        (cx,        size - m),
        (m,         size * 0.60),
    ]
    draw.polygon(pts, fill=ACCENT)

    # Inner shield (darker inset for depth)
    pad = size * 0.10
    inner = [
        (m + pad,       m * 1.5 + pad),
        (size - m - pad, m * 1.5 + pad),
        (size - m - pad, size * 0.58),
        (cx,             size - m - pad),
        (m + pad,        size * 0.58),
    ]
    draw.polygon(inner, fill=DARK)

    # "OG" text
    font_size = int(size * 0.30)
    font = None
    for name in ("C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/arial.ttf"):
        if os.path.exists(name):
            try:
                font = ImageFont.truetype(name, font_size)
                break
            except Exception:
                pass
    if font is None:
        font = ImageFont.load_default()

    label = "OG"
    bbox  = draw.textbbox((0, 0), label, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = cx - tw / 2
    ty = size * 0.35 - th / 2

    draw.text((tx + 2, ty + 2), label, font=font, fill=(0, 0, 0, 140))
    draw.text((tx,     ty),     label, font=font, fill=WHITE)
    return img


def create_icon_image(size: int = 256) -> Image.Image:
    """Return a PIL Image of the app icon at the given size."""
    return _draw_shield(size=size)


def create_app_icon(output_dir: str | None = None) -> str:
    """
    Generate Oranovix Guardian icon.ico with multiple sizes.
    Returns the absolute path to the written file.
    """
    if output_dir is None:
        output_dir = str(ASSETS_DIR)

    os.makedirs(output_dir, exist_ok=True)
    ico_path = os.path.join(output_dir, "icon.ico")

    sizes  = [256, 128, 64, 48, 32, 16]
    images = [_draw_shield(s) for s in sizes]
    images[0].save(
        ico_path,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[1:],
    )
    return ico_path


if __name__ == "__main__":
    print("Oranovix Guardian — Icon setup")
    if not convert_png_to_ico():
        print("assets/icon.png not found — generating shield icon...")
        path = create_app_icon()
        print(f"Generated: {path}")
    print("Done.")
