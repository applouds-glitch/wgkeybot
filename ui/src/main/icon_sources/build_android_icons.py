#!/usr/bin/env python3
"""Package the v1.6.0 mascot refresh as Android launcher resources.

Requires Pillow. Run this file from any working directory; the generated source
is never modified. Android layers are 108dp with the mark inside the central
66dp safe circle. Legacy exports use the same 72dp viewport as adaptive icons.
"""
from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw, ImageChops

SOURCE_DIR = Path(__file__).resolve().parent
MAIN = SOURCE_DIR.parent
RES = MAIN / "res"
BACKGROUND = "#142D4E"
DENSITIES = {"mdpi": 1, "hdpi": 1.5, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}


def centered_layer(source: Image.Image, size: int) -> Image.Image:
    subject = source.crop(source.getchannel("A").getbbox())
    # A 58dp bounding box keeps the antennas/key/hand within the safe circle.
    subject.thumbnail((round(size * 58 / 108), round(size * 58 / 108)), Image.Resampling.LANCZOS)
    layer = Image.new("RGBA", (size, size))
    layer.alpha_composite(subject, ((size - subject.width) // 2, (size - subject.height) // 2))
    return layer


def build_monochrome(source: Image.Image) -> Image.Image:
    # Dark outlines and face become negative space; bright shell, eyes and key
    # form the themed glyph. Android supplies its final wallpaper-based color.
    red, green, blue, alpha = source.split()
    brightness = ImageChops.lighter(red, ImageChops.lighter(green, blue))
    mask = brightness.point(lambda value: max(0, min(255, (value - 115) * 255 // 65)))
    result = Image.new("RGBA", source.size, "white")
    result.putalpha(ImageChops.multiply(mask, alpha))
    return result


def viewport(layer: Image.Image, background: str = BACKGROUND) -> Image.Image:
    result = Image.new("RGBA", layer.size, background)
    result.alpha_composite(layer)
    inset = layer.width // 6
    return result.crop((inset, inset, layer.width - inset, layer.height - inset))


def masked(image: Image.Image, kind: str) -> Image.Image:
    mask = Image.new("L", image.size)
    draw = ImageDraw.Draw(mask)
    bounds = (0, 0, image.width - 1, image.height - 1)
    if kind == "round":
        draw.ellipse(bounds, fill=255)
    else:
        draw.rounded_rectangle(bounds, radius=round(image.width * .23), fill=255)
    result = image.copy()
    result.putalpha(mask)
    return result


def save(image: Image.Image, path: Path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image.resize((size, size), Image.Resampling.LANCZOS).save(path, "WEBP", lossless=True, method=6)


def build() -> None:
    source = Image.open(SOURCE_DIR / "wgkeybot_v160_refresh.png").convert("RGBA")
    foreground = centered_layer(source, 1296)
    monochrome = centered_layer(build_monochrome(source), 1296)
    full = viewport(foreground)
    for density, scale in DENSITIES.items():
        folder = RES / f"mipmap-{density}"
        for name, layer in (("foreground", foreground), ("monochrome", monochrome)):
            save(layer, folder / f"ic_launcher_{name}.webp", round(108 * scale))
        save(Image.new("RGB", foreground.size, BACKGROUND), folder / "ic_launcher_background.webp", round(108 * scale))
        save(masked(full, "square"), folder / "ic_launcher.webp", round(48 * scale))
        save(masked(full, "round"), folder / "ic_launcher_round.webp", round(48 * scale))
    full.convert("RGB").resize((512, 512), Image.Resampling.LANCZOS).save(MAIN / "ic_launcher-playstore.png", optimize=True)


if __name__ == "__main__":
    build()
