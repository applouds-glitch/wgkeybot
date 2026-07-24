#!/usr/bin/env python3
"""Build dark cyber-security Android launcher assets for WGKeyBot."""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[4]
RES = ROOT / "ui" / "src" / "main" / "res"
SOURCE_DIR = Path(__file__).resolve().parent

DENSITIES = {
    "mdpi": 1.0,
    "hdpi": 1.5,
    "xhdpi": 2.0,
    "xxhdpi": 3.0,
    "xxxhdpi": 4.0,
}


def crop_alpha(image: Image.Image) -> Image.Image:
    rgba = image.convert("RGBA")
    bbox = rgba.getchannel("A").getbbox()
    if bbox is None:
        raise ValueError("Source image has no visible pixels")
    return rgba.crop(bbox)


def dark_background(size: int) -> Image.Image:
    """Render a restrained graphite-to-midnight backdrop for the neon mark."""
    inner = (18, 34, 51)
    outer = (7, 9, 13)
    center_x = size * 0.5
    center_y = size * 0.28
    radius = size * 0.9

    image = Image.new("RGB", (size, size))
    pixels = image.load()
    for y in range(size):
        for x in range(size):
            distance = math.hypot(x - center_x, y - center_y) / radius
            t = min(1.0, max(0.0, distance))
            t = t * t * (3.0 - 2.0 * t)
            pixels[x, y] = tuple(
                round(inner[channel] * (1.0 - t) + outer[channel] * t)
                for channel in range(3)
            )
    return image


def flatten_cyber_palette(source: Image.Image) -> Image.Image:
    """Collapse generated shading to three dark-theme brand colors."""
    rgba = source.convert("RGBA")
    result = Image.new("RGBA", rgba.size, (0, 0, 0, 0))
    source_pixels = rgba.load()
    result_pixels = result.load()

    palette = (
        (53, 216, 255, 255),  # electric cyan shell/key
        (16, 20, 27, 255),  # graphite face screen
        (112, 255, 157, 255),  # Matrix-green eyes and antenna nodes
    )
    references = (
        (28, 205, 242),
        (10, 18, 27),
        (88, 239, 147),
    )

    for y in range(rgba.height):
        for x in range(rgba.width):
            red, green, blue, alpha = source_pixels[x, y]
            if alpha == 0:
                continue
            color_index = min(
                range(len(references)),
                key=lambda index: (
                    (red - references[index][0]) ** 2
                    + (green - references[index][1]) ** 2
                    + (blue - references[index][2]) ** 2
                ),
            )
            flat_red, flat_green, flat_blue, _ = palette[color_index]
            result_pixels[x, y] = (flat_red, flat_green, flat_blue, alpha)
    return result


def add_matrix_eyes(foreground: Image.Image) -> Image.Image:
    """Replace the terse terminal prompt with two friendly neon-green eyes."""
    result = foreground.copy()
    draw = ImageDraw.Draw(result)

    graphite = (16, 20, 27, 255)
    matrix_green = (112, 255, 157, 255)

    # Repaint the screen to remove the generated >_ prompt cleanly.
    draw.rounded_rectangle(
        (462, 362, 791, 585),
        radius=72,
        fill=graphite,
    )

    # Rounded, slightly tall eyes remain legible at Android launcher sizes.
    draw.rounded_rectangle(
        (526, 429, 587, 504),
        radius=21,
        fill=matrix_green,
    )
    draw.rounded_rectangle(
        (666, 429, 727, 504),
        radius=21,
        fill=matrix_green,
    )
    return result


def build_monochrome(foreground: Image.Image) -> Image.Image:
    """Use the face panel as negative space and retain the neon eyes."""
    result = Image.new("RGBA", foreground.size, (255, 255, 255, 0))
    source_pixels = foreground.load()
    result_pixels = result.load()
    for y in range(foreground.height):
        for x in range(foreground.width):
            red, green, blue, alpha = source_pixels[x, y]
            is_graphite = red < 40 and green < 45 and blue < 55
            if alpha and not is_graphite:
                result_pixels[x, y] = (255, 255, 255, alpha)
    return result


def centered_layer(source: Image.Image, size: int, max_fraction: float) -> Image.Image:
    subject = crop_alpha(source)
    max_extent = round(size * max_fraction)
    scale = min(max_extent / subject.width, max_extent / subject.height)
    resized = subject.resize(
        (max(1, round(subject.width * scale)), max(1, round(subject.height * scale))),
        Image.Resampling.LANCZOS,
    )
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    x = (size - resized.width) // 2
    y = (size - resized.height) // 2
    layer.alpha_composite(resized, (x, y))
    return layer


def apply_mask(image: Image.Image, kind: str) -> Image.Image:
    size = image.width
    mask = Image.new("L", image.size, 0)
    draw = ImageDraw.Draw(mask)
    if kind == "round":
        draw.ellipse((0, 0, size - 1, size - 1), fill=255)
    else:
        radius = round(size * 0.21)
        draw.rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    rgba = image.convert("RGBA")
    rgba.putalpha(mask)
    return rgba


def save_webp(image: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, "WEBP", lossless=True, method=6)


def build() -> None:
    foreground_path = SOURCE_DIR / "wgkeybot_cyber_foreground.png"
    foreground = add_matrix_eyes(
        flatten_cyber_palette(
            Image.open(foreground_path)
        )
    )
    monochrome = build_monochrome(foreground)
    foreground.save(foreground_path, "PNG", optimize=True)
    monochrome.save(
        SOURCE_DIR / "wgkeybot_cyber_monochrome.png", "PNG", optimize=True
    )

    for density, scale in DENSITIES.items():
        adaptive_size = round(108 * scale)
        legacy_size = round(48 * scale)
        mipmap = RES / f"mipmap-{density}"

        # Android recommends a 48-66dp logo inside the 108dp layer. The tall
        # two-antenna silhouette uses 58dp, leaving 4dp of extra vertical margin
        # on each side of the guaranteed 66dp safe zone.
        adaptive_foreground = centered_layer(
            foreground, adaptive_size, max_fraction=58 / 108
        )
        adaptive_monochrome = centered_layer(
            monochrome, adaptive_size, max_fraction=58 / 108
        )
        save_webp(adaptive_foreground, mipmap / "ic_launcher_foreground.webp")
        save_webp(adaptive_monochrome, mipmap / "ic_launcher_monochrome.webp")

        legacy_background = dark_background(legacy_size).convert("RGBA")
        legacy_foreground = centered_layer(foreground, legacy_size, 0.8)
        legacy_background.alpha_composite(legacy_foreground)
        save_webp(
            apply_mask(legacy_background, "squircle"),
            mipmap / "ic_launcher.webp",
        )

        legacy_round_background = dark_background(legacy_size).convert("RGBA")
        legacy_round_background.alpha_composite(
            centered_layer(foreground, legacy_size, 0.76)
        )
        save_webp(
            apply_mask(legacy_round_background, "round"),
            mipmap / "ic_launcher_round.webp",
        )


if __name__ == "__main__":
    build()
