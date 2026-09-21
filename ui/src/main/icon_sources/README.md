# Launcher icon

The current icon is a small refresh of the mascot from tag `v1.6.0`.
`wgkeybot_v160_refresh.png` is the transparent master produced with the built-in
image_gen tool. The older cyber foreground is retained for reference.

Rebuild all density variants and the 512px store image with:

```sh
python3 -m pip install Pillow
python3 ui/src/main/icon_sources/build_android_icons.py
```

The script preserves the master and exports foreground, themed monochrome,
background, legacy square and round resources. Adaptive icons continue to use
the existing XML declarations. Background color `#142D4E` must match
`res/values/ic_launcher_background.xml`.

Sizing follows https://developer.android.com/develop/ui/compose/system/icon_design_adaptive.

## Generation prompt

Use case: style-transfer.
Asset type: production Android adaptive launcher icon FOREGROUND, a single mascot cutout.
Input image: edit target, the original WGKeyBot v1.6.0 app icon.
Primary request: Only a subtle modernization of this exact friendly turquoise robot mascot holding a gold WG key and waving. Preserve its recognizable silhouette, rounded rectangular head, two short antennas, smiling dark navy face with two cyan eyes, small tapered torso with shield, left gold key and right raised hand. This is a refresh, not a redesign.
Style: polished contemporary Android app illustration, cleaner broad shapes, rounded outlines, restrained soft shading. Reduce micro-details, remove busy reflections and glow, simplify joints and chest circuitry. Retain cyan/turquoise, deep navy outlines and golden yellow key. Keep exact readable text "WG" on the key.
Composition: entire mascot centered with generous transparent margin on all sides, all antenna tips, the key and hand fully visible. Balanced compact proportions similar to original.
Background: genuinely transparent alpha, remove ALL blue backdrop and circuitry. No tile shape, no border, no drop shadow outside mascot, no watermark, no sparkle, no extra objects. Deliver one isolated mascot image only.
