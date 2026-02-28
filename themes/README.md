# Tab5UI SD Themes

Each theme lives in its own folder on SD:

`/sdcard/themes/<theme_name>/`

Required files:
- `theme.ini` (colors/style)

Optional files:
- `layout.json` (button positions/sizes)
- `icons/*.png` (custom tile icons)
- background image file referenced from `theme.ini`

## 1) `theme.ini`

Supported keys:
- `name`
- `bg`, `bg_layer`, `surface`, `surface_alt`, `card`, `border`
- `text_primary`, `text_secondary`, `text_muted`
- `accent_primary`, `accent_secondary`
- `success`, `warning`, `error`, `info`
- `modal_overlay`
- `outline_color`
- `font` (`default`, `compact`, `large`, `terminal`)
- `icon_tint` (hex color for PNG icon recolor)
- `icon_tint_opa` (`0..255`, tint strength; `255` = full recolor)
- `background_image` (relative file path in this folder, e.g. `bg.jpg`)

Color format: `RRGGBB`, `#RRGGBB`, or `0xRRGGBB`

Font presets:
- `default` - baseline UI typography.
- `compact` - smaller, denser typography.
- `large` - larger typography for readability.
- `terminal` - terminal-like profile.  
  Uses `UNSCII` fonts if enabled in firmware config; otherwise falls back to compact Montserrat.

## 2) `layout.json`

You can control tile geometry without touching firmware logic.

Sections:
- `uart_tiles` for the main 7-tile screen
- `internal_tiles` for INTERNAL tab main tiles
- `dashboard` for bottom dashboard visibility (`true/false` or object with `enabled`)

`uart_tiles` IDs:
- `wifi_scan_attack`
- `global_wifi_attacks`
- `compromised_data`
- `deauth_detector`
- `bluetooth`
- `network_observer`
- `karma`

`internal_tiles` IDs:
- `settings`
- `adhoc_portal`

Each entry format:
```json
{ "x": 0, "y": 0, "w": 246, "h": 182 }
```

Notes:
- `w` and `h` must be > 0.
- If a section is incomplete/invalid, firmware falls back to default layout for that section.
- Dashboard examples:
```json
{ "dashboard": false }
```
or
```json
{ "dashboard": { "enabled": false } }
```

## 3) `icons/`

Put PNG icons (transparent background) in:

`/sdcard/themes/<theme_name>/icons/`

Runtime behavior:
- Icons are auto-scaled to the tile icon box (preserve aspect ratio, contain mode).
- Recommended source size: square PNG, e.g. `96x96`.
- If `icon_tint` is set in `theme.ini`, PNG icons are recolored using `icon_tint_opa`.
  Useful for monochrome icons (e.g. black -> white/green on dark themes).

Supported main-tile icon filenames:
- `wifiscanattack.png`
- `globalwifiattacks.png`
- `compromiseddata.png`
- `deauthdetector.png`
- `bluetooth.png`
- `networkobserver.png`
- `karma.png`

Supported INTERNAL-tile icon filenames:
- `settings.png`
- `adhoc.png`

Also supported as aliases (snake_case):
- `wifi_scan_attack.png`
- `global_wifi_attacks.png`
- `compromised_data.png`
- `deauth_detector.png`
- `network_observer.png`
- `adhoc_portal.png`

If a PNG is missing, firmware uses the built-in LVGL symbol icon for that tile.

## 4) Example

See:
- `themes/example_ocean/theme.ini`
- `themes/example_ocean/layout.json`
- `themes/example_ocean/icons/` (full icon filename template ready to replace)
- `themes/example_terminal/theme.ini`
- `themes/example_terminal/layout.json`
