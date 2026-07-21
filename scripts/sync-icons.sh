#!/usr/bin/env bash
# Sync branding icon into package resources and AppImage desktop icon.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/branding/qbit-plugin-dl-icon.png"
PKG_ICON="${ROOT}/src/qbit_plugin_dl/resources/icon.png"
APP_ICON="${ROOT}/appimage/qbit-plugin-dl.png"

if [[ ! -f "$SRC" ]]; then
  echo "Missing branding icon: $SRC" >&2
  exit 1
fi

mkdir -p "$(dirname "$PKG_ICON")" "$(dirname "$APP_ICON")"

if command -v magick >/dev/null 2>&1; then
  magick "$SRC" \
    -background none -gravity center \
    -extent "%[fx:max(w,h)]x%[fx:max(w,h)]" \
    "$PKG_ICON"
  magick "$PKG_ICON" -resize 256x256 "$APP_ICON"
  echo "Synced icons via ImageMagick → $PKG_ICON , $APP_ICON"
  exit 0
fi

# Optional Pillow fallback (venv or system).
for PY in "${ROOT}/.venv/bin/python" "${ROOT}/.venv-appimage/bin/python" python3; do
  if [[ -x "$PY" ]] || command -v "$PY" >/dev/null 2>&1; then
    if "$PY" - <<'PY' "$SRC" "$PKG_ICON" "$APP_ICON"
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    sys.exit(2)

src, pkg, app = map(Path, sys.argv[1:4])
im = Image.open(src).convert("RGBA")
side = max(im.size)
canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
canvas.paste(im, ((side - im.width) // 2, (side - im.height) // 2), im)
canvas.save(pkg)
canvas.resize((256, 256), Image.Resampling.LANCZOS).save(app)
print(f"Synced icons via Pillow → {pkg} , {app}")
PY
    then
      exit 0
    fi
  fi
done

echo "Cannot sync icons: install ImageMagick (magick) or Pillow." >&2
exit 1
