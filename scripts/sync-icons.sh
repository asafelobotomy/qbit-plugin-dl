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

# Replace *dest* only when pixels differ (avoids dirtying git on every rebuild).
_install_if_pixels_differ() {
  local generated="$1"
  local dest="$2"
  if [[ -f "$dest" ]] && command -v magick >/dev/null 2>&1; then
    if magick compare -metric AE "$generated" "$dest" null: >/dev/null 2>&1; then
      rm -f "$generated"
      return 0
    fi
  elif [[ -f "$dest" ]] && cmp -s "$generated" "$dest"; then
    rm -f "$generated"
    return 0
  fi
  mv -f "$generated" "$dest"
}

if command -v magick >/dev/null 2>&1; then
  pkg_tmp="$(mktemp "${TMPDIR:-/tmp}/qbit-plugin-dl-pkg-icon.XXXXXX.png")"
  app_tmp="$(mktemp "${TMPDIR:-/tmp}/qbit-plugin-dl-app-icon.XXXXXX.png")"
  # shellcheck disable=SC2064
  trap 'rm -f "$pkg_tmp" "$app_tmp"' EXIT

  magick "$SRC" \
    -background none -gravity center \
    -extent "%[fx:max(w,h)]x%[fx:max(w,h)]" \
    "$pkg_tmp"
  magick "$pkg_tmp" -resize 256x256 "$app_tmp"

  _install_if_pixels_differ "$pkg_tmp" "$PKG_ICON"
  _install_if_pixels_differ "$app_tmp" "$APP_ICON"
  trap - EXIT
  echo "Synced icons via ImageMagick → $PKG_ICON , $APP_ICON"
  exit 0
fi

# Optional Pillow fallback (venv or system).
for PY in "${ROOT}/.venv/bin/python" "${ROOT}/.venv-appimage/bin/python" python3; do
  if [[ -x "$PY" ]] || command -v "$PY" >/dev/null 2>&1; then
    if "$PY" - <<'PY' "$SRC" "$PKG_ICON" "$APP_ICON"
import sys
import tempfile
from pathlib import Path

try:
    from PIL import Image, ImageChops
except ImportError:
    sys.exit(2)

src, pkg, app = map(Path, sys.argv[1:4])
im = Image.open(src).convert("RGBA")
side = max(im.size)
canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
canvas.paste(im, ((side - im.width) // 2, (side - im.height) // 2), im)
app_im = canvas.resize((256, 256), Image.Resampling.LANCZOS)


def install_if_changed(image: Image.Image, dest: Path) -> None:
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as handle:
        tmp = Path(handle.name)
    try:
        image.save(tmp)
        if dest.is_file():
            existing = Image.open(dest).convert("RGBA")
            if existing.size == image.size and ImageChops.difference(existing, image).getbbox() is None:
                tmp.unlink(missing_ok=True)
                return
        tmp.replace(dest)
    finally:
        tmp.unlink(missing_ok=True)


install_if_changed(canvas, pkg)
install_if_changed(app_im, app)
print(f"Synced icons via Pillow → {pkg} , {app}")
PY
    then
      exit 0
    fi
  fi
done

echo "Cannot sync icons: install ImageMagick (magick) or Pillow." >&2
exit 1
